//! Multi-protocol connection manager.
//!
//! Unifies TCP (HTTP/1.1, HTTP/2 over TLS) and UDP (HTTP/3 over QUIC)
//! connections behind a single event loop. Requires `alloc`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

#[cfg(feature = "h3")]
use crate::connection::{Connection, ConnectionId, HandshakePoolAccess};
use crate::crypto::CryptoProvider;
use crate::error::Error;
#[cfg(feature = "h3")]
use crate::h3::server::H3Server;
use crate::http::server_conn::{HttpEvent, HttpServerConn};
#[cfg(feature = "h3")]
use crate::packet::decode_dcid::decode_dcid;
use crate::tcp_tls::TlsParts;
use crate::tls::handshake::ServerTlsConfig;
#[cfg(feature = "h3")]
use crate::tls::transport_params::TransportParams;
use crate::transport::{Address, Rng};

#[cfg(feature = "h3")]
pub mod runner;

// ---------------------------------------------------------------------------
// ConnId — opaque connection handle
// ---------------------------------------------------------------------------

/// Opaque connection handle returned by the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u32);

/// Protocol used by a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnProtocol {
    /// TLS handshake in progress, protocol not yet determined.
    Handshaking,
    /// HTTP/1.1 over TLS.
    Http1,
    /// HTTP/2 over TLS.
    H2,
    /// HTTP/3 over QUIC.
    #[cfg(feature = "h3")]
    H3,
}

// ---------------------------------------------------------------------------
// ServerEvent — unified event
// ---------------------------------------------------------------------------

/// Event from the connection manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// HTTP event on a specific connection.
    Http { conn: ConnId, event: HttpEvent },
    /// A connection was accepted and TLS/QUIC handshake completed.
    Connected(ConnId),
    /// A connection was closed and removed.
    Closed(ConnId),
}

// ---------------------------------------------------------------------------
// TCP connection state
// ---------------------------------------------------------------------------

enum TcpState<C: CryptoProvider, const BUF: usize> {
    /// TLS handshake in progress.
    Handshaking(TlsParts<C, BUF>),
    /// HTTP protocol established (H1 or H2, erased via dyn trait).
    Established(Box<dyn HttpServerConn>),
    /// Closed, pending removal.
    Closed,
}

struct TcpConn<C: CryptoProvider, const BUF: usize> {
    id: ConnId,
    state: TcpState<C, BUF>,
    /// Negotiated protocol (set after TLS handshake completes).
    protocol: ConnProtocol,
    /// Timestamp (microseconds) when the connection was accepted.
    /// Used for handshake timeout enforcement.
    accepted_at: u64,
}

// ---------------------------------------------------------------------------
// QUIC/H3 connection state
// ---------------------------------------------------------------------------

#[cfg(feature = "h3")]
struct QuicConn<
    C: CryptoProvider,
    A: Address,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
    const STREAM_BUF: usize,
    const SEND_QUEUE: usize,
    const H3_HDR_BUF: usize,
    const H3_DATA_BUF: usize,
> {
    id: ConnId,
    server: H3Server<
        C,
        MAX_STREAMS,
        SENT_PER_SPACE,
        MAX_CIDS,
        STREAM_BUF,
        SEND_QUEUE,
        H3_HDR_BUF,
        H3_DATA_BUF,
    >,
    peer_addr: A,
    local_cids: Vec<ConnectionId>,
    /// The client-chosen Destination Connection ID from the first Initial.
    /// Until the client has processed a server packet it keeps addressing us
    /// by this CID — a ClientHello large enough to span multiple Initial
    /// datagrams (e.g. post-quantum key shares) sends every fragment under it,
    /// so routing must match it in addition to our own `local_cids`.
    original_dcid: ConnectionId,
    /// When the connection was created (µs), for the handshake deadline. A
    /// handshake that never completes (e.g. our flight was lost and the
    /// client gave up) would otherwise pin the conn slot and its handshake
    /// pool slot forever.
    created_at: u64,
}

// ---------------------------------------------------------------------------
// ServerManager
// ---------------------------------------------------------------------------

/// Configuration for connection limits and timeouts.
pub struct ServerConfig {
    /// Maximum number of TCP connections.
    pub max_tcp_conns: usize,
    /// Maximum number of QUIC connections.
    #[cfg(feature = "h3")]
    pub max_quic_conns: usize,
    /// Maximum number of queued events.
    pub max_events: usize,
    /// TLS handshake timeout in microseconds.
    pub handshake_timeout_us: u64,
    /// HTTP-level timeouts (idle / first-headers) applied to every TCP
    /// connection when it becomes established. Defaults ON (idle 60 s,
    /// header 10 s): a connection wedged behind receive backpressure (body
    /// never drained, see [`HttpServerConn::discard_body`]) is reaped by the
    /// idle timeout as the backstop. Note "activity" counts only received
    /// bytes — a handler that goes silent longer than the idle timeout while
    /// processing (peer quietly waiting for the response) will be reaped, so
    /// size the idle timeout above worst-case handler processing time.
    pub http_timeouts: crate::http::TimeoutConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_tcp_conns: 4,
            #[cfg(feature = "h3")]
            max_quic_conns: 8,
            max_events: 32,
            handshake_timeout_us: 10_000_000,
            http_timeouts: crate::http::TimeoutConfig {
                idle_timeout_us: Some(60_000_000),
                header_timeout_us: Some(10_000_000),
            },
        }
    }
}

/// Multi-protocol connection manager.
///
/// Manages TCP (HTTP/1.1, HTTP/2 over TLS) and UDP (HTTP/3 over QUIC)
/// connections, providing a unified event stream.
///
/// Generic parameters:
/// - `C`: Crypto provider
/// - `A`: Address type for UDP peers
/// - `BUF`: TLS I/O buffer capacity cap (default 4096; handles handshakes and typical HTTP)
/// - `MAX_STREAMS`: Max concurrent QUIC streams per connection (default 4)
/// - `SENT_PER_SPACE`: Max tracked sent packets per QUIC packet space (default 16)
/// - `MAX_CIDS`: Max QUIC connection IDs per connection (default 2)
/// - `STREAM_BUF`: Per-stream buffer size in bytes (default 256)
/// - `SEND_QUEUE`: QUIC send queue depth (default 4)
pub struct ServerManager<
    C: CryptoProvider,
    A: Address,
    const BUF: usize = 4096,
    const MAX_STREAMS: usize = 16,
    const SENT_PER_SPACE: usize = 16,
    const MAX_CIDS: usize = 2,
    const STREAM_BUF: usize = 256,
    // At connection setup the H3 server queues its control + QPACK streams;
    // a response arriving in the same poll cycle (common at 1200-byte QUIC
    // datagram pacing) must still fit alongside them, or send_response fails
    // with BufferTooSmall. 16 matches H3Server's own default.
    const SEND_QUEUE: usize = 16,
    const H3_HDR_BUF: usize = 512,
    const H3_DATA_BUF: usize = 1024,
> {
    tls_config: ServerTlsConfig,
    provider: C,
    config: ServerConfig,

    tcp_conns: Vec<TcpConn<C, BUF>>,
    #[cfg(feature = "h3")]
    quic_conns: Vec<
        QuicConn<
            C,
            A,
            MAX_STREAMS,
            SENT_PER_SPACE,
            MAX_CIDS,
            STREAM_BUF,
            SEND_QUEUE,
            H3_HDR_BUF,
            H3_DATA_BUF,
        >,
    >,

    events: VecDeque<ServerEvent>,
    next_id: u32,

    /// Idle `'static`-slice buffer kits available to lend to a new TLS
    /// connection (see [`add_tls_buffer_kit`](Self::add_tls_buffer_kit)). A kit
    /// is popped on accept and returned on teardown via the reclaim funnel, so
    /// the same `.bss` region is reused for the connection's lifetime and the
    /// large TLS/h2 I/O buffers never touch the heap. Empty by default →
    /// connections fall back to heap-backed buffers (std tests, non-firmware
    /// users).
    free_kits: Vec<crate::tcp_tls::TlsBufKit>,
    _marker: core::marker::PhantomData<A>,
}

impl<
    C,
    A,
    const BUF: usize,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
    const STREAM_BUF: usize,
    const SEND_QUEUE: usize,
    const H3_HDR_BUF: usize,
    const H3_DATA_BUF: usize,
>
    ServerManager<
        C,
        A,
        BUF,
        MAX_STREAMS,
        SENT_PER_SPACE,
        MAX_CIDS,
        STREAM_BUF,
        SEND_QUEUE,
        H3_HDR_BUF,
        H3_DATA_BUF,
    >
where
    C: CryptoProvider + Clone + 'static,
    C::Hkdf: Default,
    A: Address,
{
    /// Create a new server manager.
    pub fn new(provider: C, tls_config: ServerTlsConfig, config: ServerConfig) -> Self {
        Self {
            tls_config,
            provider,
            config,
            tcp_conns: Vec::new(),
            #[cfg(feature = "h3")]
            quic_conns: Vec::new(),
            events: VecDeque::new(),
            next_id: 0,
            free_kits: Vec::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Donate a [`TlsBufKit`](crate::tcp_tls::TlsBufKit) of `'static` slices for
    /// the manager to lend to TLS connections instead of heap-allocating their
    /// I/O buffers. Each slice must be at least `BUF` bytes. Add as many kits as
    /// the maximum number of concurrent TLS connections; if none are available
    /// at accept time the connection falls back to heap-backed buffers.
    pub fn add_tls_buffer_kit(&mut self, kit: crate::tcp_tls::TlsBufKit) {
        self.free_kits.push(kit);
    }

    /// Number of `'static` buffer kits currently idle in the free pool (i.e.
    /// donated but not lent to a live connection). Useful for diagnostics and
    /// for verifying the reclaim funnel returns kits on teardown.
    pub fn free_tls_buffer_kits(&self) -> usize {
        self.free_kits.len()
    }

    /// Remove and return one idle buffer kit from the free pool, if any. The
    /// inverse of [`add_tls_buffer_kit`](Self::add_tls_buffer_kit); the manager
    /// gives up the `.bss` slices to the caller.
    pub fn take_tls_buffer_kit(&mut self) -> Option<crate::tcp_tls::TlsBufKit> {
        self.free_kits.pop()
    }

    fn alloc_id(&mut self) -> ConnId {
        let id = ConnId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Reclaim funnel: take a TCP connection's state to `Closed`, recovering any
    /// `'static` buffer kit it was lent (from `Handshaking` parts directly, or
    /// from an `Established` HTTP conn via `reclaim_buffers`) so the `.bss`
    /// region can be reused by the next connection.
    ///
    /// EVERY transition of a connection to `Closed` must go through here, or the
    /// kit leaks and the manager silently degrades to heap-backed buffers
    /// (which is exactly the fragmentation this design avoids). Operates on the
    /// state field alone (a split borrow), so it is callable from sites that
    /// hold only `&mut conn.state`. The recovered kit is returned for the caller
    /// to push into `free_kits` (callers inside a `&mut self.tcp_conns` borrow
    /// can't touch `free_kits` directly).
    #[must_use = "the reclaimed kit must be returned to free_kits or it leaks"]
    fn reclaim_and_close(state: &mut TcpState<C, BUF>) -> Option<crate::tcp_tls::TlsBufKit> {
        let kit = match state {
            TcpState::Handshaking(parts) => parts.reclaim_buffers(),
            TcpState::Established(http) => http.reclaim_buffers(),
            TcpState::Closed => None,
        };
        *state = TcpState::Closed;
        kit
    }

    // -----------------------------------------------------------------------
    // TCP interface
    // -----------------------------------------------------------------------

    /// Push an event into the queue, dropping the oldest if at capacity.
    fn push_server_event(&mut self, event: ServerEvent) {
        if self.events.len() >= self.config.max_events {
            let _ = self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Accept a new TCP connection. Creates TLS handshake state.
    ///
    /// Returns the connection ID, or an error if at capacity.
    /// The caller should then feed TCP data via `tcp_feed` and drain
    /// output via `tcp_poll_output`.
    pub fn accept_tcp(&mut self, rng: &mut impl Rng, now: u64) -> Result<ConnId, Error> {
        if self.tcp_conns.len() >= self.config.max_tcp_conns {
            return Err(Error::StreamLimitExhausted);
        }
        let id = self.alloc_id();

        let mut secret = [0u8; 32];
        let mut random = [0u8; 32];
        rng.fill(&mut secret);
        rng.fill(&mut random);

        // Lend a `'static` buffer kit if one is free, so the large TLS/h2 I/O
        // buffers live in `.bss` instead of the heap; otherwise fall back to
        // heap-backed buffers (no kit donated, e.g. std tests).
        let parts = match self.free_kits.pop() {
            Some(kit) => TlsParts::new_server_in(
                self.provider.clone(),
                self.tls_config.clone(),
                secret,
                random,
                kit,
            ),
            None => TlsParts::new_server(
                self.provider.clone(),
                self.tls_config.clone(),
                secret,
                random,
            ),
        };

        self.tcp_conns.push(TcpConn {
            id,
            state: TcpState::Handshaking(parts),
            protocol: ConnProtocol::Handshaking,
            accepted_at: now,
        });

        Ok(id)
    }

    /// Accept a new cleartext (non-TLS) TCP connection.
    ///
    /// Unlike [`accept_tcp`](Self::accept_tcp), this skips the TLS handshake and
    /// starts the connection as an established plaintext HTTP/1.1 server. Feed
    /// raw TCP bytes via `tcp_feed` and drain output via `tcp_poll_output`, same
    /// as a TLS connection. Used to serve plain HTTP alongside HTTPS.
    #[cfg(feature = "http1")]
    pub fn accept_tcp_cleartext(&mut self, now: u64) -> Result<ConnId, Error> {
        if self.tcp_conns.len() >= self.config.max_tcp_conns {
            return Err(Error::StreamLimitExhausted);
        }
        let id = self.alloc_id();

        let http_conn: Box<dyn HttpServerConn> = Box::new(crate::http1::Http1Server::<BUF>::new());
        self.tcp_conns.push(TcpConn {
            id,
            state: TcpState::Established(http_conn),
            protocol: ConnProtocol::Http1,
            accepted_at: now,
        });
        self.push_server_event(ServerEvent::Connected(id));

        Ok(id)
    }

    /// Feed TCP data into a connection.
    pub fn tcp_feed(&mut self, id: ConnId, data: &[u8], now: u64) -> Result<(), Error> {
        let conn = self
            .tcp_conns
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(Error::InvalidState)?;

        // Check if currently handshaking
        let needs_upgrade = matches!(&conn.state, TcpState::Handshaking(_));

        if needs_upgrade {
            // Feed data through TlsParts. On error, close the connection
            // immediately to avoid zombie handshake state.
            if let TcpState::Handshaking(parts) = &mut conn.state {
                if let Err(e) = parts.feed_data(data) {
                    let conn_id = conn.id;
                    if let Some(kit) = Self::reclaim_and_close(&mut conn.state) {
                        self.free_kits.push(kit);
                    }
                    self.push_server_event(ServerEvent::Closed(conn_id));
                    return Err(e);
                }
            }

            // Check if handshake completed (separate borrow scope)
            let handshake_done = matches!(&conn.state, TcpState::Handshaking(p) if p.is_active());

            if handshake_done {
                // Take ownership of parts
                let old_state = core::mem::replace(&mut conn.state, TcpState::Closed);
                let parts = match old_state {
                    TcpState::Handshaking(p) => p,
                    _ => unreachable!(),
                };

                let alpn = parts.alpn();
                // `parts` is moved into the building arms below. The reject arm
                // does not consume it, so reclaim its kit there before dropping.
                let (protocol, http_conn): (ConnProtocol, Box<dyn HttpServerConn>) = match alpn {
                    #[cfg(feature = "h2")]
                    Some(b"h2") => (
                        ConnProtocol::H2,
                        Box::new(crate::h2_tls::H2TlsServer::<C, BUF>::from_parts(parts)),
                    ),
                    #[cfg(feature = "http1")]
                    Some(b"http/1.1") => (
                        ConnProtocol::Http1,
                        Box::new(crate::https1::Https1Server::<C, BUF>::from_parts(parts)),
                    ),
                    #[cfg(feature = "http1")]
                    None => (
                        ConnProtocol::Http1,
                        Box::new(crate::https1::Https1Server::<C, BUF>::from_parts(parts)),
                    ),
                    _ => {
                        // Unknown/unsupported ALPN — reject the connection.
                        // `conn.state` is already `Closed` (replaced above); the
                        // kit lives in the still-owned `parts` here.
                        let conn_id = conn.id;
                        let mut parts = parts;
                        if let Some(kit) = parts.reclaim_buffers() {
                            self.free_kits.push(kit);
                        }
                        self.push_server_event(ServerEvent::Closed(conn_id));
                        return Err(Error::InvalidState);
                    }
                };
                let mut http_conn = http_conn;

                // Arm the HTTP-level timeouts (idle / first-headers) from the
                // moment the connection is established.
                http_conn.set_timeouts(self.config.http_timeouts, now);

                // Process any application data that was decrypted alongside the
                // final handshake message (common with TLS 1.3 piggybacking).
                // Feeding an empty slice triggers processing of the decrypted
                // plaintext already sitting in net_recv's visible prefix.
                let _ = http_conn.tcp_feed_data(&[], now);

                conn.state = TcpState::Established(http_conn);
                conn.protocol = protocol;
                let conn_id = conn.id;
                self.push_server_event(ServerEvent::Connected(conn_id));
            }

            Ok(())
        } else {
            match &mut conn.state {
                TcpState::Established(http) => http.tcp_feed_data(data, now),
                _ => Err(Error::InvalidState),
            }
        }
    }

    /// Whether an established connection is applying receive backpressure: it
    /// is holding undelivered body data behind a full application buffer, so
    /// the runner should stop reading more TCP for it and instead re-drive
    /// processing (feed an empty slice) so the consumer can drain. See
    /// [`HttpServerConn::recv_blocked`].
    pub fn conn_recv_blocked(&self, id: ConnId) -> bool {
        self.tcp_conns
            .iter()
            .find(|c| c.id == id)
            .map(|c| match &c.state {
                TcpState::Established(http) => http.recv_blocked(),
                _ => false,
            })
            .unwrap_or(false)
    }

    /// Pull outgoing TCP data from a connection.
    pub fn tcp_poll_output<'a>(&mut self, id: ConnId, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let conn = self.tcp_conns.iter_mut().find(|c| c.id == id)?;

        match &mut conn.state {
            TcpState::Handshaking(parts) => parts.poll_output(buf),
            TcpState::Established(http) => http.tcp_poll_output(buf),
            TcpState::Closed => None,
        }
    }

    // -----------------------------------------------------------------------
    // UDP interface
    // -----------------------------------------------------------------------

    /// Feed a UDP datagram. Routes by DCID to existing connections or creates new ones.
    #[cfg(feature = "h3")]
    pub fn udp_feed<const CRYPTO_BUF: usize>(
        &mut self,
        data: &[u8],
        from: A,
        now: u64,
        rng: &mut impl Rng,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        // Extract DCID to route
        let dcid = decode_dcid(data, 8);

        // Try to find an existing connection by CID. Match our own local CIDs
        // *and* the client's original DCID: until the client has processed a
        // server packet it keeps addressing us by its own chosen DCID, and a
        // multi-datagram Initial flight (large ClientHello, e.g. post-quantum
        // key shares) sends every fragment under it. Without this, fragment 2+
        // falls through to the new-connection path and bounces off
        // max_quic_conns.
        if let Some(dcid) = dcid {
            for qconn in &mut self.quic_conns {
                let matched = qconn.local_cids.iter().any(|cid| cid.as_slice() == dcid)
                    || qconn.original_dcid.as_slice() == dcid;
                if matched {
                    let mut scratch = [0u8; 2048];
                    qconn
                        .server
                        .recv::<CRYPTO_BUF>(data, &mut scratch, now, pool)?;
                    return Ok(());
                }
            }
        }

        // New connection: create QUIC server + H3. At capacity, first reap
        // any conn that has already expired — on an otherwise idle server
        // nothing has called handle_timeouts since the predecessor died, and
        // bouncing this Initial would cost the client a full retransmit
        // timeout before its retry finds the freed slot.
        if self.quic_conns.len() >= self.config.max_quic_conns {
            self.reap_quic_conns::<CRYPTO_BUF>(now, pool);
        }
        if self.quic_conns.len() >= self.config.max_quic_conns {
            return Err(Error::StreamLimitExhausted);
        }
        let id = self.alloc_id();
        let quic_conn = Connection::<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>::server(
            self.provider.clone(),
            self.tls_config.clone(),
            TransportParams::default_params(),
            rng,
            pool,
        )?;

        // Cache local CIDs
        let local_cids: Vec<ConnectionId> = quic_conn.local_cids().to_vec();

        let mut server = H3Server::<
            C,
            MAX_STREAMS,
            SENT_PER_SPACE,
            MAX_CIDS,
            STREAM_BUF,
            SEND_QUEUE,
            H3_HDR_BUF,
            H3_DATA_BUF,
        >::new(quic_conn);
        // Feed the initial datagram. If this fails, release the handshake pool
        // slot to avoid leaking it (Connection has no Drop impl).
        let mut scratch = [0u8; 2048];
        if let Err(e) = server.recv::<CRYPTO_BUF>(data, &mut scratch, now, pool) {
            server.release_handshake_slot::<CRYPTO_BUF>(pool);
            return Err(e);
        }

        self.quic_conns.push(QuicConn {
            id,
            server,
            peer_addr: from,
            local_cids,
            original_dcid: dcid.map(ConnectionId::from_slice).unwrap_or_else(|| {
                // Unreachable for a valid Initial (long headers always carry a
                // DCID); an empty CID matches nothing.
                ConnectionId::empty()
            }),
            created_at: now,
        });

        Ok(())
    }

    /// Pull the next outgoing UDP datagram.
    ///
    /// Call repeatedly until `None` to drain all pending transmits.
    #[cfg(feature = "h3")]
    pub fn udp_poll_transmit<'a, const CRYPTO_BUF: usize>(
        &'a mut self,
        buf: &'a mut [u8],
        now: u64,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Option<(A, usize)> {
        for qconn in &mut self.quic_conns {
            if let Some(tx) = qconn.server.poll_transmit::<CRYPTO_BUF>(buf, now, pool) {
                let addr = qconn.peer_addr.clone();
                let len = tx.data.len();
                return Some((addr, len));
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Unified HTTP interface
    // -----------------------------------------------------------------------

    /// Poll for the next server event.
    ///
    /// Drains events from all connections (TCP and UDP) into the unified
    /// event stream. `scratch` is a caller-provided buffer for temporary
    /// stream reads (used by H3 connections to avoid stack allocations).
    pub fn poll_event(&mut self, scratch: &mut [u8]) -> Option<ServerEvent> {
        // Return any queued events first
        if let Some(ev) = self.events.pop_front() {
            return Some(ev);
        }

        // Poll TCP connections. A connection that has closed itself is taken to
        // `Closed` via the reclaim funnel; the recovered kit is stashed and
        // pushed to free_kits after the `tcp_conns` borrow ends.
        let mut reclaimed: Option<(ConnId, Option<crate::tcp_tls::TlsBufKit>)> = None;
        for conn in &mut self.tcp_conns {
            if let TcpState::Established(http) = &mut conn.state {
                if let Some(ev) = http.poll_event(scratch) {
                    return Some(ServerEvent::Http {
                        conn: conn.id,
                        event: ev,
                    });
                }
                if http.is_closed() {
                    let id = conn.id;
                    let kit = Self::reclaim_and_close(&mut conn.state);
                    reclaimed = Some((id, kit));
                    break;
                }
            }
        }
        if let Some((id, kit)) = reclaimed {
            if let Some(kit) = kit {
                self.free_kits.push(kit);
            }
            return Some(ServerEvent::Closed(id));
        }

        // Poll QUIC connections
        #[cfg(feature = "h3")]
        {
            let mut quic_event = None;
            for qconn in &mut self.quic_conns {
                if let Some(ev) = qconn.server.poll_event(scratch) {
                    let http_ev = crate::h3::server::map_h3_event(ev);
                    quic_event = Some(ServerEvent::Http {
                        conn: qconn.id,
                        event: http_ev,
                    });
                    break;
                }
            }
            if quic_event.is_some() {
                return quic_event;
            }
        }

        // Clean up closed TCP connections
        self.tcp_conns
            .retain(|c| !matches!(c.state, TcpState::Closed));

        // Closed QUIC connections are reaped in handle_timeouts(), which has
        // the handshake pool and can release a mid-handshake conn's slot.

        self.events.pop_front()
    }

    /// Read request headers for a connection/stream.
    pub fn recv_headers(
        &mut self,
        conn: ConnId,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == conn) {
            if let TcpState::Established(http) = &mut tcp.state {
                return http.recv_headers(stream_id, emit);
            }
        }
        #[cfg(feature = "h3")]
        if let Some(qconn) = self.quic_conns.iter_mut().find(|c| c.id == conn) {
            return qconn.server.recv_headers(stream_id, emit);
        }
        Err(Error::InvalidState)
    }

    /// Read body data from a connection/stream.
    pub fn recv_body(
        &mut self,
        conn: ConnId,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == conn) {
            if let TcpState::Established(http) = &mut tcp.state {
                return http.recv_body(stream_id, buf);
            }
        }
        #[cfg(feature = "h3")]
        if let Some(qconn) = self.quic_conns.iter_mut().find(|c| c.id == conn) {
            return qconn.server.recv_body(stream_id, buf);
        }
        Err(Error::InvalidState)
    }

    /// Stop receiving a stream's request body: the application will not (or
    /// no longer) read it. Call this when responding without consuming the
    /// body (e.g. rejecting an upload with 413) — an unread body otherwise
    /// stalls the connection behind receive backpressure until the idle
    /// timeout reaps it.
    ///
    /// For HTTP/2 this discards buffered/in-flight body data, restores
    /// flow-control credit, and sends RST_STREAM with `error_code` (`0` =
    /// NO_ERROR when rejecting after a complete response per RFC 9113 §8.1,
    /// `0x8` = CANCEL otherwise). Returns `InvalidState` for protocols
    /// without per-stream cancellation (HTTP/1.1) — close the connection
    /// instead.
    pub fn discard_body(
        &mut self,
        conn: ConnId,
        stream_id: u64,
        error_code: u32,
    ) -> Result<(), Error> {
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == conn)
            && let TcpState::Established(http) = &mut tcp.state
        {
            return http.discard_body(stream_id, error_code);
        }
        Err(Error::InvalidState)
    }

    /// Send response headers on a connection/stream.
    pub fn send_response(
        &mut self,
        conn: ConnId,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == conn) {
            if let TcpState::Established(http) = &mut tcp.state {
                return http.send_response(stream_id, status, headers, end_stream);
            }
        }
        #[cfg(feature = "h3")]
        if let Some(qconn) = self.quic_conns.iter_mut().find(|c| c.id == conn) {
            return qconn
                .server
                .send_response(stream_id, status, headers, end_stream);
        }
        Err(Error::InvalidState)
    }

    /// Send body data on a connection/stream.
    pub fn send_body(
        &mut self,
        conn: ConnId,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == conn) {
            if let TcpState::Established(http) = &mut tcp.state {
                return http.send_body(stream_id, data, end_stream);
            }
        }
        #[cfg(feature = "h3")]
        if let Some(qconn) = self.quic_conns.iter_mut().find(|c| c.id == conn) {
            return qconn.server.send_body(stream_id, data, end_stream);
        }
        Err(Error::InvalidState)
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Return the earliest timeout deadline across all connections.
    pub fn next_timeout(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;

        for conn in &self.tcp_conns {
            match &conn.state {
                TcpState::Handshaking(_) => {
                    let deadline = conn
                        .accepted_at
                        .saturating_add(self.config.handshake_timeout_us);
                    earliest = Some(earliest.map_or(deadline, |e: u64| e.min(deadline)));
                }
                TcpState::Established(http) => {
                    if let Some(t) = http.next_timeout() {
                        earliest = Some(earliest.map_or(t, |e: u64| e.min(t)));
                    }
                }
                TcpState::Closed => {}
            }
        }

        #[cfg(feature = "h3")]
        for qconn in &self.quic_conns {
            if !qconn.server.is_established() {
                let deadline = qconn
                    .created_at
                    .saturating_add(self.config.handshake_timeout_us);
                earliest = Some(earliest.map_or(deadline, |e: u64| e.min(deadline)));
            }
            if let Some(t) = qconn.server.next_timeout() {
                earliest = Some(earliest.map_or(t, |e: u64| e.min(t)));
            }
        }

        earliest
    }

    /// Handle timeouts on all connections, and reap dead QUIC connections.
    ///
    /// Takes the handshake pool because a connection closed mid-handshake
    /// still owns a pool slot (`Connection` has no `Drop` impl); reaping it
    /// without releasing the slot would leak the pool dry.
    #[cfg(feature = "h3")]
    pub fn handle_timeouts<const CRYPTO_BUF: usize>(
        &mut self,
        now: u64,
        pool: &mut dyn crate::connection::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) {
        self.handle_tcp_timeouts(now);
        self.reap_quic_conns::<CRYPTO_BUF>(now, pool);
    }

    /// Drive QUIC connection timers and remove dead connections, releasing
    /// any handshake pool slot a mid-handshake conn still owns.
    ///
    /// Called from `handle_timeouts` each poll cycle, and from `udp_feed`
    /// when a new connection bounces off `max_quic_conns` — the predecessor
    /// may have expired long ago with no wakeup since (an idle server only
    /// wakes on traffic), and the very datagram being refused is what would
    /// have triggered the reap one step later.
    #[cfg(feature = "h3")]
    fn reap_quic_conns<const CRYPTO_BUF: usize>(
        &mut self,
        now: u64,
        pool: &mut dyn crate::connection::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) {
        let handshake_timeout_us = self.config.handshake_timeout_us;
        let mut reaped = Vec::new();
        self.quic_conns.retain_mut(|qconn| {
            qconn.server.handle_timeout(now);

            // A handshake that hasn't completed by the deadline is dead:
            // the peer has long stopped retrying. Same deadline as TCP
            // TLS handshakes.
            let handshake_expired = !qconn.server.is_established()
                && now >= qconn.created_at.saturating_add(handshake_timeout_us);

            if qconn.server.is_closed() || handshake_expired {
                qconn.server.release_handshake_slot::<CRYPTO_BUF>(pool);
                reaped.push(qconn.id);
                false
            } else {
                true
            }
        });
        for id in reaped {
            self.push_server_event(ServerEvent::Closed(id));
        }
    }

    /// Handle timeouts on all connections (TCP-only build).
    #[cfg(not(feature = "h3"))]
    pub fn handle_timeouts(&mut self, now: u64) {
        self.handle_tcp_timeouts(now);
    }

    /// Expire TCP TLS handshakes past their deadline and drive HTTP-level
    /// timers on established connections.
    fn handle_tcp_timeouts(&mut self, now: u64) {
        // Collect timed-out IDs + reclaimed kits first (can't push events or
        // touch free_kits while iterating tcp_conns).
        let mut timed_out = Vec::new();
        let mut reclaimed_kits = Vec::new();
        for conn in &mut self.tcp_conns {
            match &mut conn.state {
                TcpState::Handshaking(_) => {
                    if now
                        >= conn
                            .accepted_at
                            .saturating_add(self.config.handshake_timeout_us)
                    {
                        let id = conn.id;
                        if let Some(kit) = Self::reclaim_and_close(&mut conn.state) {
                            reclaimed_kits.push(kit);
                        }
                        timed_out.push(id);
                    }
                }
                TcpState::Established(http) => {
                    http.handle_timeout(now);
                }
                TcpState::Closed => {}
            }
        }
        self.free_kits.append(&mut reclaimed_kits);
        for id in timed_out {
            self.push_server_event(ServerEvent::Closed(id));
        }
    }

    /// Notify the manager that the TCP peer sent EOF (read returned 0).
    ///
    /// Drains any queued HTTP events before closing, so that a request
    /// arriving alongside FIN is not lost.
    pub fn tcp_eof(&mut self, id: ConnId) {
        // Drain queued HTTP events before closing, collected into a temp vec
        // to avoid borrow conflict with push_server_event.
        let mut drained = Vec::new();
        let reclaimed_kit;
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == id) {
            if matches!(tcp.state, TcpState::Closed) {
                return;
            }
            if let TcpState::Established(http) = &mut tcp.state {
                let mut scratch_buf = [0u8; 128]; // TCP-based — scratch unused
                while let Some(ev) = http.poll_event(&mut scratch_buf) {
                    drained.push(ServerEvent::Http {
                        conn: id,
                        event: ev,
                    });
                }
            }
            reclaimed_kit = Self::reclaim_and_close(&mut tcp.state);
        } else {
            return;
        }
        if let Some(kit) = reclaimed_kit {
            self.free_kits.push(kit);
        }
        for ev in drained {
            self.push_server_event(ev);
        }
        self.push_server_event(ServerEvent::Closed(id));
    }

    /// Close a specific connection.
    pub fn close(&mut self, id: ConnId) -> Result<(), Error> {
        let reclaimed_kit;
        if let Some(tcp) = self.tcp_conns.iter_mut().find(|c| c.id == id) {
            if matches!(tcp.state, TcpState::Closed) {
                return Ok(());
            }
            reclaimed_kit = Self::reclaim_and_close(&mut tcp.state);
            if let Some(kit) = reclaimed_kit {
                self.free_kits.push(kit);
            }
            self.push_server_event(ServerEvent::Closed(id));
            return Ok(());
        }
        #[cfg(feature = "h3")]
        if let Some(qconn) = self.quic_conns.iter_mut().find(|c| c.id == id) {
            qconn.server.close(0, b"");
            return Ok(());
        }
        Err(Error::InvalidState)
    }

    /// Check if a connection is closed.
    pub fn is_closed(&self, id: ConnId) -> bool {
        if let Some(tcp) = self.tcp_conns.iter().find(|c| c.id == id) {
            return matches!(tcp.state, TcpState::Closed);
        }
        #[cfg(feature = "h3")]
        if let Some(qconn) = self.quic_conns.iter().find(|c| c.id == id) {
            return qconn.server.is_closed();
        }
        true // not found = closed
    }

    /// Number of active QUIC connections.
    #[cfg(feature = "h3")]
    pub fn quic_conn_count(&self) -> usize {
        self.quic_conns.len()
    }

    /// Number of active TCP connections.
    pub fn tcp_conn_count(&self) -> usize {
        self.tcp_conns.len()
    }

    /// Query the protocol used by a connection.
    ///
    /// Returns `None` if the connection ID is not found.
    pub fn conn_protocol(&self, id: ConnId) -> Option<ConnProtocol> {
        if let Some(tcp) = self.tcp_conns.iter().find(|c| c.id == id) {
            return Some(tcp.protocol);
        }
        #[cfg(feature = "h3")]
        if self.quic_conns.iter().any(|c| c.id == id) {
            return Some(ConnProtocol::H3);
        }
        None
    }
}
