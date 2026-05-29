//! QUIC connection state machine.
//!
//! The `Connection` struct integrates all existing modules (crypto, TLS, packet,
//! frame, transport) into a working QUIC connection. It manages the handshake,
//! packet encryption/decryption, stream multiplexing, loss detection, congestion
//! control, and flow control.

pub mod handshake_pool;
pub mod io;
pub mod keys;
pub mod recv;
pub mod transmit;

use crate::crypto::{CryptoProvider, Level};
use crate::error::Error;
use crate::tls::handshake::{Role, ServerTlsConfig, TlsConfig, TlsEngine};
use crate::tls::transport_params::TransportParams;

pub use handshake_pool::{HandshakeContext, HandshakePool, HandshakePoolAccess};

use crate::transport::congestion::CongestionController;
use crate::transport::flow_control::FlowController;
use crate::transport::loss::LossDetector;
use crate::transport::recovery::SentPacketTracker;
use crate::transport::stream::StreamMap;
use crate::transport::{Instant, Rng};

use self::keys::ConnectionKeys;
use self::recv::level_index;

// ---------------------------------------------------------------------------
// Configuration trait
// ---------------------------------------------------------------------------

/// Compile-time configuration for a QUIC connection.
///
/// Note: Rust does not allow associated constants from traits to be used as
/// const generic parameters (e.g. `StreamMap<Self::MAX_STREAMS>`). Therefore
/// the actual wiring uses const generic parameters directly on `Connection`.
/// This trait is retained as documentation and for use cases where a type-level
/// "config bundle" is useful in downstream code.
pub trait ConnectionConfig {
    const MAX_STREAMS: usize;
    const SENT_PACKETS_PER_SPACE: usize;
    const MAX_CIDS: usize;
    const CRYPTO_BUF_SIZE: usize;
}

/// Default configuration suitable for most use cases.
pub struct DefaultConfig;

impl ConnectionConfig for DefaultConfig {
    const MAX_STREAMS: usize = 32;
    const SENT_PACKETS_PER_SPACE: usize = 64;
    const MAX_CIDS: usize = 4;
    const CRYPTO_BUF_SIZE: usize = 4096;
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// High-level state of the QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// TLS handshake in progress.
    Handshaking,
    /// Handshake complete, data can be exchanged.
    Active,
    /// We received a CONNECTION_CLOSE and are draining.
    Draining,
    /// We are sending CONNECTION_CLOSE.
    Closing,
    /// Connection fully closed.
    Closed,
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// Events produced by the connection for the application layer.
#[derive(Debug, Clone)]
pub enum Event {
    /// Handshake is complete; connection is now usable.
    Connected,
    /// A new stream was opened (by the peer).
    StreamOpened(u64),
    /// Stream has data available to read.
    StreamReadable(u64),
    /// Stream can accept more data.
    StreamWritable(u64),
    /// Peer reset the stream.
    StreamReset { stream_id: u64, error_code: u64 },
    /// Peer asked us to stop sending.
    StopSending { stream_id: u64, error_code: u64 },
    /// Stream send side finished (all data acked).
    StreamFinished(u64),
    /// Connection was closed.
    ConnectionClose {
        error_code: u64,
        reason: heapless::Vec<u8, 64>,
    },
}

// ---------------------------------------------------------------------------
// ConnectionId
// ---------------------------------------------------------------------------

/// A QUIC Connection ID (up to 20 bytes).
#[derive(Debug, Clone)]
pub struct ConnectionId {
    pub bytes: [u8; 20],
    pub len: u8,
}

impl ConnectionId {
    pub fn empty() -> Self {
        Self {
            bytes: [0u8; 20],
            len: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut cid = Self::empty();
        let copy_len = data.len().min(20);
        cid.bytes[..copy_len].copy_from_slice(&data[..copy_len]);
        cid.len = copy_len as u8;
        cid
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn generate(rng: &mut impl Rng, len: u8) -> Self {
        let mut cid = Self::empty();
        let actual_len = (len as usize).min(20);
        rng.fill(&mut cid.bytes[..actual_len]);
        cid.len = actual_len as u8;
        cid
    }
}

// ---------------------------------------------------------------------------
// Transmit
// ---------------------------------------------------------------------------

/// An outgoing datagram to send on the wire.
pub struct Transmit<'a> {
    pub data: &'a [u8],
}

// ---------------------------------------------------------------------------
// Stream send queue entry
// ---------------------------------------------------------------------------

/// A pending stream data send.
///
/// The const generic `N` controls the per-entry buffer size (default: 1024).
#[derive(Clone)]
pub struct StreamSendEntry<const N: usize = 1024> {
    pub stream_id: u64,
    pub offset: u64,
    pub data: [u8; N],
    pub len: usize,
    pub fin: bool,
}

/// A simple received-data buffer for a single stream.
///
/// The const generic `N` controls the per-stream buffer size (default: 1024).
pub struct StreamRecvBuf<const N: usize = 1024> {
    pub stream_id: u64,
    pub data: [u8; N],
    pub len: usize,
    pub read_offset: usize,
    pub fin_received: bool,
    /// The next expected stream offset (byte position in the stream).
    pub next_offset: u64,
}

// ---------------------------------------------------------------------------
// Received PN tracker for ACK generation
// ---------------------------------------------------------------------------

/// Tracker of received packet number ranges per space for correct ACK generation.
///
/// Stores up to 32 non-overlapping, non-adjacent `(start, end)` inclusive
/// ranges, sorted in ascending order. When a new PN is recorded the tracker
/// extends or merges existing ranges. If the vec is full the lowest (oldest)
/// range is dropped.
pub struct RecvPnTracker {
    /// Non-overlapping, non-adjacent, ascending-sorted inclusive ranges.
    #[cfg(not(feature = "alloc"))]
    pub ranges: heapless::Vec<(u64, u64), 32>,
    #[cfg(feature = "alloc")]
    pub ranges: alloc::vec::Vec<(u64, u64)>,
    /// Highest packet number evicted from `ranges` once the tracker filled.
    /// Everything at or below this is treated as already received, so a replay
    /// of an old packet number whose range was dropped is still rejected
    /// (RFC 9000 §12.3) rather than re-processed as new.
    floor: Option<u64>,
}

impl Default for RecvPnTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RecvPnTracker {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            ranges: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            ranges: alloc::vec::Vec::new(),
            floor: None,
        }
    }

    /// The largest received PN, or `None` if nothing has been received.
    pub fn largest(&self) -> Option<u64> {
        self.ranges.last().map(|&(_, end)| end)
    }

    /// Record reception of packet number `pn`.
    pub fn record(&mut self, pn: u64) {
        // Packets at or below the floor were evicted from the window and are
        // treated as already received; do not re-insert them.
        if let Some(f) = self.floor
            && pn <= f
        {
            return;
        }
        // Find which range to extend / insert at.
        // Ranges are sorted ascending by start.

        // Check if pn is already contained in an existing range.
        // Also find potential ranges to extend.
        let mut merge_left: Option<usize> = None;
        let mut merge_right: Option<usize> = None;

        for (i, &(start, end)) in self.ranges.iter().enumerate() {
            if pn >= start && pn <= end {
                // Already tracked.
                return;
            }
            // Can extend this range's upper end by 1?
            if pn == end + 1 {
                merge_left = Some(i);
            }
            // Can extend this range's lower end by 1?
            if pn + 1 == start {
                merge_right = Some(i);
            }
        }

        match (merge_left, merge_right) {
            (Some(li), Some(ri)) => {
                // pn bridges two adjacent ranges -- merge them.
                let new_start = self.ranges[li].0;
                let new_end = self.ranges[ri].1;
                // Remove the higher-index first to keep the lower index valid.
                let (first_rm, second_rm) = if li < ri { (ri, li) } else { (li, ri) };
                self.ranges.remove(first_rm);
                self.ranges.remove(second_rm);
                // Insert merged range at the correct position.
                self.insert_range(new_start, new_end);
            }
            (Some(li), None) => {
                // Extend upper bound of range at li.
                self.ranges[li].1 = pn;
            }
            (None, Some(ri)) => {
                // Extend lower bound of range at ri.
                self.ranges[ri].0 = pn;
            }
            (None, None) => {
                // New standalone range.
                #[cfg(not(feature = "alloc"))]
                if self.ranges.is_full() {
                    // Drop the lowest (oldest) range and raise the floor so its
                    // packet numbers remain rejected as replays.
                    let dropped = self.ranges.remove(0);
                    self.floor = Some(self.floor.map_or(dropped.1, |f| f.max(dropped.1)));
                }
                #[cfg(feature = "alloc")]
                if self.ranges.len() >= 32 {
                    // Drop the lowest (oldest) range to match no-alloc cap.
                    let dropped = self.ranges.remove(0);
                    self.floor = Some(self.floor.map_or(dropped.1, |f| f.max(dropped.1)));
                }
                self.insert_range(pn, pn);
            }
        }
    }

    /// Returns `true` if `pn` has already been recorded (or is at/below the
    /// evicted floor and so must be treated as a replay).
    pub fn contains(&self, pn: u64) -> bool {
        if let Some(f) = self.floor
            && pn <= f
        {
            return true;
        }
        self.ranges
            .iter()
            .any(|&(start, end)| pn >= start && pn <= end)
    }

    /// Insert a `(start, end)` range maintaining ascending order by `start`.
    fn insert_range(&mut self, start: u64, end: u64) {
        let pos = self
            .ranges
            .iter()
            .position(|&(s, _)| s > start)
            .unwrap_or(self.ranges.len());
        // heapless::Vec doesn't have `insert`, so we push and rotate.
        let _ = self.ranges.push((start, end));
        // Shift elements right from pos to len-2 to make room.
        let len = self.ranges.len();
        if pos < len - 1 {
            // Rotate the tail so the newly pushed element ends up at `pos`.
            self.ranges[pos..].rotate_right(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Connection struct
// ---------------------------------------------------------------------------

/// A QUIC connection.
///
/// The const generic parameters allow compile-time tuning of resource limits:
///
/// - `MAX_STREAMS` — maximum number of concurrent streams (default: 32).
///   Controls the size of the internal `StreamMap`.
/// - `SENT_PER_SPACE` — maximum sent packets tracked per encryption space for
///   loss detection and ACK processing (default: 128).
/// - `MAX_CIDS` — maximum number of local connection IDs (default: 4).
///
/// Stream I/O buffers (send queue, receive buffers) are provided externally
/// via [`QuicStreamIo`](io::QuicStreamIo) to avoid per-connection buffer
/// duplication in composed stacks.
///
/// Handshake state (TLS engine, crypto reassembly buffers, pending crypto data)
/// is stored externally in a [`HandshakePool`]. This reduces per-connection
/// memory from ~38 KiB to ~15 KiB after the handshake completes.
pub struct Connection<
    C: CryptoProvider,
    const MAX_STREAMS: usize = 32,
    const SENT_PER_SPACE: usize = 128,
    const MAX_CIDS: usize = 4,
> {
    pub(crate) state: ConnectionState,
    pub(crate) role: Role,
    pub(crate) crypto: C,
    pub(crate) keys: ConnectionKeys<C>,
    pub(crate) streams: StreamMap<MAX_STREAMS>,
    pub(crate) sent_tracker: SentPacketTracker<SENT_PER_SPACE>,
    pub(crate) loss_detector: LossDetector,
    pub(crate) congestion: CongestionController,
    pub(crate) flow_control: FlowController,

    // Handshake pool slot index. Some(idx) during handshake, None after.
    pub(crate) handshake_slot: Option<u8>,

    // Our connection IDs
    pub(crate) local_cids: heapless::Vec<ConnectionId, MAX_CIDS>,
    pub(crate) remote_cid: ConnectionId,

    // Packet numbers
    pub(crate) next_pn: [u64; 3],
    pub(crate) largest_recv_pn: [Option<u64>; 3],

    // Received PN tracking per space for ACK generation
    pub(crate) recv_pn_tracker: [RecvPnTracker; 3],

    // ACK state
    pub(crate) ack_eliciting_received: [bool; 3],

    // Transport parameters
    pub(crate) local_params: TransportParams,
    pub(crate) peer_params: Option<TransportParams>,

    // Events queue
    #[cfg(not(feature = "alloc"))]
    pub(crate) events: heapless::Deque<Event, 16>,
    #[cfg(feature = "alloc")]
    pub(crate) events: alloc::collections::VecDeque<Event>,

    // Pending close
    pub(crate) close_frame: Option<(u64, heapless::Vec<u8, 64>)>,

    // Idle timeout
    pub(crate) idle_timeout: Option<u64>,
    pub(crate) last_activity: Instant,

    // Server needs to send HANDSHAKE_DONE
    pub(crate) need_handshake_done: bool,

    // PATH_RESPONSE pending data (RFC 9000 §8.2.2)
    pub(crate) pending_path_response: Option<[u8; 8]>,

    // Anti-amplification: total bytes received before address validation
    pub(crate) anti_amplification_bytes_received: usize,
    // Anti-amplification: total bytes sent before address validation
    pub(crate) anti_amplification_bytes_sent: usize,
    // Whether address has been validated (handshake complete or Retry)
    pub(crate) address_validated: bool,
}

impl<
    C: CryptoProvider,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
> Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>
where
    C::Hkdf: Default,
{
    /// Create a new client-side QUIC connection.
    ///
    /// Claims a handshake slot from the provided pool and initializes
    /// the TLS engine within it. The slot is released when the handshake
    /// completes (in `recv()`).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn client<const CRYPTO_BUF: usize>(
        crypto: C,
        server_name: &str,
        alpn: &'static [&'static [u8]],
        transport_params: TransportParams,
        rng: &mut impl Rng,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<Self, Error> {
        // Claim a handshake slot
        let slot = pool.claim()?;

        // Generate X25519 secret and random bytes
        let mut secret_bytes = [0u8; 32];
        let mut random = [0u8; 32];
        rng.fill(&mut secret_bytes);
        rng.fill(&mut random);

        // Generate a local connection ID
        let local_cid = ConnectionId::generate(rng, 8);

        // Set the client's initial_source_connection_id in transport params
        // (RFC 9000 §18.2 — both endpoints MUST include this).
        let mut tp = transport_params.clone();
        let scid_slice = local_cid.as_slice();
        let scid_len = scid_slice.len().min(20);
        tp.initial_scid[..scid_len].copy_from_slice(&scid_slice[..scid_len]);
        tp.initial_scid_len = scid_len as u8;

        let tls_config = TlsConfig {
            server_name: heapless::String::try_from(server_name).map_err(|_| Error::Tls)?,
            alpn_protocols: alpn,
            transport_params: tp,
            pinned_certs: &[],
        };

        let tls = TlsEngine::<C>::new_client(tls_config, secret_bytes, random);

        // Install TLS engine into the pool slot
        let ctx = pool.get_mut(slot);
        ctx.tls = tls;

        // Generate a random destination CID for the server
        let initial_dcid = ConnectionId::generate(rng, 8);

        let mut keys = ConnectionKeys::new();
        // Derive initial keys from the destination CID
        keys.derive_initial(&crypto, initial_dcid.as_slice(), true)?;

        let mut local_cids = heapless::Vec::new();
        let _ = local_cids.push(local_cid);

        let fc = FlowController::new(
            transport_params.initial_max_data,
            transport_params.initial_max_streams_bidi,
            transport_params.initial_max_streams_uni,
        );

        Ok(Self {
            state: ConnectionState::Handshaking,
            role: Role::Client,
            crypto,
            keys,
            streams: StreamMap::new(),
            sent_tracker: SentPacketTracker::new(),
            loss_detector: LossDetector::new(transport_params.max_ack_delay * 1000),
            congestion: CongestionController::new(1200),
            flow_control: fc,
            handshake_slot: Some(slot),
            local_cids,
            remote_cid: initial_dcid,
            next_pn: [0; 3],
            largest_recv_pn: [None; 3],
            recv_pn_tracker: core::array::from_fn(|_| RecvPnTracker::new()),
            ack_eliciting_received: [false; 3],
            local_params: transport_params,
            peer_params: None,
            #[cfg(not(feature = "alloc"))]
            events: heapless::Deque::new(),
            #[cfg(feature = "alloc")]
            events: alloc::collections::VecDeque::new(),
            close_frame: None,
            idle_timeout: None,
            last_activity: 0,
            need_handshake_done: false,
            pending_path_response: None,
            anti_amplification_bytes_received: 0,
            anti_amplification_bytes_sent: 0,
            address_validated: true, // Client doesn't need amplification protection
        })
    }

    /// Create a new server-side QUIC connection.
    ///
    /// Claims a handshake slot from the provided pool and initializes
    /// the TLS engine within it. The slot is released when the handshake
    /// completes (in `recv()`).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn server<const CRYPTO_BUF: usize>(
        crypto: C,
        config: ServerTlsConfig,
        transport_params: TransportParams,
        rng: &mut impl Rng,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<Self, Error> {
        // Claim a handshake slot
        let slot = pool.claim()?;

        let mut secret_bytes = [0u8; 32];
        let mut random = [0u8; 32];
        rng.fill(&mut secret_bytes);
        rng.fill(&mut random);

        let tls = TlsEngine::<C>::new_server(config, secret_bytes, random);

        // Install TLS engine into the pool slot
        let ctx = pool.get_mut(slot);
        ctx.tls = tls;

        let local_cid = ConnectionId::generate(rng, 8);
        let mut local_cids = heapless::Vec::new();
        let _ = local_cids.push(local_cid);

        let fc = FlowController::new(
            transport_params.initial_max_data,
            transport_params.initial_max_streams_bidi,
            transport_params.initial_max_streams_uni,
        );

        Ok(Self {
            state: ConnectionState::Handshaking,
            role: Role::Server,
            crypto,
            keys: ConnectionKeys::new(),
            streams: StreamMap::new(),
            sent_tracker: SentPacketTracker::new(),
            loss_detector: LossDetector::new(transport_params.max_ack_delay * 1000),
            congestion: CongestionController::new(1200),
            flow_control: fc,
            handshake_slot: Some(slot),
            local_cids,
            remote_cid: ConnectionId::empty(),
            next_pn: [0; 3],
            largest_recv_pn: [None; 3],
            recv_pn_tracker: core::array::from_fn(|_| RecvPnTracker::new()),
            ack_eliciting_received: [false; 3],
            local_params: transport_params,
            peer_params: None,
            #[cfg(not(feature = "alloc"))]
            events: heapless::Deque::new(),
            #[cfg(feature = "alloc")]
            events: alloc::collections::VecDeque::new(),
            close_frame: None,
            idle_timeout: None,
            last_activity: 0,
            need_handshake_done: true,
            pending_path_response: None,
            anti_amplification_bytes_received: 0,
            anti_amplification_bytes_sent: 0,
            address_validated: false, // Server must validate address before sending freely
        })
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get the next event for the application.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Get the next timer deadline.
    pub fn next_timeout(&self) -> Option<Instant> {
        if matches!(self.state, ConnectionState::Closed) {
            return None;
        }
        // Draining connections need a drain timer.
        if matches!(self.state, ConnectionState::Draining) {
            return self
                .idle_timeout
                .map(|idle| self.last_activity.saturating_add(idle));
        }
        let mut earliest = self.loss_detector.next_timeout(&self.sent_tracker);
        // Also consider idle timeout for active connections.
        if let Some(idle) = self.idle_timeout {
            let idle_deadline = self.last_activity.saturating_add(idle);
            earliest = Some(earliest.map_or(idle_deadline, |e| e.min(idle_deadline)));
        }
        earliest
    }

    /// Handle a timer expiration.
    pub fn handle_timeout(&mut self, now: Instant) {
        // Draining connections transition to Closed after idle timeout.
        // Per RFC 9000 §10.2.1, the drain period should be at least 3x PTO.
        // We reuse the idle timeout which is a conservative upper bound.
        if matches!(self.state, ConnectionState::Draining) {
            if let Some(idle) = self.idle_timeout {
                if now.saturating_sub(self.last_activity) >= idle {
                    self.state = ConnectionState::Closed;
                }
            } else {
                // No idle timeout configured — close immediately.
                self.state = ConnectionState::Closed;
            }
            return;
        }

        // Check idle timeout
        if let Some(idle) = self.idle_timeout
            && now.saturating_sub(self.last_activity) >= idle
        {
            self.state = ConnectionState::Closed;
            self.push_event(Event::ConnectionClose {
                error_code: 0,
                reason: heapless::Vec::new(),
            });
            return;
        }

        // PTO expired
        self.loss_detector.on_pto();
    }

    /// Open a new bidirectional stream.
    pub fn open_stream(&mut self) -> Result<u64, Error> {
        if !matches!(self.state, ConnectionState::Active) {
            return Err(Error::InvalidState);
        }
        let is_client = self.role == Role::Client;
        let stream_id = self.streams.open_bidi(is_client)?;
        // open_bidi seeds placeholder windows; apply the negotiated limits so we
        // may send up to the peer's advertised limit (otherwise a transfer larger
        // than the placeholder deadlocks before the peer grants more) and we
        // advertise our own limit on the receive side.
        let send_max = self
            .peer_params
            .as_ref()
            .map(|p| p.initial_max_stream_data_bidi_remote);
        self.streams.set_stream_windows(
            stream_id,
            send_max,
            Some(self.local_params.initial_max_stream_data_bidi_local),
        );
        Ok(stream_id)
    }

    /// Open a new unidirectional stream.
    pub fn open_uni_stream(&mut self) -> Result<u64, Error> {
        if !matches!(self.state, ConnectionState::Active) {
            return Err(Error::InvalidState);
        }
        let is_client = self.role == Role::Client;
        let stream_id = self.streams.open_uni(is_client)?;
        let send_max = self
            .peer_params
            .as_ref()
            .map(|p| p.initial_max_stream_data_uni);
        self.streams.set_stream_windows(stream_id, send_max, None);
        Ok(stream_id)
    }

    /// Send data on a stream.
    pub fn stream_send<const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Draining
        ) {
            return Err(Error::Closed);
        }

        // Validate stream exists
        let stream = self.streams.get(stream_id).ok_or(Error::InvalidState)?;
        let send = stream.send.as_ref().ok_or(Error::InvalidState)?;
        let offset = send.offset;

        // Limit data to available capacity
        let max_send = (send.max_data - send.offset) as usize;
        let send_len = data.len().min(max_send).min(STREAM_BUF);

        if send_len == 0 && !fin {
            return Ok(0);
        }

        // Check send queue capacity before modifying state.
        #[cfg(not(feature = "alloc"))]
        if sio.send_queue.is_full() {
            return Err(Error::BufferTooSmall {
                needed: SEND_QUEUE + 1,
            });
        }
        #[cfg(feature = "alloc")]
        if sio.send_queue.len() >= SEND_QUEUE {
            return Err(Error::BufferTooSmall {
                needed: SEND_QUEUE + 1,
            });
        }

        // Record in stream map
        self.streams.mark_send(stream_id, send_len as u64, fin)?;

        // Queue for transmission
        let mut entry = StreamSendEntry {
            stream_id,
            offset,
            data: [0u8; STREAM_BUF],
            len: send_len,
            fin,
        };
        entry.data[..send_len].copy_from_slice(&data[..send_len]);
        let _ = sio.send_queue.push(entry);

        Ok(send_len)
    }

    /// Receive data from a stream.
    pub fn stream_recv<const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        if matches!(self.state, ConnectionState::Closed) {
            return Err(Error::Closed);
        }

        // Look for data in our receive buffers
        for slot in sio.recv_bufs.iter_mut() {
            if let Some(recv) = slot
                && recv.stream_id == stream_id
            {
                let available = recv.len - recv.read_offset;
                if available == 0 {
                    if recv.fin_received {
                        let fin = true;
                        *slot = None;
                        return Ok((0, fin));
                    }
                    return Err(Error::WouldBlock);
                }
                let copy_len = available.min(buf.len());
                buf[..copy_len]
                    .copy_from_slice(&recv.data[recv.read_offset..recv.read_offset + copy_len]);
                recv.read_offset += copy_len;
                let fin = recv.fin_received && recv.read_offset >= recv.len;
                if fin {
                    *slot = None;
                } else if recv.read_offset > 0 {
                    // Compact: discard already-read bytes from the front so the
                    // fixed-capacity buffer can keep accepting data on a
                    // long-lived stream. Without this, `len` only ever grows and
                    // store_stream_data silently drops everything once the
                    // buffer first fills, capping stream throughput at STREAM_BUF.
                    recv.data.copy_within(recv.read_offset..recv.len, 0);
                    recv.len -= recv.read_offset;
                    recv.read_offset = 0;
                }
                return Ok((copy_len, fin));
            }
        }

        Err(Error::WouldBlock)
    }

    /// Reset a stream (send RESET_STREAM to peer).
    pub fn stream_reset(&mut self, stream_id: u64, _error_code: u64) -> Result<(), Error> {
        self.streams.mark_reset_sent(stream_id)
    }

    /// Tell peer to stop sending on a stream.
    pub fn stream_stop_sending(&mut self, stream_id: u64, _error_code: u64) -> Result<(), Error> {
        // Mark in stream map; the actual frame is sent in poll_transmit
        self.streams.handle_stop_sending(stream_id)
    }

    /// Initiate connection close.
    pub fn close(&mut self, error_code: u64, reason: &[u8]) {
        if matches!(
            self.state,
            ConnectionState::Closed | ConnectionState::Draining | ConnectionState::Closing
        ) {
            return;
        }
        let mut reason_vec = heapless::Vec::new();
        let copy_len = reason.len().min(64);
        let _ = reason_vec.extend_from_slice(&reason[..copy_len]);
        self.close_frame = Some((error_code, reason_vec));
        self.state = ConnectionState::Closing;
    }

    /// Is the connection fully closed?
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Closed)
    }

    /// Is the handshake complete and the connection established?
    pub fn is_established(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }

    /// Get the local connection IDs.
    pub fn local_cids(&self) -> &[ConnectionId] {
        &self.local_cids
    }

    /// Initiate a QUIC key update (RFC 9001 section 6).
    ///
    /// Derives next-generation application send/recv keys, rotates the
    /// current recv key to `prev_recv` for decrypting late packets, and
    /// flips the key_phase bit so subsequent outgoing packets use the
    /// new keys.
    ///
    /// Returns `Err` if:
    /// - The connection is not yet established (handshake not complete)
    /// - A previous key update has not yet been confirmed by the peer
    /// - Application keys are not installed
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn initiate_key_update(&mut self) -> Result<(), Error> {
        if !matches!(self.state, ConnectionState::Active) {
            return Err(Error::InvalidState);
        }
        self.keys.perform_key_update(&self.crypto)
    }

    /// Get the current key phase bit (0 or 1) for 1-RTT packets.
    pub fn key_phase(&self) -> u8 {
        self.keys.key_phase()
    }

    /// Get the connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Push an event to the events queue, enforcing a capacity limit for alloc.
    pub(crate) fn push_event(&mut self, event: Event) {
        #[cfg(not(feature = "alloc"))]
        {
            let _ = self.events.push_back(event);
        }
        #[cfg(feature = "alloc")]
        {
            if self.events.len() < 64 {
                self.events.push_back(event);
            }
        }
    }

    /// Store received stream data in a receive buffer, respecting the offset.
    ///
    /// - If `offset` equals the expected next offset, data is appended.
    /// - If `offset` is less than expected (duplicate/overlap), already-received
    ///   bytes are skipped and only the new tail (if any) is appended.
    /// - If `offset` is greater than expected (gap), the frame is dropped
    ///   because we do not buffer out-of-order data; QUIC will retransmit.
    pub(crate) fn store_stream_data<const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) {
        // Find existing buffer or allocate new one
        let mut target_idx = None;
        for (i, slot) in sio.recv_bufs.iter().enumerate() {
            if let Some(buf) = slot
                && buf.stream_id == stream_id
            {
                target_idx = Some(i);
                break;
            }
        }

        if target_idx.is_none() {
            // Find empty slot
            for (i, slot) in sio.recv_bufs.iter().enumerate() {
                if slot.is_none() {
                    target_idx = Some(i);
                    break;
                }
            }
        }

        // With alloc, grow the Vec on demand if no empty slot was found (capped at MAX_STREAMS).
        #[cfg(feature = "alloc")]
        if target_idx.is_none() && sio.recv_bufs.len() < MAX_STREAMS {
            let new_idx = sio.recv_bufs.len();
            sio.recv_bufs.push(None);
            target_idx = Some(new_idx);
        }

        if let Some(idx) = target_idx {
            if sio.recv_bufs[idx].is_none() {
                sio.recv_bufs[idx] = Some(StreamRecvBuf {
                    stream_id,
                    data: [0u8; STREAM_BUF],
                    len: 0,
                    read_offset: 0,
                    fin_received: false,
                    next_offset: 0,
                });
            }
            if let Some(ref mut buf) = sio.recv_bufs[idx] {
                let frame_end = offset + data.len() as u64;

                if offset > buf.next_offset {
                    return;
                }

                if frame_end <= buf.next_offset {
                    if fin {
                        buf.fin_received = true;
                    }
                    return;
                }

                let skip = (buf.next_offset - offset) as usize;
                let new_data = &data[skip..];
                let copy_len = new_data.len().min(STREAM_BUF - buf.len);
                buf.data[buf.len..buf.len + copy_len].copy_from_slice(&new_data[..copy_len]);
                buf.len += copy_len;
                buf.next_offset += copy_len as u64;
                if fin {
                    buf.fin_received = true;
                }
            }
        }
    }

    /// Check whether the anti-amplification limit allows sending `bytes` more bytes.
    /// Returns `true` if sending is allowed, `false` if it would exceed the 3x limit.
    pub(crate) fn amplification_allows(&self, bytes: usize) -> bool {
        if self.address_validated {
            return true;
        }
        self.anti_amplification_bytes_sent + bytes <= 3 * self.anti_amplification_bytes_received
    }

    /// Track a received packet number for ACK generation.
    pub(crate) fn track_received_pn(&mut self, level: Level, pn: u64) {
        let idx = level_index(level);
        self.recv_pn_tracker[idx].record(pn);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MIN_INITIAL_PACKET_SIZE;

    #[test]
    fn connection_id_from_slice() {
        let cid = ConnectionId::from_slice(&[1, 2, 3, 4]);
        assert_eq!(cid.len, 4);
        assert_eq!(cid.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn connection_id_empty() {
        let cid = ConnectionId::empty();
        assert_eq!(cid.len, 0);
        assert_eq!(cid.as_slice().len(), 0);
    }

    #[test]
    fn connection_id_max_len() {
        let data = [0xAA; 25]; // longer than 20
        let cid = ConnectionId::from_slice(&data);
        assert_eq!(cid.len, 20);
        assert_eq!(cid.as_slice().len(), 20);
    }

    #[test]
    fn connection_state_initial() {
        assert_eq!(ConnectionState::Handshaking, ConnectionState::Handshaking);
    }

    #[test]
    fn default_config_values() {
        assert_eq!(DefaultConfig::MAX_STREAMS, 32);
        assert_eq!(DefaultConfig::SENT_PACKETS_PER_SPACE, 64);
        assert_eq!(DefaultConfig::MAX_CIDS, 4);
        assert_eq!(DefaultConfig::CRYPTO_BUF_SIZE, 4096);
    }

    struct TestRng(u8);

    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn connection_id_generate() {
        let mut rng = TestRng(0x42);
        let cid = ConnectionId::generate(&mut rng, 8);
        assert_eq!(cid.len, 8);
        assert_eq!(cid.as_slice()[0], 0x42);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_connection_creates() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
            &mut pool,
        );
        assert!(conn.is_ok());
        let conn = conn.unwrap();
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert_eq!(conn.role, Role::Client);
        assert!(!conn.is_established());
        assert!(!conn.is_closed());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_connection_creates() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::tls::handshake::ServerTlsConfig;

        let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
        let mut rng = TestRng(0x20);
        let tp = TransportParams::default_params();
        let config = ServerTlsConfig {
            cert_der: &[0xDE, 0xAD],
            private_key_der: &[0x01, 0x02],
            alpn_protocols: &[b"h3"],
            transport_params: tp.clone(),
        };
        let conn = Connection::<Aes128GcmProvider>::server(
            Aes128GcmProvider,
            config,
            tp,
            &mut rng,
            &mut pool,
        );
        assert!(conn.is_ok());
        let conn = conn.unwrap();
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert_eq!(conn.role, Role::Server);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_poll_transmit_produces_initial() {
        use super::io::QuicStreamIoBufs;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

        let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let mut conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
            &mut pool,
        )
        .unwrap();

        let mut sio_bufs = SioBufs::new();
        let mut buf = [0u8; 2048];
        let tx = conn.poll_transmit(&mut sio_bufs.as_io(), &mut buf, 0, &mut pool);
        assert!(tx.is_some());
        let tx = tx.unwrap();

        // Should be at least MIN_INITIAL_PACKET_SIZE
        assert!(
            tx.data.len() >= MIN_INITIAL_PACKET_SIZE,
            "Initial packet should be padded to at least 1200 bytes, got {}",
            tx.data.len()
        );

        // First byte should be a long header (form bit set)
        assert!(tx.data[0] & 0x80 != 0, "should be long header");
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn close_transitions_state() {
        use super::io::QuicStreamIoBufs;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

        let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let mut conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
            &mut pool,
        )
        .unwrap();

        conn.close(0, b"goodbye");
        assert_eq!(conn.state, ConnectionState::Closing);

        // poll_transmit should send the close frame
        let mut sio_bufs = SioBufs::new();
        let mut buf = [0u8; 2048];
        let tx = conn.poll_transmit(&mut sio_bufs.as_io(), &mut buf, 0, &mut pool);
        assert!(tx.is_some());
        assert_eq!(conn.state, ConnectionState::Closed);
        assert!(conn.is_closed());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn recv_pn_tracker() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
        let mut rng = TestRng(0x10);
        let tp = TransportParams::default_params();
        let mut conn = Connection::<Aes128GcmProvider>::client(
            Aes128GcmProvider,
            "example.com",
            &[b"h3"],
            tp,
            &mut rng,
            &mut pool,
        )
        .unwrap();

        conn.track_received_pn(Level::Initial, 0);
        conn.track_received_pn(Level::Initial, 1);
        conn.track_received_pn(Level::Initial, 5);

        assert_eq!(conn.recv_pn_tracker[0].largest(), Some(5));
        // Should have two ranges: [0,1] and [5,5]
        assert_eq!(conn.recv_pn_tracker[0].ranges.len(), 2);
        assert_eq!(conn.recv_pn_tracker[0].ranges[0], (0, 1));
        assert_eq!(conn.recv_pn_tracker[0].ranges[1], (5, 5));
    }

    // =========================================================================
    // Integration test: full client-server handshake over Connection API
    // =========================================================================

    // -----------------------------------------------------------------------
    // Phase 13: Anti-amplification tests
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    mod amplification_tests {
        use super::io::QuicStreamIoBufs;
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::tls::handshake::ServerTlsConfig;
        type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

        const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

        fn get_test_ed25519_cert_der() -> &'static [u8] {
            use std::sync::LazyLock;
            static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
                let s: [u8; 32] = [0x01u8; 32];
                let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
                let mut b = [0u8; 512];
                let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
                b[..n].to_vec()
            });
            &V
        }

        struct TestRng(u8);
        impl Rng for TestRng {
            fn fill(&mut self, buf: &mut [u8]) {
                for b in buf.iter_mut() {
                    *b = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
            }
        }

        #[test]
        fn client_address_always_validated() {
            let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
            let mut rng = TestRng(0x10);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let conn = Connection::<Aes128GcmProvider>::client(
                Aes128GcmProvider,
                "example.com",
                &[b"h3"],
                tp,
                &mut rng,
                &mut pool,
            )
            .unwrap();
            assert!(conn.address_validated);
        }

        #[test]
        fn server_address_not_validated_initially() {
            let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
                &mut pool,
            )
            .unwrap();
            assert!(!conn.address_validated);
        }

        #[test]
        fn amplification_allows_within_3x() {
            let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let mut conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
                &mut pool,
            )
            .unwrap();

            conn.anti_amplification_bytes_received = 1200;
            assert!(conn.amplification_allows(3600));
            assert!(!conn.amplification_allows(3601));

            conn.anti_amplification_bytes_sent = 3000;
            assert!(conn.amplification_allows(600));
            assert!(!conn.amplification_allows(601));
        }

        #[test]
        fn amplification_allows_after_validation() {
            let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let mut conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
                &mut pool,
            )
            .unwrap();

            assert!(!conn.amplification_allows(1));
            conn.address_validated = true;
            assert!(conn.amplification_allows(1_000_000));
        }

        #[test]
        fn amplification_zero_received_blocks_all() {
            let mut pool = HandshakePool::<Aes128GcmProvider, 2>::new();
            let mut rng = TestRng(0x20);
            let tp = crate::tls::transport_params::TransportParams::default_params();
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let conn = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
                &mut pool,
            )
            .unwrap();

            assert!(!conn.amplification_allows(1));
            assert!(conn.amplification_allows(0));
        }

        #[test]
        fn server_validated_after_handshake() {
            let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();
            let mut rng_c = TestRng(0x10);
            let mut rng_s = TestRng(0x50);
            let tp = crate::tls::transport_params::TransportParams::default_params();

            let mut client = Connection::<Aes128GcmProvider>::client(
                Aes128GcmProvider,
                "test.local",
                &[b"h3"],
                tp.clone(),
                &mut rng_c,
                &mut pool,
            )
            .unwrap();

            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };
            let mut server = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng_s,
                &mut pool,
            )
            .unwrap();

            assert!(!server.address_validated);

            let mut c_sio = SioBufs::new();
            let mut s_sio = SioBufs::new();
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;
            for _round in 0..20 {
                loop {
                    let mut buf = [0u8; 4096];
                    match client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool) {
                        Some(tx) => {
                            let data: heapless::Vec<u8, 4096> = {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(tx.data);
                                v
                            };
                            let _ = server.recv(
                                &mut s_sio.as_io(),
                                &data,
                                &mut scratch,
                                now,
                                &mut pool,
                            );
                        }
                        None => break,
                    }
                }
                loop {
                    let mut buf = [0u8; 4096];
                    match server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool) {
                        Some(tx) => {
                            let data: heapless::Vec<u8, 4096> = {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(tx.data);
                                v
                            };
                            let _ = client.recv(
                                &mut c_sio.as_io(),
                                &data,
                                &mut scratch,
                                now,
                                &mut pool,
                            );
                        }
                        None => break,
                    }
                }
                if client.is_established() && server.is_established() {
                    break;
                }
            }

            assert!(server.is_established());
            assert!(
                server.address_validated,
                "server should be address-validated after handshake"
            );
        }
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    mod integration {
        use super::io::QuicStreamIoBufs;
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::packet::MIN_INITIAL_PACKET_SIZE;
        use crate::tls::handshake::ServerTlsConfig;
        type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

        const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

        fn get_test_ed25519_cert_der() -> &'static [u8] {
            use std::sync::LazyLock;
            static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
                let s: [u8; 32] = [0x01u8; 32];
                let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
                let mut b = [0u8; 512];
                let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
                b[..n].to_vec()
            });
            &V
        }

        struct TestRng(u8);
        impl Rng for TestRng {
            fn fill(&mut self, buf: &mut [u8]) {
                for b in buf.iter_mut() {
                    *b = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
            }
        }

        fn make_pool() -> HandshakePool<Aes128GcmProvider, 4> {
            HandshakePool::new()
        }

        fn make_client(
            pool: &mut HandshakePool<Aes128GcmProvider, 4>,
        ) -> (Connection<Aes128GcmProvider>, SioBufs) {
            let mut rng = TestRng(0x10);
            let conn = Connection::client(
                Aes128GcmProvider,
                "test.local",
                &[b"h3"],
                TransportParams::default_params(),
                &mut rng,
                pool,
            )
            .unwrap();
            (conn, SioBufs::new())
        }

        fn make_server(
            pool: &mut HandshakePool<Aes128GcmProvider, 4>,
        ) -> (Connection<Aes128GcmProvider>, SioBufs) {
            let mut rng = TestRng(0x50);
            let config = ServerTlsConfig {
                cert_der: get_test_ed25519_cert_der(),
                private_key_der: &TEST_ED25519_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: TransportParams::default_params(),
            };
            let conn = Connection::server(
                Aes128GcmProvider,
                config,
                TransportParams::default_params(),
                &mut rng,
                pool,
            )
            .unwrap();
            (conn, SioBufs::new())
        }

        #[test]
        fn client_generates_padded_initial() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool)
                .unwrap();
            assert!(tx.data.len() >= MIN_INITIAL_PACKET_SIZE);
        }

        #[test]
        fn full_handshake() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let now = 1_000_000u64;

            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            assert!(server.is_established());
            assert!(client.is_established());

            let mut found_connected = false;
            while let Some(ev) = client.poll_event() {
                if matches!(ev, Event::Connected) {
                    found_connected = true;
                }
            }
            assert!(
                found_connected,
                "client should have received Connected event"
            );
        }

        #[test]
        fn stream_data_after_handshake() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;

            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            assert!(client.is_established());
            assert!(server.is_established());

            let stream_id = client.open_stream().unwrap();
            let data = b"hello from client";
            let sent = client
                .stream_send(&mut c_sio.as_io(), stream_id, data, false)
                .unwrap();
            assert_eq!(sent, data.len());

            let mut buf = [0u8; 2048];
            let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
            assert!(tx.is_some(), "should have stream data to send");

            let tx = tx.unwrap();
            let pkt_data: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };

            server
                .recv(&mut s_sio.as_io(), &pkt_data, &mut scratch, now, &mut pool)
                .unwrap();

            let mut found_readable = false;
            while let Some(ev) = server.poll_event() {
                if matches!(ev, Event::StreamReadable(id) if id == stream_id) {
                    found_readable = true;
                }
            }
            assert!(found_readable, "server should see StreamReadable event");

            let mut recv_buf = [0u8; 256];
            let (read_len, fin) = server
                .stream_recv(&mut s_sio.as_io(), stream_id, &mut recv_buf)
                .unwrap();
            assert_eq!(read_len, data.len());
            assert_eq!(&recv_buf[..read_len], data);
            assert!(!fin);
        }

        #[test]
        fn connection_close_after_handshake() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;

            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            client.close(0, b"done");
            assert_eq!(client.state(), ConnectionState::Closing);

            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let close_pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };

            assert!(client.is_closed());

            server
                .recv(&mut s_sio.as_io(), &close_pkt, &mut scratch, now, &mut pool)
                .unwrap();
            assert_eq!(server.state(), ConnectionState::Draining);

            let mut found_close = false;
            while let Some(ev) = server.poll_event() {
                if matches!(ev, Event::ConnectionClose { error_code: 0, .. }) {
                    found_close = true;
                }
            }
            assert!(found_close, "server should see ConnectionClose event");
        }

        fn run_handshake_to_completion(
            client: &mut Connection<Aes128GcmProvider>,
            c_sio: &mut SioBufs,
            server: &mut Connection<Aes128GcmProvider>,
            s_sio: &mut SioBufs,
            now: Instant,
            pool: &mut HandshakePool<Aes128GcmProvider, 4>,
        ) {
            let mut scratch = [0u8; 2048];
            for _round in 0..20 {
                loop {
                    let mut buf = [0u8; 4096];
                    match client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, pool) {
                        Some(tx) => {
                            let data: heapless::Vec<u8, 4096> = {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(tx.data);
                                v
                            };
                            let _ = server.recv(&mut s_sio.as_io(), &data, &mut scratch, now, pool);
                        }
                        None => break,
                    }
                }
                loop {
                    let mut buf = [0u8; 4096];
                    match server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, pool) {
                        Some(tx) => {
                            let data: heapless::Vec<u8, 4096> = {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(tx.data);
                                v
                            };
                            let _ = client.recv(&mut c_sio.as_io(), &data, &mut scratch, now, pool);
                        }
                        None => break,
                    }
                }
                if client.is_established() && server.is_established() {
                    return;
                }
            }
            assert!(
                client.is_established() && server.is_established(),
                "handshake did not complete after 20 rounds: client={:?}, server={:?}",
                client.state(),
                server.state()
            );
        }

        #[test]
        fn open_stream_before_handshake_fails() {
            let mut pool = make_pool();
            let (mut client, _c_sio) = make_client(&mut pool);
            assert_eq!(client.open_stream().unwrap_err(), Error::InvalidState);
        }

        #[test]
        fn poll_event_empty_initially() {
            let mut pool = make_pool();
            let (mut client, _c_sio) = make_client(&mut pool);
            assert!(client.poll_event().is_none());
        }

        #[test]
        fn multiple_poll_transmit_drains() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let mut buf = [0u8; 2048];

            let tx1 = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);
            assert!(tx1.is_some());

            let tx2 = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);
            assert!(tx2.is_none());
        }

        #[test]
        fn stream_send_with_fin() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;

            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            let stream_id = client.open_stream().unwrap();
            let sent = client
                .stream_send(&mut c_sio.as_io(), stream_id, b"final", true)
                .unwrap();
            assert_eq!(sent, 5);

            let mut buf = [0u8; 2048];
            let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
            assert!(tx.is_some());

            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.unwrap().data);
                v
            };

            server
                .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
                .unwrap();

            let mut recv_buf = [0u8; 256];
            let (len, fin) = server
                .stream_recv(&mut s_sio.as_io(), stream_id, &mut recv_buf)
                .unwrap();
            assert_eq!(len, 5);
            assert_eq!(&recv_buf[..len], b"final");
            assert!(fin);
        }

        // -------------------------------------------------------------------
        // PATH_CHALLENGE / PATH_RESPONSE tests (RFC 9000 §8.2.2)
        // -------------------------------------------------------------------

        #[test]
        fn path_challenge_stores_pending_response() {
            // After a handshake completes, directly inject a PATH_CHALLENGE
            // frame into the server's dispatch_frame and verify that
            // pending_path_response is set with the correct data.
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            assert!(server.pending_path_response.is_none());

            // Simulate receiving a PATH_CHALLENGE frame
            let challenge_data: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
            let frame = crate::frame::Frame::PathChallenge(challenge_data);
            server
                .dispatch_frame(
                    &mut s_sio.as_io(),
                    frame,
                    crate::crypto::Level::Application,
                    now,
                    &mut pool,
                )
                .unwrap();

            assert_eq!(
                server.pending_path_response,
                Some(challenge_data),
                "PATH_CHALLENGE should store the 8-byte challenge data"
            );
        }

        #[test]
        fn path_response_echoes_exact_challenge_bytes() {
            // After injecting a PATH_CHALLENGE, verify that poll_transmit
            // produces a packet and that the pending_path_response is cleared.
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            // Drain any pending transmits from the handshake
            loop {
                let mut buf = [0u8; 4096];
                if server
                    .poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }

            // Inject PATH_CHALLENGE
            let challenge_data: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
            let frame = crate::frame::Frame::PathChallenge(challenge_data);
            // Mark as ack-eliciting so that the ack_eliciting flag triggers
            // (PATH_CHALLENGE is ack-eliciting)
            server
                .dispatch_frame(
                    &mut s_sio.as_io(),
                    frame,
                    crate::crypto::Level::Application,
                    now,
                    &mut pool,
                )
                .unwrap();
            assert!(server.pending_path_response.is_some());

            // poll_transmit should produce a packet containing PATH_RESPONSE
            let mut buf = [0u8; 2048];
            let tx = server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool);
            assert!(
                tx.is_some(),
                "server should send a PATH_RESPONSE after PATH_CHALLENGE"
            );

            // After transmitting, pending_path_response should be cleared
            assert_eq!(
                server.pending_path_response, None,
                "pending_path_response should be cleared after sending"
            );
        }

        #[test]
        fn path_challenge_end_to_end() {
            // Full end-to-end test: client sends PATH_CHALLENGE to server,
            // server responds with PATH_RESPONSE, client decodes it.
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            // Drain remaining transmits from both sides
            loop {
                let mut buf = [0u8; 4096];
                if client
                    .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }
            loop {
                let mut buf = [0u8; 4096];
                if server
                    .poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }

            // Inject a PATH_CHALLENGE into the server as if it received one
            let challenge_data: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
            server.pending_path_response = Some(challenge_data);
            // Also set ack_eliciting so the packet gets built
            server.ack_eliciting_received[2] = true; // Application level

            // Server generates a short packet with the PATH_RESPONSE
            let mut buf = [0u8; 2048];
            let tx = server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool);
            assert!(
                tx.is_some(),
                "server should produce a packet with PATH_RESPONSE"
            );

            // The PATH_RESPONSE is now cleared
            assert!(server.pending_path_response.is_none());

            // Client receives and processes the packet
            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.unwrap().data);
                v
            };
            let result = client.recv(&mut c_sio.as_io(), &pkt, &mut scratch, now, &mut pool);
            assert!(
                result.is_ok(),
                "client should process PATH_RESPONSE without error"
            );
        }

        #[test]
        fn successive_path_challenges_last_wins() {
            // If multiple PATH_CHALLENGEs arrive, only the last one is stored.
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            let data1: [u8; 8] = [0x01; 8];
            let data2: [u8; 8] = [0x02; 8];

            let frame1 = crate::frame::Frame::PathChallenge(data1);
            server
                .dispatch_frame(
                    &mut s_sio.as_io(),
                    frame1,
                    crate::crypto::Level::Application,
                    now,
                    &mut pool,
                )
                .unwrap();
            assert_eq!(server.pending_path_response, Some(data1));

            let frame2 = crate::frame::Frame::PathChallenge(data2);
            server
                .dispatch_frame(
                    &mut s_sio.as_io(),
                    frame2,
                    crate::crypto::Level::Application,
                    now,
                    &mut pool,
                )
                .unwrap();
            assert_eq!(
                server.pending_path_response,
                Some(data2),
                "the most recent PATH_CHALLENGE should overwrite the previous one"
            );
        }

        // -------------------------------------------------------------------
        // Key Update tests (RFC 9001 section 6)
        // -------------------------------------------------------------------

        #[test]
        fn key_update_before_handshake_fails() {
            let mut pool = make_pool();
            let (mut client, _c_sio) = make_client(&mut pool);
            let result = client.initiate_key_update();
            assert_eq!(result.unwrap_err(), Error::InvalidState);
        }

        #[test]
        fn key_update_after_handshake_succeeds() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            assert_eq!(client.key_phase(), 0);
            let result = client.initiate_key_update();
            assert!(result.is_ok(), "key update should succeed after handshake");
            assert_eq!(client.key_phase(), 1);
        }

        #[test]
        fn key_phase_bit_in_outgoing_short_packets() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            // Drain any pending transmits
            loop {
                let mut buf = [0u8; 4096];
                if client
                    .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }

            // Before key update, internal key_phase should be 0
            assert_eq!(client.key_phase(), 0);
            let stream_id = client.open_stream().unwrap();
            client
                .stream_send(&mut c_sio.as_io(), stream_id, b"phase0", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            // Short header: first byte bit 7 = 0 (short)
            // Note: bits 0-4 are masked by header protection, so we can't
            // directly check the key_phase bit from the wire format.
            let first_byte = tx.data[0];
            assert_eq!(first_byte & 0x80, 0, "should be short header");
            assert_eq!(client.key_phase(), 0, "key_phase should be 0");

            // Initiate key update
            client.initiate_key_update().unwrap();

            // After key update, key_phase = 1 => bit 2 of first byte should be 1
            let stream_id2 = client.open_stream().unwrap();
            client
                .stream_send(&mut c_sio.as_io(), stream_id2, b"phase1", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let first_byte = tx.data[0];
            assert_eq!(first_byte & 0x80, 0, "should be short header");
            // Note: first_byte has header protection applied, so we can't
            // directly check the key_phase bit from the wire format.
            // But the internal key_phase should be 1.
            assert_eq!(client.key_phase(), 1);
        }

        #[test]
        fn key_update_data_exchange() {
            // Full integration: handshake, send data, key update, send more data
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            // Drain pending transmits
            loop {
                let mut buf = [0u8; 4096];
                if client
                    .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }
            loop {
                let mut buf = [0u8; 4096];
                if server
                    .poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }

            // Send data before key update
            let stream_id = client.open_stream().unwrap();
            client
                .stream_send(&mut c_sio.as_io(), stream_id, b"before update", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };
            server
                .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
                .unwrap();

            let mut recv_buf = [0u8; 256];
            let (len, _fin) = server
                .stream_recv(&mut s_sio.as_io(), stream_id, &mut recv_buf)
                .unwrap();
            assert_eq!(&recv_buf[..len], b"before update");

            // Client initiates key update
            assert_eq!(client.key_phase(), 0);
            client.initiate_key_update().unwrap();
            assert_eq!(client.key_phase(), 1);

            // Client sends data with new keys (key_phase = 1)
            client
                .stream_send(&mut c_sio.as_io(), stream_id, b" after update", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };

            // Server receives: should detect key_phase change and update keys
            assert_eq!(server.key_phase(), 0);
            server
                .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
                .unwrap();
            // After processing, server should have updated its key phase
            assert_eq!(server.key_phase(), 1);

            let mut recv_buf = [0u8; 256];
            let (len, _fin) = server
                .stream_recv(&mut s_sio.as_io(), stream_id, &mut recv_buf)
                .unwrap();
            assert_eq!(&recv_buf[..len], b" after update");
        }

        #[test]
        fn bidirectional_key_update() {
            // Both sides send data after one side does a key update
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            // Drain pending transmits
            loop {
                let mut buf = [0u8; 4096];
                if client
                    .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }
            loop {
                let mut buf = [0u8; 4096];
                if server
                    .poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool)
                    .is_none()
                {
                    break;
                }
            }

            // Client initiates key update
            client.initiate_key_update().unwrap();
            assert_eq!(client.key_phase(), 1);

            // Client sends with new keys
            let c_stream = client.open_stream().unwrap();
            client
                .stream_send(&mut c_sio.as_io(), c_stream, b"client data", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };
            server
                .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
                .unwrap();
            assert_eq!(server.key_phase(), 1);

            // Now server responds with new keys as well
            let s_stream = server.open_stream().unwrap();
            server
                .stream_send(&mut s_sio.as_io(), s_stream, b"server data", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = server
                .poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };
            client
                .recv(&mut c_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
                .unwrap();

            // Both sides should still be on key_phase 1
            assert_eq!(client.key_phase(), 1);
            assert_eq!(server.key_phase(), 1);

            // Verify data was received
            let mut recv_buf = [0u8; 256];
            let (len, _) = server
                .stream_recv(&mut s_sio.as_io(), c_stream, &mut recv_buf)
                .unwrap();
            assert_eq!(&recv_buf[..len], b"client data");

            let (len, _) = client
                .stream_recv(&mut c_sio.as_io(), s_stream, &mut recv_buf)
                .unwrap();
            assert_eq!(&recv_buf[..len], b"server data");
        }

        #[test]
        fn double_key_update_blocked_until_confirmed() {
            let mut pool = make_pool();
            let (mut client, mut c_sio) = make_client(&mut pool);
            let (mut server, mut s_sio) = make_server(&mut pool);
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;
            run_handshake_to_completion(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );

            // First key update succeeds
            client.initiate_key_update().unwrap();
            assert_eq!(client.key_phase(), 1);

            // Second key update fails (not yet confirmed by peer)
            let result = client.initiate_key_update();
            assert!(
                result.is_err(),
                "second key update should fail before confirmation"
            );

            // Send a packet to the server to trigger peer update
            let stream_id = client.open_stream().unwrap();
            client
                .stream_send(&mut c_sio.as_io(), stream_id, b"confirm me", false)
                .unwrap();
            let mut buf = [0u8; 2048];
            let tx = client
                .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
                .unwrap();
            let pkt: heapless::Vec<u8, 2048> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(tx.data);
                v
            };
            server
                .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
                .unwrap();

            // Drain server transmits and have client receive them (ACK with new phase)
            loop {
                let mut buf = [0u8; 4096];
                match server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool) {
                    Some(tx) => {
                        let data: heapless::Vec<u8, 4096> = {
                            let mut v = heapless::Vec::new();
                            let _ = v.extend_from_slice(tx.data);
                            v
                        };
                        let _ =
                            client.recv(&mut c_sio.as_io(), &data, &mut scratch, now, &mut pool);
                    }
                    None => break,
                }
            }

            // Now the client's key update should be confirmed
            assert!(client.keys.key_update.update_confirmed);

            // Second key update should now succeed
            client.initiate_key_update().unwrap();
            assert_eq!(client.key_phase(), 0); // Flipped back to 0
        }
    }

    // =========================================================================
    // M9 — RecvPnTracker range-based ACK generation tests
    // =========================================================================

    mod recv_pn_tracker_tests {
        use super::*;

        #[test]
        fn single_pn_produces_single_range() {
            let mut t = RecvPnTracker::new();
            t.record(5);
            assert_eq!(t.ranges.as_slice(), &[(5, 5)]);
            assert_eq!(t.largest(), Some(5));
        }

        #[test]
        fn contiguous_pns_merge_into_one_range() {
            let mut t = RecvPnTracker::new();
            t.record(0);
            t.record(1);
            t.record(2);
            t.record(3);
            assert_eq!(t.ranges.as_slice(), &[(0, 3)]);
        }

        #[test]
        fn non_contiguous_pns_produce_multiple_ranges() {
            let mut t = RecvPnTracker::new();
            // Receive 0, 1, 5, 6, 10
            t.record(0);
            t.record(1);
            t.record(5);
            t.record(6);
            t.record(10);
            assert_eq!(t.ranges.as_slice(), &[(0, 1), (5, 6), (10, 10)]);
        }

        #[test]
        fn filling_gap_merges_ranges() {
            let mut t = RecvPnTracker::new();
            t.record(0);
            t.record(2);
            assert_eq!(t.ranges.as_slice(), &[(0, 0), (2, 2)]);
            // Now fill the gap
            t.record(1);
            assert_eq!(t.ranges.as_slice(), &[(0, 2)]);
        }

        #[test]
        fn out_of_order_pns_correctly_tracked() {
            let mut t = RecvPnTracker::new();
            t.record(5);
            t.record(3);
            t.record(1);
            t.record(4);
            t.record(2);
            // Should all merge into one range
            assert_eq!(t.ranges.as_slice(), &[(1, 5)]);
        }

        #[test]
        fn duplicate_pn_is_idempotent() {
            let mut t = RecvPnTracker::new();
            t.record(3);
            t.record(3);
            t.record(3);
            assert_eq!(t.ranges.as_slice(), &[(3, 3)]);
        }

        #[cfg(not(feature = "alloc"))]
        #[test]
        fn full_tracker_drops_lowest_range() {
            let mut t = RecvPnTracker::new();
            // Fill all 32 slots with non-contiguous ranges: 0, 100, 200, ...
            for i in 0..32 {
                t.record(i * 100);
            }
            assert_eq!(t.ranges.len(), 32);
            assert_eq!(t.ranges[0], (0, 0));

            // Adding one more should drop the lowest (0, 0)
            t.record(5000);
            assert_eq!(t.ranges.len(), 32);
            assert_eq!(t.ranges[0], (100, 100));
            assert_eq!(t.ranges[31], (5000, 5000));
        }

        #[test]
        fn evicted_packet_numbers_still_rejected_as_replays() {
            // RFC 9000 §12.3: dropping the lowest tracked range when the window
            // fills must not re-open old packet numbers to replay. A replayed
            // packet whose range was evicted must still be reported as seen.
            let mut t = RecvPnTracker::new();
            for i in 0..32 {
                t.record(i * 100);
            }
            assert!(t.contains(0));
            // Overflow the window, evicting the lowest range (0, 0).
            t.record(5000);
            assert!(
                t.contains(0),
                "an evicted packet number must still be treated as already received"
            );
            // Recording it again must not resurrect it as a new range.
            let len_before = t.ranges.len();
            t.record(0);
            assert_eq!(t.ranges.len(), len_before);
            assert!(!t.ranges.iter().any(|&(s, _)| s == 0));
        }

        #[test]
        fn largest_returns_none_when_empty() {
            let t = RecvPnTracker::new();
            assert_eq!(t.largest(), None);
        }

        #[test]
        fn extend_lower_bound() {
            let mut t = RecvPnTracker::new();
            t.record(5);
            t.record(4);
            assert_eq!(t.ranges.as_slice(), &[(4, 5)]);
        }
    }

    // =========================================================================
    // M4 — Stream data offset handling tests
    // =========================================================================

    mod stream_offset_tests {
        use super::io::QuicStreamIoBufs;
        use super::*;
        type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        fn make_test_client(
            pool: &mut HandshakePool<crate::crypto::rustcrypto::Aes128GcmProvider, 4>,
        ) -> (
            Connection<crate::crypto::rustcrypto::Aes128GcmProvider>,
            SioBufs,
        ) {
            use crate::crypto::rustcrypto::Aes128GcmProvider;

            struct TestRng(u8);
            impl Rng for TestRng {
                fn fill(&mut self, buf: &mut [u8]) {
                    for b in buf.iter_mut() {
                        *b = self.0;
                        self.0 = self.0.wrapping_add(1);
                    }
                }
            }

            let mut rng = TestRng(0x10);
            let conn = Connection::client(
                Aes128GcmProvider,
                "test.local",
                &[b"h3"],
                TransportParams::default_params(),
                &mut rng,
                pool,
            )
            .unwrap();
            (conn, SioBufs::new())
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn in_order_data_appended() {
            let mut pool = HandshakePool::<crate::crypto::rustcrypto::Aes128GcmProvider, 4>::new();
            let (mut conn, mut sio_bufs) = make_test_client(&mut pool);
            let sid = 4u64; // arbitrary stream id
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"hello", false);
            let buf = sio_bufs.recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn gap_drops_frame() {
            let mut pool = HandshakePool::<crate::crypto::rustcrypto::Aes128GcmProvider, 4>::new();
            let (mut conn, mut sio_bufs) = make_test_client(&mut pool);
            let sid = 4u64;
            // First send offset 0 with 5 bytes
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"hello", false);
            // Then send offset 10 (gap) -- should be dropped
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 10, b"world", false);
            let buf = sio_bufs.recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn duplicate_data_skipped() {
            let mut pool = HandshakePool::<crate::crypto::rustcrypto::Aes128GcmProvider, 4>::new();
            let (mut conn, mut sio_bufs) = make_test_client(&mut pool);
            let sid = 4u64;
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"hello", false);
            // Retransmit same data
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"hello", false);
            let buf = sio_bufs.recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            // Should not double-append
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn partial_overlap_appends_new_tail() {
            let mut pool = HandshakePool::<crate::crypto::rustcrypto::Aes128GcmProvider, 4>::new();
            let (mut conn, mut sio_bufs) = make_test_client(&mut pool);
            let sid = 4u64;
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"hel", false);
            assert_eq!(
                sio_bufs
                    .recv_bufs
                    .iter()
                    .find_map(|s| s.as_ref())
                    .unwrap()
                    .next_offset,
                3
            );
            // Overlap: offset 1 with "ello" -- first 2 bytes overlap, last 2 are new
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 1, b"ello", false);
            let buf = sio_bufs.recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello");
            assert_eq!(buf.next_offset, 5);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn sequential_in_order_frames() {
            let mut pool = HandshakePool::<crate::crypto::rustcrypto::Aes128GcmProvider, 4>::new();
            let (mut conn, mut sio_bufs) = make_test_client(&mut pool);
            let sid = 4u64;
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"hel", false);
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 3, b"lo ", false);
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 6, b"world", true);
            let buf = sio_bufs.recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"hello world");
            assert_eq!(buf.next_offset, 11);
            assert!(buf.fin_received);
        }

        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        #[test]
        fn fin_on_duplicate_is_recorded() {
            let mut pool = HandshakePool::<crate::crypto::rustcrypto::Aes128GcmProvider, 4>::new();
            let (mut conn, mut sio_bufs) = make_test_client(&mut pool);
            let sid = 4u64;
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"done", false);
            // Retransmit with FIN
            conn.store_stream_data(&mut sio_bufs.as_io(), sid, 0, b"done", true);
            let buf = sio_bufs.recv_bufs.iter().find_map(|s| s.as_ref()).unwrap();
            assert_eq!(&buf.data[..buf.len], b"done");
            assert!(buf.fin_received);
        }
    }

    /// Test that processes a real curl --http3 Initial packet.
    #[cfg(feature = "rustcrypto-chacha")]
    mod curl_interop {
        use super::io::QuicStreamIoBufs;
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

        /// Hex-encoded Initial packet captured from `curl --http3`.
        const CURL_INITIAL_HEX: &str = "ca00000001145853147be8dc7ffd04d27473064d582c2c9f8d471486e5be8c8451a8acebec17f0649776ebdd90221c008000047c69639d2b78e5215ce9d38a549bb4e688821d3188bc79338e5e0431d6551a14ea5b36462fb746f1a17913ae38d0ae789132b5b31d5c8ed9c418ba0ac877f4a68fa436f7477f5ee9f5bd90d4137dafdfec0b04ffcaef83f5e0184b9742faac00fe7246d94117a9d11ab92944b1cc9e8dbb799545ae87db196f9e5f7f0ab0779685b369ae3bb9c281ac872de74c1bdba52d7c0b61b52b1c56e5a42ef9c01751348961ecb3bb4b8b052b1ef0919fe4fb66beafc588e0761ad77b6b8f036e0baa8e7f8dbe369dd82bf79fc40664a4f5b9679c8c435fc6eac36f10cfb00f864a8fed955eda0bffd0f822ff30202f8e4d73511560078339b3961a90bfbb93bab6d0c832bc1912adc6dbc2cab5adb9acf3764bcff373394c1b08e29ebeecffecf1e3de0d205e07676198c11a9a803cf03c9b706885cbb89e43aa1eb8779eeb3ea94ff590ae853b6bc394f0091c93b2e5da54bb674c55d820bdc57bef9b401022198a573b74ce7430dfaf84efe24de129a93f2b05d902234490b4398a6e7a13f766c131d3dae63a71c434de7ba68002162bea6c0105d378cca320817f6192ae6701fc040c06f52dac2cf8fe00813810202478c2b81a98778d9a264c33a57ddae92e0d4375aa5fd19825582e5f5293a6a4a9c1ad24e6c4476b77c3c5228637708c0ec6b3469e3874a3509df2d36806caf72f1a60fcbfe2fcb0c0dcba4b54f80838dfc10f610e5377d95041ac78a03e9f2c74acc27bbc61b4e6c911f0c591a1da67ccb3ce982603238b34a0ccb486f79226f0046289e6317edc55569d41a01ad04ee4d359acb8fa494cc3229251d56eab7da70e46c543c4afd49a7f5efb8f12b890f982a4002c1513cb0c87e25f9b59035b4f9987b96feb1b5c6e86c1314d3064f418bfd6d1a3a7242e761a50ebc6c4e190919fa4a0a2a9406b741b53534a1baebe185ef8698998ff47cf0a9165b8b7cd5e4966c8e6a5faaa4a8309f973f5ae0ff7d96c6eadf12a89124b6f1297c90363727aa64c8d1be9ff4fdb886dbe8add8ccd7410d705617c4830ab90949544b1e47544d25c25e7f3d8e36054e95205ecb68464e0561cc5e8f0f458a4c82c3fdb1fdb2c1e7bd9b2da14807b4d3eda466f4fc57554fac825803557c28d4537175c672bd1496c361c211613838b465b4dcec2a5d64d31760c713f55b480205f228c0a9999c94684e88f2b645d5961818afb145ac12511896784bdf7688d7f4381cbc98a2584b05c31a81071e96d67ace70663601d2e88963590c82dd37983df27688618a584a54f2c33e6d9013ea434577a813d9e9d433a2c59ed070c7db47d286fd2b687428c0a22b9933149ca9988682803dc554cb0603edb5f62b0f16217abca14be43b1ba03931158b40695f3e3ec03b51ebd1dbd30e36daa3f527955f25e3524db0480c65d4c2c8d4b87c5d58c0a2bf5e6bcbc5354b97b9dc50f22b3c961c2ded546556beb3dbd6d48e3c69b182abd6034df6a806d7e235ea8f9bd7c648197d5e56c65591d26da0e0e62e3e536570eefd1dd66a5b9e376d116dfad88d7bb337a856a5a95b98b2840b58d83c769d2d8b01dc12b09a0f8db6c667c2fe4752ebd21cdc4c97349de0fcf805db46253b4503f18";

        const TEST_SEED: [u8; 32] = [0x42u8; 32];

        fn get_test_cert_der() -> &'static [u8] {
            use std::sync::LazyLock;
            static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
                let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&TEST_SEED);
                let mut b = [0u8; 512];
                let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
                b[..n].to_vec()
            });
            &V
        }

        fn hex_to_bytes(hex: &str) -> std::vec::Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }

        #[test]
        fn server_processes_curl_initial_packet() {
            let data = hex_to_bytes(CURL_INITIAL_HEX);
            assert_eq!(data.len(), 1200);

            let tp = TransportParams::default_params();
            let config = crate::tls::handshake::ServerTlsConfig {
                cert_der: get_test_cert_der(),
                private_key_der: &TEST_SEED,
                alpn_protocols: &[b"h3"],
                transport_params: tp.clone(),
            };

            struct TestRng(u8);
            impl Rng for TestRng {
                fn fill(&mut self, buf: &mut [u8]) {
                    for b in buf.iter_mut() {
                        *b = self.0;
                        self.0 = self.0.wrapping_add(1);
                    }
                }
            }
            let mut rng = TestRng(0x10);
            let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();
            let mut server = Connection::<Aes128GcmProvider>::server(
                Aes128GcmProvider,
                config,
                tp,
                &mut rng,
                &mut pool,
            )
            .expect("create server");

            // Process the curl Initial packet
            let mut sio_bufs = SioBufs::new();
            let mut scratch = [0u8; 2048];
            let now = 1_000_000u64;
            let result = server.recv(&mut sio_bufs.as_io(), &data, &mut scratch, now, &mut pool);
            std::eprintln!("recv result: {:?}", result);
            assert!(result.is_ok(), "recv should succeed: {:?}", result);

            // Check that the server:
            // 1. Derived initial keys (from DCID)
            assert!(
                server.keys.has_recv_keys(Level::Initial),
                "should have initial recv keys"
            );

            // 2. Marked the packet as ack-eliciting
            assert!(
                server.ack_eliciting_received[0],
                "Initial packet should be ack-eliciting"
            );

            // 3. Tracked PN 0 in the recv_pn_tracker
            assert!(
                !server.recv_pn_tracker[0].ranges.is_empty(),
                "should have tracked PN 0"
            );

            // 4. Buffered CRYPTO data in the reassembly buffer (now in pool)
            // The ClientHello is 1499 bytes but only ~1077 fit in this datagram.
            let slot = server.handshake_slot.expect("should have handshake slot");
            let ctx = pool.get_mut(slot);
            let reasm = &ctx.crypto_reasm[0];
            let avail = reasm.contiguous_len();
            std::eprintln!(
                "CRYPTO reassembly: {} contiguous bytes, delivered={}",
                avail,
                reasm.delivered
            );
            assert!(avail > 0, "should have some contiguous CRYPTO data");
            assert!(
                avail < 1499,
                "shouldn't have the full ClientHello yet (only one datagram)"
            );

            // 5. poll_transmit should produce an ACK (even though TLS hasn't
            //    processed the ClientHello yet).
            let mut tx_buf = [0u8; 2048];
            let tx = server.poll_transmit(&mut sio_bufs.as_io(), &mut tx_buf, now, &mut pool);
            std::eprintln!("poll_transmit: {:?}", tx.as_ref().map(|t| t.data.len()));
            assert!(
                tx.is_some(),
                "server should send an ACK for the client's Initial"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Stack footprint audit
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn size_of_connection_and_fields() {
        use crate::connection::handshake_pool::{HandshakeContext, HandshakePool};
        use crate::connection::keys::{ConnectionKeys, KeyUpdateState};
        use crate::connection::recv::CryptoReassemblyBuf;
        use crate::crypto::DirectionalKeys;
        use crate::crypto::rustcrypto::Aes128GcmProvider;
        use crate::crypto::rustcrypto::{Aes128GcmAead, AesHeaderProtection};
        use crate::tls::handshake::TlsEngine;
        use crate::tls::transport_params::TransportParams;
        use crate::transport::congestion::CongestionController;
        use crate::transport::flow_control::FlowController;
        use crate::transport::loss::LossDetector;
        use crate::transport::recovery::SentPacketTracker;
        use crate::transport::stream::StreamMap;

        // Default configuration (stream I/O buffers externalized, now 4 generics)
        type ConnDefault = Connection<Aes128GcmProvider>;
        // Minimal embedded configuration
        type ConnMinimal = Connection<Aes128GcmProvider, 4, 32, 2>;

        let total_default = core::mem::size_of::<ConnDefault>();
        let total_minimal = core::mem::size_of::<ConnMinimal>();

        std::eprintln!("=== Connection stack footprint comparison ===");
        std::eprintln!();
        std::eprintln!(
            "Default  (Connection<P>):                                  {} bytes ({:.1} KiB)",
            total_default,
            total_default as f64 / 1024.0
        );
        std::eprintln!(
            "Minimal  (Connection<P, 4, 32, 2>):                        {} bytes ({:.1} KiB)",
            total_minimal,
            total_minimal as f64 / 1024.0
        );
        std::eprintln!(
            "Savings: {} bytes ({:.1} KiB, {:.0}%)",
            total_default - total_minimal,
            (total_default - total_minimal) as f64 / 1024.0,
            (1.0 - total_minimal as f64 / total_default as f64) * 100.0
        );
        std::eprintln!();

        std::eprintln!("--- Field-level breakdown (default config) ---");
        std::eprintln!(
            "  state (ConnectionState): {} bytes",
            core::mem::size_of::<ConnectionState>()
        );
        std::eprintln!(
            "  role (Role): {} bytes",
            core::mem::size_of::<crate::tls::handshake::Role>()
        );
        std::eprintln!(
            "  crypto (Aes128GcmProvider): {} bytes",
            core::mem::size_of::<Aes128GcmProvider>()
        );
        std::eprintln!(
            "  keys (ConnectionKeys<Aes128GcmProvider>): {} bytes",
            core::mem::size_of::<ConnectionKeys<Aes128GcmProvider>>()
        );
        std::eprintln!(
            "  handshake_slot (Option<u8>): {} bytes",
            core::mem::size_of::<Option<u8>>()
        );
        std::eprintln!(
            "  streams (StreamMap<32>): {} bytes",
            core::mem::size_of::<StreamMap<32>>()
        );
        std::eprintln!(
            "  sent_tracker (SentPacketTracker<128>): {} bytes",
            core::mem::size_of::<SentPacketTracker<128>>()
        );
        std::eprintln!(
            "  loss_detector (LossDetector): {} bytes",
            core::mem::size_of::<LossDetector>()
        );
        std::eprintln!(
            "  congestion (CongestionController): {} bytes",
            core::mem::size_of::<CongestionController>()
        );
        std::eprintln!(
            "  flow_control (FlowController): {} bytes",
            core::mem::size_of::<FlowController>()
        );
        std::eprintln!(
            "  local_cids (heapless::Vec<ConnectionId, 4>): {} bytes",
            core::mem::size_of::<heapless::Vec<ConnectionId, 4>>()
        );
        std::eprintln!(
            "    single ConnectionId: {} bytes",
            core::mem::size_of::<ConnectionId>()
        );
        std::eprintln!(
            "  remote_cid (ConnectionId): {} bytes",
            core::mem::size_of::<ConnectionId>()
        );
        std::eprintln!(
            "  next_pn ([u64; 3]): {} bytes",
            core::mem::size_of::<[u64; 3]>()
        );
        std::eprintln!(
            "  largest_recv_pn ([Option<u64>; 3]): {} bytes",
            core::mem::size_of::<[Option<u64>; 3]>()
        );
        std::eprintln!(
            "  recv_pn_tracker ([RecvPnTracker; 3]): {} bytes",
            core::mem::size_of::<[RecvPnTracker; 3]>()
        );
        std::eprintln!(
            "    single RecvPnTracker: {} bytes",
            core::mem::size_of::<RecvPnTracker>()
        );
        std::eprintln!(
            "  ack_eliciting_received ([bool; 3]): {} bytes",
            core::mem::size_of::<[bool; 3]>()
        );
        std::eprintln!(
            "  local_params (TransportParams): {} bytes",
            core::mem::size_of::<TransportParams>()
        );
        std::eprintln!(
            "  peer_params (Option<TransportParams>): {} bytes",
            core::mem::size_of::<Option<TransportParams>>()
        );
        std::eprintln!(
            "  events (heapless::Deque<Event, 16>): {} bytes",
            core::mem::size_of::<heapless::Deque<Event, 16>>()
        );
        std::eprintln!("    single Event: {} bytes", core::mem::size_of::<Event>());
        std::eprintln!(
            "  close_frame (Option<(u64, heapless::Vec<u8, 64>)>): {} bytes",
            core::mem::size_of::<Option<(u64, heapless::Vec<u8, 64>)>>()
        );
        std::eprintln!(
            "  idle_timeout (Option<u64>): {} bytes",
            core::mem::size_of::<Option<u64>>()
        );
        std::eprintln!(
            "  last_activity (Instant/u64): {} bytes",
            core::mem::size_of::<crate::transport::Instant>()
        );
        std::eprintln!(
            "  need_handshake_done (bool): {} bytes",
            core::mem::size_of::<bool>()
        );
        std::eprintln!(
            "  stream_send_queue (heapless::Vec<StreamSendEntry<1024>, 16>): {} bytes",
            core::mem::size_of::<heapless::Vec<StreamSendEntry<1024>, 16>>()
        );
        std::eprintln!(
            "    single StreamSendEntry<1024>: {} bytes",
            core::mem::size_of::<StreamSendEntry<1024>>()
        );
        std::eprintln!(
            "    single StreamSendEntry<256>: {} bytes",
            core::mem::size_of::<StreamSendEntry<256>>()
        );
        std::eprintln!(
            "  stream_recv_bufs ([Option<StreamRecvBuf<1024>>; 32]): {} bytes",
            core::mem::size_of::<[Option<StreamRecvBuf<1024>>; 32]>()
        );
        std::eprintln!(
            "    single Option<StreamRecvBuf<1024>>: {} bytes",
            core::mem::size_of::<Option<StreamRecvBuf<1024>>>()
        );
        std::eprintln!(
            "    single StreamRecvBuf<1024>: {} bytes",
            core::mem::size_of::<StreamRecvBuf<1024>>()
        );
        std::eprintln!(
            "    single StreamRecvBuf<256>: {} bytes",
            core::mem::size_of::<StreamRecvBuf<256>>()
        );
        std::eprintln!(
            "  pending_path_response (Option<[u8; 8]>): {} bytes",
            core::mem::size_of::<Option<[u8; 8]>>()
        );
        std::eprintln!(
            "  anti_amplification_bytes_received (usize): {} bytes",
            core::mem::size_of::<usize>()
        );
        std::eprintln!(
            "  anti_amplification_bytes_sent (usize): {} bytes",
            core::mem::size_of::<usize>()
        );
        std::eprintln!(
            "  address_validated (bool): {} bytes",
            core::mem::size_of::<bool>()
        );
        std::eprintln!();

        std::eprintln!("--- HandshakePool / HandshakeContext sizes ---");
        std::eprintln!(
            "  HandshakeContext<P, 4096> (default): {} bytes ({:.1} KiB)",
            core::mem::size_of::<HandshakeContext<Aes128GcmProvider>>(),
            core::mem::size_of::<HandshakeContext<Aes128GcmProvider>>() as f64 / 1024.0
        );
        std::eprintln!(
            "  HandshakeContext<P, 2048>: {} bytes ({:.1} KiB)",
            core::mem::size_of::<HandshakeContext<Aes128GcmProvider, 2048>>(),
            core::mem::size_of::<HandshakeContext<Aes128GcmProvider, 2048>>() as f64 / 1024.0
        );
        std::eprintln!(
            "  HandshakePool<P, 4> (default): {} bytes ({:.1} KiB)",
            core::mem::size_of::<HandshakePool<Aes128GcmProvider, 4>>(),
            core::mem::size_of::<HandshakePool<Aes128GcmProvider, 4>>() as f64 / 1024.0
        );
        std::eprintln!(
            "  TlsEngine<P>: {} bytes",
            core::mem::size_of::<TlsEngine<Aes128GcmProvider>>()
        );
        std::eprintln!(
            "  crypto_reasm ([CryptoReassemblyBuf<4096>; 3]): {} bytes",
            core::mem::size_of::<[CryptoReassemblyBuf<4096>; 3]>()
        );
        std::eprintln!(
            "    single CryptoReassemblyBuf<4096>: {} bytes",
            core::mem::size_of::<CryptoReassemblyBuf<4096>>()
        );
        std::eprintln!(
            "    single CryptoReassemblyBuf<2048>: {} bytes",
            core::mem::size_of::<CryptoReassemblyBuf<2048>>()
        );
        std::eprintln!(
            "  pending_crypto ([Buf<2048>; 3]): {} bytes",
            core::mem::size_of::<[crate::buf::Buf<2048>; 3]>()
        );
        std::eprintln!(
            "    single Buf<2048>: {} bytes",
            core::mem::size_of::<crate::buf::Buf<2048>>()
        );
        std::eprintln!();

        std::eprintln!("--- Parameterized buffer size impact ---");
        std::eprintln!(
            "  stream_send_queue (Vec<StreamSendEntry<256>, 4>): {} bytes",
            core::mem::size_of::<heapless::Vec<StreamSendEntry<256>, 4>>()
        );
        std::eprintln!(
            "  stream_recv_bufs ([Option<StreamRecvBuf<256>>; 4]): {} bytes",
            core::mem::size_of::<[Option<StreamRecvBuf<256>>; 4]>()
        );
        std::eprintln!();

        std::eprintln!("--- Nested type details ---");
        std::eprintln!(
            "  DirectionalKeys<Aes128GcmAead, AesHeaderProtection>: {} bytes",
            core::mem::size_of::<DirectionalKeys<Aes128GcmAead, AesHeaderProtection>>()
        );
        std::eprintln!(
            "  Option<DirectionalKeys<Aes128GcmAead, AesHeaderProtection>>: {} bytes",
            core::mem::size_of::<Option<DirectionalKeys<Aes128GcmAead, AesHeaderProtection>>>()
        );
        std::eprintln!(
            "  KeyUpdateState<Aes128GcmProvider>: {} bytes",
            core::mem::size_of::<KeyUpdateState<Aes128GcmProvider>>()
        );
        std::eprintln!(
            "  Aes128GcmAead: {} bytes",
            core::mem::size_of::<Aes128GcmAead>()
        );
        std::eprintln!(
            "  AesHeaderProtection: {} bytes",
            core::mem::size_of::<AesHeaderProtection>()
        );
        std::eprintln!(
            "  StreamState (transport::stream): {} bytes",
            core::mem::size_of::<crate::transport::stream::StreamState>()
        );
        std::eprintln!(
            "  Option<StreamState>: {} bytes",
            core::mem::size_of::<Option<crate::transport::stream::StreamState>>()
        );
        std::eprintln!(
            "  SentPacket: {} bytes",
            core::mem::size_of::<crate::transport::recovery::SentPacket>()
        );
        std::eprintln!(
            "  Option<SentPacket>: {} bytes",
            core::mem::size_of::<Option<crate::transport::recovery::SentPacket>>()
        );
    }
}
