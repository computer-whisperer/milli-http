//! Async I/O wrapper for [`ServerManager`].
//!
//! [`ServerRunner`] owns the manager plus socket references and provides a
//! poll-based async interface. Follows the same pattern as pure-logic manager +
//! async event loop using `poll_fn(|cx| { ... poll all sources ... })`.

extern crate alloc;

use alloc::vec::Vec;
use core::task::{Context, Poll};

use crate::connection::HandshakePoolAccess;
use crate::crypto::CryptoProvider;
use crate::transport::{Address, Rng, TcpAccept, TcpStream, UdpSocket};

use super::{ConnId, ServerEvent, ServerManager};

/// Per-connection TCP write state: tracks partially-written data.
struct TcpConnState<S> {
    id: ConnId,
    stream: S,
    /// Buffered data waiting to be written (remainder of a partial write).
    pending_write: Vec<u8>,
    /// Offset into `pending_write` — bytes before this have been sent.
    write_offset: usize,
    /// Peer sent EOF (read returned Ok(0)).
    eof: bool,
}

/// Pending UDP transmit that couldn't be sent due to backpressure.
struct PendingUdpTx<A> {
    data: Vec<u8>,
    addr: A,
}

/// Async I/O wrapper around [`ServerManager`].
///
/// Drives TCP accept, TCP read/write, and UDP recv/send, forwarding
/// everything through the pure-logic manager.
pub struct ServerRunner<
    'a,
    C,
    L,
    U,
    R,
    A,
    const BUF: usize = 18432,
    const CRYPTO_BUF: usize = 4096,
    const MAX_STREAMS: usize = 4,
    const SENT_PER_SPACE: usize = 16,
    const MAX_CIDS: usize = 2,
    const STREAM_BUF: usize = 256,
    const SEND_QUEUE: usize = 4,
> where
    C: CryptoProvider + Clone + 'static,
    C::Hkdf: Default,
    L: TcpAccept,
    U: UdpSocket<Addr = A>,
    R: Rng,
    A: Address,
{
    pub manager:
        ServerManager<C, A, BUF, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE>,
    /// TLS listener. Accepted connections go through the TLS handshake.
    tls_listener: Option<&'a mut L>,
    /// Cleartext listener. Accepted connections start as plaintext HTTP/1.1.
    #[cfg_attr(not(feature = "http1"), allow(dead_code))]
    cleartext_listener: Option<&'a mut L>,
    udp_socket: &'a mut U,
    rng: &'a mut R,
    pool: &'a mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    tcp_conns: Vec<TcpConnState<L::Stream>>,
    pending_udp_tx: Option<PendingUdpTx<A>>,
}

impl<
    'a,
    C,
    L,
    U,
    R,
    A,
    const BUF: usize,
    const CRYPTO_BUF: usize,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
    const STREAM_BUF: usize,
    const SEND_QUEUE: usize,
>
    ServerRunner<
        'a,
        C,
        L,
        U,
        R,
        A,
        BUF,
        CRYPTO_BUF,
        MAX_STREAMS,
        SENT_PER_SPACE,
        MAX_CIDS,
        STREAM_BUF,
        SEND_QUEUE,
    >
where
    C: CryptoProvider + Clone + 'static,
    C::Hkdf: Default,
    L: TcpAccept,
    U: UdpSocket<Addr = A>,
    R: Rng,
    A: Address,
{
    /// Create a new server runner.
    ///
    /// `tls_listener` and `cleartext_listener` are independent and optional:
    /// pass both for standard dual HTTP/HTTPS (e.g. port 80 cleartext + 443
    /// TLS), or just one for single-mode operation. Both feed the same manager
    /// and event stream.
    pub fn new(
        manager: ServerManager<
            C,
            A,
            BUF,
            MAX_STREAMS,
            SENT_PER_SPACE,
            MAX_CIDS,
            STREAM_BUF,
            SEND_QUEUE,
        >,
        tls_listener: Option<&'a mut L>,
        cleartext_listener: Option<&'a mut L>,
        udp_socket: &'a mut U,
        rng: &'a mut R,
        pool: &'a mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Self {
        Self {
            manager,
            tls_listener,
            cleartext_listener,
            udp_socket,
            rng,
            pool,
            tcp_conns: Vec::new(),
            pending_udp_tx: None,
        }
    }

    /// Maximum reads per TCP connection per poll cycle to avoid starvation.
    const MAX_READS_PER_CONN: usize = 4;
    /// Maximum UDP datagrams to process per poll cycle.
    const MAX_UDP_READS: usize = 8;
    /// Maximum pending write buffer per TCP connection. Matches BUF to stay
    /// consistent with TLS record sizes. Once hit, we stop pulling from the
    /// manager until the socket drains.
    const MAX_PENDING_WRITE: usize = BUF;

    /// Poll for the next server event, driving all I/O.
    ///
    /// Registers wakers on all sockets. Returns `Poll::Pending` when no events
    /// are ready — the executor will wake us when any socket has data.
    ///
    /// Each I/O source is bounded per cycle to prevent starvation on
    /// cooperative executors. The runner only schedules a re-poll when there
    /// is buffered output still waiting to be flushed (i.e., actual pending
    /// work), not merely because input was consumed.
    pub fn poll_event(&mut self, cx: &mut Context<'_>, now: u64) -> Poll<ServerEvent> {
        let mut has_pending_output = false;

        // 1. Accept new TCP connections from each listener (at most one per
        //    listener per cycle to avoid starving established connections).
        //    The TLS listener's connections handshake; the cleartext listener's
        //    start as plaintext HTTP/1.1. Both feed the same manager.
        if let Some(listener) = self.tls_listener.as_mut() {
            if let Poll::Ready(Ok(stream)) = listener.poll_accept(cx) {
                if let Ok(id) = self.manager.accept_tcp(self.rng, now) {
                    self.tcp_conns.push(TcpConnState {
                        id,
                        stream,
                        pending_write: Vec::new(),
                        write_offset: 0,
                        eof: false,
                    });
                }
            }
        }
        #[cfg(feature = "http1")]
        if let Some(listener) = self.cleartext_listener.as_mut() {
            if let Poll::Ready(Ok(stream)) = listener.poll_accept(cx) {
                if let Ok(id) = self.manager.accept_tcp_cleartext(now) {
                    self.tcp_conns.push(TcpConnState {
                        id,
                        stream,
                        pending_write: Vec::new(),
                        write_offset: 0,
                        eof: false,
                    });
                }
            }
        }

        // 2. Read existing TCP streams + handle EOF (bounded per connection).
        //    If we exhaust the read budget, self-wake to ensure we come back
        //    (the last poll_read returned Ready, so no waker was registered).
        let mut tcp_buf = [0u8; 1500];
        for conn in &mut self.tcp_conns {
            if conn.eof {
                continue;
            }
            let mut reads_done = 0u32;
            for _ in 0..Self::MAX_READS_PER_CONN {
                match conn.stream.poll_read(cx, &mut tcp_buf) {
                    Poll::Ready(Ok(0)) => {
                        conn.eof = true;
                        self.manager.tcp_eof(conn.id);
                        break;
                    }
                    Poll::Ready(Ok(n)) => {
                        reads_done += 1;
                        if self.manager.tcp_feed(conn.id, &tcp_buf[..n], now).is_err() {
                            conn.eof = true;
                            break;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        conn.eof = true;
                        self.manager.tcp_eof(conn.id);
                        break;
                    }
                    Poll::Pending => break,
                }
            }
            if reads_done as usize >= Self::MAX_READS_PER_CONN {
                has_pending_output = true; // budget exhausted, may have more data
            }
        }

        // 3. Write pending TCP output back to streams.
        let mut out_buf = [0u8; 1500];
        for conn in &mut self.tcp_conns {
            // 3a. Flush pending partial write from previous poll cycle.
            while conn.write_offset < conn.pending_write.len() {
                match conn
                    .stream
                    .poll_write(cx, &conn.pending_write[conn.write_offset..])
                {
                    Poll::Ready(Ok(n)) => {
                        conn.write_offset += n;
                    }
                    Poll::Ready(Err(_)) => {
                        conn.eof = true;
                        self.manager.tcp_eof(conn.id);
                        break;
                    }
                    Poll::Pending => break,
                }
            }
            if conn.write_offset >= conn.pending_write.len() {
                conn.pending_write.clear();
                conn.write_offset = 0;
            } else {
                has_pending_output = true;
                continue;
            }

            // 3b. Pull new output from manager and write directly.
            //     Stop if pending buffer has reached the cap.
            loop {
                let pending_remaining = conn.pending_write.len() - conn.write_offset;
                if pending_remaining >= Self::MAX_PENDING_WRITE {
                    has_pending_output = true;
                    break;
                }
                if let Some(data) = self.manager.tcp_poll_output(conn.id, &mut out_buf) {
                    let data_len = data.len();
                    let mut written = 0;
                    while written < data_len {
                        match conn.stream.poll_write(cx, &data[written..]) {
                            Poll::Ready(Ok(n)) => {
                                written += n;
                            }
                            Poll::Ready(Err(_)) => {
                                conn.eof = true;
                                self.manager.tcp_eof(conn.id);
                                break;
                            }
                            Poll::Pending => break,
                        }
                    }
                    if written < data_len {
                        conn.pending_write.extend_from_slice(&data[written..]);
                        conn.write_offset = 0;
                        has_pending_output = true;
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        // 4. Read UDP datagrams (bounded).
        //    If budget exhausted, self-wake to avoid missed waker.
        let mut udp_buf = [0u8; 1500];
        let mut udp_reads_done = 0u32;
        for _ in 0..Self::MAX_UDP_READS {
            match self.udp_socket.poll_recv_from(cx, &mut udp_buf) {
                Poll::Ready(Ok((n, addr))) => {
                    udp_reads_done += 1;
                    let _ = self.manager.udp_feed::<CRYPTO_BUF>(
                        &udp_buf[..n],
                        addr,
                        now,
                        self.rng,
                        self.pool,
                    );
                }
                _ => break,
            }
        }
        if udp_reads_done as usize >= Self::MAX_UDP_READS {
            has_pending_output = true; // budget exhausted, may have more datagrams
        }

        // 5. Write pending UDP transmits.
        if let Some(pending) = &self.pending_udp_tx {
            match self
                .udp_socket
                .poll_send_to(cx, &pending.data, &pending.addr)
            {
                Poll::Ready(Ok(())) => {
                    self.pending_udp_tx = None;
                }
                Poll::Ready(Err(_)) => {
                    self.pending_udp_tx = None;
                }
                Poll::Pending => {
                    has_pending_output = true;
                }
            }
        }
        if self.pending_udp_tx.is_none() {
            let mut tx_buf = [0u8; 1500];
            loop {
                if let Some((addr, len)) =
                    self.manager
                        .udp_poll_transmit::<CRYPTO_BUF>(&mut tx_buf, now, self.pool)
                {
                    match self.udp_socket.poll_send_to(cx, &tx_buf[..len], &addr) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_)) => {}
                        Poll::Pending => {
                            self.pending_udp_tx = Some(PendingUdpTx {
                                data: tx_buf[..len].to_vec(),
                                addr,
                            });
                            has_pending_output = true;
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        }

        // 6. Handle timeouts
        self.manager.handle_timeouts(now);

        // 7. Drain manager events
        let mut scratch = [0u8; 2048];
        if let Some(event) = self.manager.poll_event(&mut scratch) {
            if let ServerEvent::Closed(id) = &event {
                self.tcp_conns.retain(|c| c.id != *id);
            }
            return Poll::Ready(event);
        }

        // 8. Only schedule a re-poll if there is genuinely buffered output
        //    waiting to be flushed. Input-side progress does not warrant a
        //    self-wake — the socket wakers will handle that.
        if has_pending_output {
            cx.waker().wake_by_ref();
        }

        Poll::Pending
    }

    /// Return the earliest timeout deadline.
    pub fn next_timeout(&self) -> Option<u64> {
        self.manager.next_timeout()
    }
}
