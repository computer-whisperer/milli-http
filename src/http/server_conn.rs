//! Unified HTTP server connection trait.
//!
//! [`HttpServerConn`] provides a protocol-agnostic interface over HTTP/1.1,
//! HTTP/2, and HTTP/3 server connections. This enables the connection manager
//! to handle all protocols through a single event loop.

use crate::error::Error;

/// Unified event from any HTTP protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpEvent {
    /// Connection/settings exchange complete.
    Connected,
    /// Headers received on a stream.
    Headers(u64),
    /// Body data available on a stream.
    Data(u64),
    /// Stream finished (FIN / END_STREAM received).
    Finished(u64),
    /// Peer reset a stream.
    StreamReset { stream_id: u64, error_code: u64 },
    /// Peer sent GOAWAY or CONNECTION_CLOSE.
    GoAway { error_code: u64 },
    /// A timeout fired.
    Timeout,
}

/// Object-safe trait for HTTP server connections.
///
/// Covers HTTP application-layer methods only. Transport I/O (feed_data,
/// poll_output, recv, poll_transmit) differs between TCP and UDP and is
/// handled by the connection manager.
pub trait HttpServerConn {
    /// Poll for the next HTTP event.
    ///
    /// `scratch` is a caller-provided buffer for temporary stream reads,
    /// avoiding internal stack allocations. Only used by H3 connections;
    /// TCP-based protocols may ignore it.
    fn poll_event(&mut self, scratch: &mut [u8]) -> Option<HttpEvent>;

    /// Read decoded headers for a stream, calling `emit(name, value)` for each.
    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error>;

    /// Read body data from a stream. Returns `(bytes_read, fin)`.
    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error>;

    /// Send response headers on a stream.
    fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error>;

    /// Send body data on a stream. Returns bytes written.
    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error>;

    /// Whether the connection is established (handshake/settings complete).
    fn is_established(&self) -> bool;

    /// Whether the connection is closed.
    fn is_closed(&self) -> bool;

    /// Stop receiving a stream's request body: the application will not (or
    /// no longer) read it. For HTTP/2 this discards buffered/in-flight body
    /// data, restores flow-control credit, and tells the peer to stop
    /// sending (RST_STREAM with `error_code`: `0` = NO_ERROR when rejecting
    /// after a complete response per RFC 9113 §8.1, `0x8` = CANCEL
    /// otherwise). Required when responding without consuming the body —
    /// otherwise the unread body stalls the connection behind receive
    /// backpressure (see [`recv_blocked`](Self::recv_blocked)) until the
    /// idle timeout reaps it.
    ///
    /// Default `Err(InvalidState)`: protocols without per-stream
    /// cancellation (HTTP/1.1) don't support it — close the connection
    /// instead.
    fn discard_body(&mut self, _stream_id: u64, _error_code: u32) -> Result<(), Error> {
        Err(Error::InvalidState)
    }

    /// Configure HTTP-level timeouts (idle / header). `now` is the current
    /// timestamp in microseconds. Called by the connection manager when the
    /// connection becomes established.
    ///
    /// Default no-op: H3 connections handle timeouts at the QUIC layer.
    fn set_timeouts(&mut self, _config: crate::http::TimeoutConfig, _now: u64) {}

    /// Return the earliest timeout deadline, or `None`.
    fn next_timeout(&self) -> Option<u64>;

    /// Check and handle timeout expiration.
    fn handle_timeout(&mut self, now: u64);

    /// Feed encrypted TCP data into the connection (TLS + HTTP processing).
    /// `now` (microseconds) tracks receive activity for the idle timeout;
    /// only non-empty feeds count as activity.
    ///
    /// Only meaningful for TCP-based connections (Https1, H2Tls).
    /// H3 connections should return `Ok(())` (they use UDP via the manager).
    fn tcp_feed_data(&mut self, data: &[u8], now: u64) -> Result<(), Error>;

    /// Pull outgoing encrypted TCP data.
    ///
    /// Only meaningful for TCP-based connections.
    /// H3 connections should return `None`.
    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]>;

    /// Whether the connection is holding undelivered receive data behind a
    /// full application buffer — i.e. the runner should stop reading more TCP
    /// for it (apply TCP-window backpressure) and instead re-drive processing
    /// (feed an empty slice) so the consumer can drain and the pump resumes.
    ///
    /// Default `false`: connections without internal receive backpressure
    /// (e.g. HTTP/1.1, where the socket RX buffer is the backpressure point)
    /// are always read.
    fn recv_blocked(&self) -> bool {
        false
    }

    /// Reclaim the `'static` I/O buffer kit backing this connection, if it was
    /// built from one (see [`TlsParts::new_server_in`]). Called once on
    /// teardown so the manager can return the `.bss`-backed buffers to its free
    /// pool for the next connection. Returns `None` for heap-backed or
    /// non-TLS (e.g. H3/UDP) connections — they own no static kit.
    ///
    /// [`TlsParts::new_server_in`]: crate::tcp_tls::TlsParts::new_server_in
    #[cfg(all(feature = "tcp-tls", feature = "alloc"))]
    fn reclaim_buffers(&mut self) -> Option<crate::tcp_tls::TlsBufKit> {
        None
    }
}
