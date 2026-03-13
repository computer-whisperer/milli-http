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
    fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error>;

    /// Whether the connection is established (handshake/settings complete).
    fn is_established(&self) -> bool;

    /// Whether the connection is closed.
    fn is_closed(&self) -> bool;

    /// Return the earliest timeout deadline, or `None`.
    fn next_timeout(&self) -> Option<u64>;

    /// Check and handle timeout expiration.
    fn handle_timeout(&mut self, now: u64);

    /// Feed encrypted TCP data into the connection (TLS + HTTP processing).
    ///
    /// Only meaningful for TCP-based connections (Https1, H2Tls).
    /// H3 connections should return `Ok(())` (they use UDP via the manager).
    fn tcp_feed_data(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Pull outgoing encrypted TCP data.
    ///
    /// Only meaningful for TCP-based connections.
    /// H3 connections should return `None`.
    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]>;
}
