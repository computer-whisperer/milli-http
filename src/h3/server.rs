//! HTTP/3 server API.
//!
//! Wraps a QUIC [`Connection`] as an HTTP/3 server capable of receiving
//! requests and sending responses.

use crate::Instant;
use crate::connection::{Connection, HandshakePoolAccess, Transmit};
use crate::crypto::CryptoProvider;
use crate::error::Error;

use super::connection::{H3Connection, H3Event};

// ---------------------------------------------------------------------------
// H3Server
// ---------------------------------------------------------------------------

/// An HTTP/3 server built on top of a QUIC connection.
pub struct H3Server<
    C: CryptoProvider,
    const MAX_STREAMS: usize = 32,
    const SENT_PER_SPACE: usize = 128,
    const MAX_CIDS: usize = 4,
    const STREAM_BUF: usize = 1024,
    const SEND_QUEUE: usize = 16,
    const H3_HDR_BUF: usize = 512,
    const H3_DATA_BUF: usize = 1024,
> {
    inner: H3Connection<
        C,
        MAX_STREAMS,
        SENT_PER_SPACE,
        MAX_CIDS,
        STREAM_BUF,
        SEND_QUEUE,
        H3_HDR_BUF,
        H3_DATA_BUF,
    >,
}

impl<
    C: CryptoProvider,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
    const STREAM_BUF: usize,
    const SEND_QUEUE: usize,
    const H3_HDR_BUF: usize,
    const H3_DATA_BUF: usize,
>
    H3Server<
        C,
        MAX_STREAMS,
        SENT_PER_SPACE,
        MAX_CIDS,
        STREAM_BUF,
        SEND_QUEUE,
        H3_HDR_BUF,
        H3_DATA_BUF,
    >
where
    C::Hkdf: Default,
{
    /// Wrap a QUIC connection as an HTTP/3 server.
    pub fn new(quic: Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>) -> Self {
        Self {
            inner: H3Connection::new(quic),
        }
    }

    /// Poll for HTTP/3 events.
    ///
    /// Before polling, this processes any pending QUIC events.
    /// `scratch` is a caller-provided buffer for reading stream data,
    /// avoiding internal stack allocations. Should be at least MTU-sized.
    pub fn poll_event(&mut self, scratch: &mut [u8]) -> Option<H3Event> {
        // Process QUIC events first (server is_server=true).
        let _ = self.inner.process_quic_events(true, scratch);
        self.inner.poll_event()
    }

    /// Read request headers for a stream (after receiving `H3Event::Headers`).
    ///
    /// Calls `emit(name, value)` for each decoded header.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read request body data from a stream.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.inner.recv_body(stream_id, buf)
    }

    /// Send response headers on a request stream.
    ///
    /// Encodes the `:status` pseudo-header plus any additional headers.
    pub fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        // 1 pseudo-header + up to 19 user headers = 20 max
        if 1 + headers.len() > 20 {
            return Err(Error::TooManyHeaders);
        }

        // Format the status as a short string.
        let status_str = crate::http::StatusCode(status).to_bytes();

        // Build the full header list: :status pseudo-header first, then extras.
        let mut all_headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = all_headers.push((b":status", &status_str[..]));

        for &(name, value) in headers {
            let _ = all_headers.push((name, value));
        }

        self.inner.send_headers(stream_id, &all_headers, end_stream)
    }

    /// Send response body data.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner.send_data(stream_id, data, end_stream)
    }

    /// Whether the QUIC handshake is complete and the connection is established.
    pub fn is_established(&self) -> bool {
        self.inner.quic.is_established()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.quic.is_closed()
    }

    /// Initiate connection close.
    pub fn close(&mut self, error_code: u64, reason: &[u8]) {
        self.inner.quic.close(error_code, reason);
    }

    // ------------------------------------------------------------------
    // QUIC connection delegates
    // ------------------------------------------------------------------

    /// Process an incoming UDP datagram.
    ///
    /// `scratch` is a caller-provided mutable buffer used for in-place
    /// decryption, avoiding internal stack allocations. It must be at
    /// least as large as the biggest packet in the datagram (typically
    /// MTU-sized, e.g. 1500 bytes).
    pub fn recv<const CRYPTO_BUF: usize>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        now: Instant,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        let mut sio = self.inner.sio_bufs.as_io();
        self.inner.quic.recv(&mut sio, datagram, scratch, now, pool)
    }

    /// Build the next outgoing UDP datagram.
    pub fn poll_transmit<'a, const CRYPTO_BUF: usize>(
        &mut self,
        buf: &'a mut [u8],
        now: Instant,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Option<Transmit<'a>> {
        let mut sio = self.inner.sio_bufs.as_io();
        self.inner.quic.poll_transmit(&mut sio, buf, now, pool)
    }

    /// Get the next timer deadline.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.inner.quic.next_timeout()
    }

    /// Handle a timer expiration.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.inner.quic.handle_timeout(now);
    }

    /// Force-release the handshake pool slot if one is held.
    ///
    /// Called by the connection manager when a new connection fails after
    /// `Connection::server()` claimed a slot (e.g. malformed initial datagram).
    /// Without this, the slot leaks since `Connection` has no `Drop` impl.
    pub(crate) fn release_handshake_slot<const CRYPTO_BUF: usize>(
        &mut self,
        pool: &mut dyn HandshakePoolAccess<C, CRYPTO_BUF>,
    ) {
        if let Some(slot) = self.inner.quic.handshake_slot.take() {
            pool.release(slot);
        }
    }
}

pub(crate) fn map_h3_event(ev: H3Event) -> crate::http::server_conn::HttpEvent {
    use crate::http::server_conn::HttpEvent;
    match ev {
        H3Event::Connected => HttpEvent::Connected,
        H3Event::Headers(s) => HttpEvent::Headers(s),
        H3Event::Data(s) => HttpEvent::Data(s),
        H3Event::Finished(s) => HttpEvent::Finished(s),
        H3Event::GoAway(_) => HttpEvent::GoAway { error_code: 0 },
        H3Event::StreamReset {
            stream_id,
            error_code,
        } => HttpEvent::StreamReset {
            stream_id,
            error_code,
        },
        H3Event::ConnectionClose { error_code } => HttpEvent::GoAway { error_code },
    }
}

impl<
    C: CryptoProvider,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
    const STREAM_BUF: usize,
    const SEND_QUEUE: usize,
    const H3_HDR_BUF: usize,
    const H3_DATA_BUF: usize,
> crate::http::server_conn::HttpServerConn
    for H3Server<
        C,
        MAX_STREAMS,
        SENT_PER_SPACE,
        MAX_CIDS,
        STREAM_BUF,
        SEND_QUEUE,
        H3_HDR_BUF,
        H3_DATA_BUF,
    >
where
    C::Hkdf: Default,
{
    fn poll_event(&mut self, scratch: &mut [u8]) -> Option<crate::http::server_conn::HttpEvent> {
        H3Server::poll_event(self, scratch).map(map_h3_event)
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        H3Server::recv_headers(self, stream_id, emit)
    }

    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        H3Server::recv_body(self, stream_id, buf)
    }

    fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        H3Server::send_response(self, stream_id, status, headers, end_stream)
    }

    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        H3Server::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        H3Server::is_established(self)
    }

    fn is_closed(&self) -> bool {
        H3Server::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        H3Server::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        H3Server::handle_timeout(self, now);
    }

    fn tcp_feed_data(&mut self, _data: &[u8]) -> Result<(), Error> {
        Ok(()) // H3 uses UDP, not TCP
    }

    fn tcp_poll_output<'a>(&mut self, _buf: &'a mut [u8]) -> Option<&'a [u8]> {
        None // H3 uses UDP, not TCP
    }
}
