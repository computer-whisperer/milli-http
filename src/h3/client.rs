//! HTTP/3 client API.
//!
//! Wraps a QUIC [`Connection`] as an HTTP/3 client capable of sending requests
//! and receiving responses.

use crate::Instant;
use crate::connection::{Connection, HandshakePoolAccess, Transmit};
use crate::crypto::CryptoProvider;
use crate::error::Error;

use super::connection::{H3Connection, H3Event};

// ---------------------------------------------------------------------------
// H3Client
// ---------------------------------------------------------------------------

/// An HTTP/3 client built on top of a QUIC connection.
pub struct H3Client<
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
    H3Client<
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
    /// Wrap a QUIC connection as an HTTP/3 client.
    pub fn new(quic: Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>) -> Self {
        Self {
            inner: H3Connection::new(quic),
        }
    }

    /// Send an HTTP request. Returns the request stream ID.
    ///
    /// Encodes pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`)
    /// plus any additional headers using QPACK, wraps in a HEADERS frame, and
    /// sends on a new bidirectional stream.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        // 4 pseudo-headers + up to 16 user headers = 20 max
        if 4 + headers.len() > 20 {
            return Err(Error::TooManyHeaders);
        }

        // Open a new bidirectional request stream.
        let stream_id = self.inner.quic.open_stream()?;

        // Build the full header list: pseudo-headers first, then regular headers.
        // We need to combine them into a single slice for QPACK encoding.
        let mut all_headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = all_headers.push((b":method", method.as_bytes()));
        let _ = all_headers.push((b":scheme", b"https"));
        let _ = all_headers.push((b":authority", authority.as_bytes()));
        let _ = all_headers.push((b":path", path.as_bytes()));

        for &(name, value) in headers {
            let _ = all_headers.push((name, value));
        }

        self.inner
            .send_headers(stream_id, &all_headers, end_stream)?;

        // Track this as a request stream.
        let _ = self
            .inner
            .request_streams
            .push(super::connection::RequestStreamState::new(stream_id));

        Ok(stream_id)
    }

    /// Send request body data on a stream.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner.send_data(stream_id, data, end_stream)
    }

    /// Poll for HTTP/3 events.
    ///
    /// Before polling, this processes any pending QUIC events.
    /// `scratch` is a caller-provided buffer for reading stream data,
    /// avoiding internal stack allocations. Should be at least MTU-sized.
    pub fn poll_event(&mut self, scratch: &mut [u8]) -> Option<H3Event> {
        // Process QUIC events first (client is_server=false).
        let _ = self.inner.process_quic_events(false, scratch);
        self.inner.poll_event()
    }

    /// Read response headers for a stream (after receiving `H3Event::Headers`).
    ///
    /// Calls `emit(name, value)` for each decoded header.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read response body data from a stream.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.inner.recv_body(stream_id, buf)
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
    for H3Client<
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
        H3Client::poll_event(self, scratch).map(super::server::map_h3_event)
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), crate::error::Error> {
        H3Client::recv_headers(self, stream_id, emit)
    }

    fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), crate::error::Error> {
        H3Client::recv_body(self, stream_id, buf)
    }

    fn send_response(
        &mut self,
        _stream_id: u64,
        _status: u16,
        _headers: &[(&[u8], &[u8])],
        _end_stream: bool,
    ) -> Result<(), crate::error::Error> {
        Err(crate::error::Error::InvalidState)
    }

    fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, crate::error::Error> {
        H3Client::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        H3Client::is_established(self)
    }

    fn is_closed(&self) -> bool {
        H3Client::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        H3Client::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        H3Client::handle_timeout(self, now);
    }

    fn tcp_feed_data(&mut self, _data: &[u8]) -> Result<(), crate::error::Error> {
        Ok(()) // H3 uses UDP, not TCP
    }

    fn tcp_poll_output<'a>(&mut self, _buf: &'a mut [u8]) -> Option<&'a [u8]> {
        None // H3 uses UDP, not TCP
    }
}
