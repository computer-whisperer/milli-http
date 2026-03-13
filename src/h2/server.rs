//! HTTP/2 server wrapper.

use super::connection::{H2Connection, H2Event};
use super::io::H2IoBufs;
use crate::error::Error;

/// HTTP/2 server — owns both the connection state and I/O buffers.
pub struct H2Server<
    const MAX_STREAMS: usize = 8,
    const BUF: usize = 16384,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    inner: H2Connection<MAX_STREAMS, HDRBUF, DATABUF>,
    io: H2IoBufs<BUF>,
}

impl<const MAX_STREAMS: usize, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    H2Server<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    /// Create a new HTTP/2 server connection.
    pub fn new() -> Self {
        Self {
            inner: H2Connection::new_server(),
            io: H2IoBufs::new(),
        }
    }

    /// Feed received TCP data.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.feed_data(&mut self.io.as_io(), data)
    }

    /// Pull outgoing data to send on TCP.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        self.inner.poll_output(&mut self.io.as_io(), buf)
    }

    /// Poll for events.
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.inner.poll_event()
    }

    /// Read request headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read request body.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.inner.recv_body(&mut self.io.as_io(), stream_id, buf)
    }

    /// Send response headers.
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
        let status_str = crate::http::StatusCode(status).to_bytes();
        let mut all_headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = all_headers.push((b":status", &status_str[..]));
        for &(name, value) in headers {
            let _ = all_headers.push((name, value));
        }
        self.inner
            .send_headers(&mut self.io.as_io(), stream_id, &all_headers, end_stream)
    }

    /// Send response body.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner
            .send_data(&mut self.io.as_io(), stream_id, data, end_stream)
    }

    /// Send GOAWAY.
    pub fn send_goaway(&mut self, error_code: u32) -> Result<(), Error> {
        self.inner.send_goaway(&mut self.io.as_io(), error_code)
    }

    /// Configure timeouts. `now` is the current timestamp in microseconds.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.inner.set_timeouts(config, now);
    }

    /// Return the earliest deadline (in µs) at which `handle_timeout` should be called.
    pub fn next_timeout(&self) -> Option<u64> {
        self.inner.next_timeout()
    }

    /// Check timeouts and emit events if they fire.
    pub fn handle_timeout(&mut self, now: u64) {
        self.inner.handle_timeout(&mut self.io.as_io(), now);
    }

    /// Feed data with timestamp tracking.
    pub fn feed_data_timed(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        self.inner.feed_data_timed(&mut self.io.as_io(), data, now)
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Whether the SETTINGS exchange is complete.
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }
}

impl<const MAX_STREAMS: usize, const BUF: usize, const HDRBUF: usize, const DATABUF: usize> Default
    for H2Server<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_creation() {
        let _server = H2Server::<16, 4096>::new();
    }

    #[test]
    fn server_max_headers_succeeds() {
        let mut server = H2Server::<16, 16384>::new();
        let hdrs: [(&[u8], &[u8]); 19] = [
            (b"h1", b"v"),
            (b"h2", b"v"),
            (b"h3", b"v"),
            (b"h4", b"v"),
            (b"h5", b"v"),
            (b"h6", b"v"),
            (b"h7", b"v"),
            (b"h8", b"v"),
            (b"h9", b"v"),
            (b"h10", b"v"),
            (b"h11", b"v"),
            (b"h12", b"v"),
            (b"h13", b"v"),
            (b"h14", b"v"),
            (b"h15", b"v"),
            (b"h16", b"v"),
            (b"h17", b"v"),
            (b"h18", b"v"),
            (b"h19", b"v"),
        ];
        let result = server.send_response(1, 200, &hdrs, true);
        assert_ne!(result, Err(crate::error::Error::TooManyHeaders));
    }

    #[test]
    fn server_too_many_headers() {
        let mut server = H2Server::<16, 16384>::new();
        let hdrs: [(&[u8], &[u8]); 20] = [
            (b"h1", b"v"),
            (b"h2", b"v"),
            (b"h3", b"v"),
            (b"h4", b"v"),
            (b"h5", b"v"),
            (b"h6", b"v"),
            (b"h7", b"v"),
            (b"h8", b"v"),
            (b"h9", b"v"),
            (b"h10", b"v"),
            (b"h11", b"v"),
            (b"h12", b"v"),
            (b"h13", b"v"),
            (b"h14", b"v"),
            (b"h15", b"v"),
            (b"h16", b"v"),
            (b"h17", b"v"),
            (b"h18", b"v"),
            (b"h19", b"v"),
            (b"h20", b"v"),
        ];
        let result = server.send_response(1, 200, &hdrs, true);
        assert_eq!(result, Err(crate::error::Error::TooManyHeaders));
    }

    #[test]
    fn server_generates_settings() {
        let mut server = H2Server::<16, 4096>::new();
        let mut buf = [0u8; 4096];
        let output = server.poll_output(&mut buf);
        assert!(output.is_some());
    }
}
