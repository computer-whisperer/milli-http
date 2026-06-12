//! HTTP/1.1 server wrapper.

use super::connection::{Http1Connection, Http1Event};
use super::io::Http1IoBufs;
use crate::error::Error;

/// HTTP/1.1 server — owns both the connection state and I/O buffers.
pub struct Http1Server<
    const BUF: usize = 8192,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    inner: Http1Connection<HDRBUF, DATABUF>,
    io: Http1IoBufs<BUF>,
}

impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Http1Server<BUF, HDRBUF, DATABUF>
{
    /// Create a new HTTP/1.1 server connection.
    pub fn new() -> Self {
        Self {
            inner: Http1Connection::new_server(),
            io: Http1IoBufs::new(),
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
    pub fn poll_event(&mut self) -> Option<Http1Event> {
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
        self.inner.recv_body(stream_id, buf)
    }

    /// Send response headers.
    ///
    /// Encodes `HTTP/1.1 {status} {reason}\r\n` + headers + `\r\n`.
    /// If `end_stream` is true, no body will follow.
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

    /// Send response body data.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner
            .send_data(&mut self.io.as_io(), stream_id, data, end_stream)
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
        self.inner.handle_timeout(now);
    }

    /// Feed data with timestamp tracking.
    pub fn feed_data_timed(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        self.inner.feed_data_timed(&mut self.io.as_io(), data, now)
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Whether the connection is usable.
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }
}

impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize> Default
    for Http1Server<BUF, HDRBUF, DATABUF>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Cleartext HTTP/1.1 over a plain TCP byte stream.
///
/// This lets `ServerManager`/`ServerRunner` drive plaintext HTTP/1.1 through the
/// same unified event loop as the TLS-wrapped [`Https1Server`](crate::https1)
/// — `tcp_feed_data`/`tcp_poll_output` operate directly on cleartext bytes (no
/// TLS layer). Selected via
/// [`ServerManager::accept_tcp_cleartext`](crate::server::ServerManager::accept_tcp_cleartext).
impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    crate::http::server_conn::HttpServerConn for Http1Server<BUF, HDRBUF, DATABUF>
{
    fn poll_event(&mut self, _scratch: &mut [u8]) -> Option<crate::http::server_conn::HttpEvent> {
        use crate::http::server_conn::HttpEvent;
        self.poll_event().map(|ev| match ev {
            Http1Event::Connected => HttpEvent::Connected,
            Http1Event::Headers(s) => HttpEvent::Headers(s),
            Http1Event::Data(s) => HttpEvent::Data(s),
            Http1Event::Finished(s) => HttpEvent::Finished(s),
            Http1Event::Timeout => HttpEvent::Timeout,
        })
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        Http1Server::recv_headers(self, stream_id, emit)
    }

    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        Http1Server::recv_body(self, stream_id, buf)
    }

    fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        Http1Server::send_response(self, stream_id, status, headers, end_stream)
    }

    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        Http1Server::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        Http1Server::is_established(self)
    }

    fn is_closed(&self) -> bool {
        Http1Server::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        Http1Server::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        Http1Server::handle_timeout(self, now);
    }

    fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        Http1Server::set_timeouts(self, config, now);
    }

    fn tcp_feed_data(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        Http1Server::feed_data_timed(self, data, now)
    }

    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        Http1Server::poll_output(self, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_creation() {
        let _server = Http1Server::<4096>::new();
    }

    #[test]
    fn server_max_headers_succeeds() {
        let mut server = Http1Server::<8192, 1024, 1024>::new();
        server
            .feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        while server.poll_event().is_some() {}
        server.recv_headers(1, |_, _| {}).unwrap();
        // 1 pseudo + 19 user = 20, at the limit
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
        assert!(result.is_ok());
    }

    #[test]
    fn server_too_many_headers() {
        let mut server = Http1Server::<8192, 1024, 1024>::new();
        server
            .feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        while server.poll_event().is_some() {}
        server.recv_headers(1, |_, _| {}).unwrap();
        // 1 pseudo + 20 user = 21, over the limit
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
    fn server_handles_request() {
        let mut server = Http1Server::<4096, 1024, 1024>::new();
        server
            .feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        assert!(matches!(server.poll_event(), Some(Http1Event::Connected)));
        let event = server.poll_event().unwrap();
        assert!(matches!(event, Http1Event::Headers(1)));
    }

    #[test]
    fn server_sends_response() {
        let mut server = Http1Server::<4096, 1024, 1024>::new();
        server
            .feed_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();

        // Drain events
        while server.poll_event().is_some() {}
        server.recv_headers(1, |_, _| {}).unwrap();

        server
            .send_response(1, 200, &[(b"content-length", b"5")], false)
            .unwrap();
        server.send_body(1, b"hello", true).unwrap();

        let mut buf = [0u8; 4096];
        let data = server.poll_output(&mut buf).unwrap();
        let s = core::str::from_utf8(data).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("content-length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }
}
