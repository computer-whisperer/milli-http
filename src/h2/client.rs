//! HTTP/2 client wrapper.

use super::connection::{H2Connection, H2Event};
use super::io::H2IoBufs;
use crate::error::Error;

/// HTTP/2 client — owns both the connection state and I/O buffers.
pub struct H2Client<
    const MAX_STREAMS: usize = 8,
    const BUF: usize = 16384,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    inner: H2Connection<MAX_STREAMS, HDRBUF, DATABUF>,
    io: H2IoBufs<BUF>,
}

impl<const MAX_STREAMS: usize, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    H2Client<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    /// Create a new HTTP/2 client connection.
    pub fn new() -> Self {
        Self {
            inner: H2Connection::new_client(),
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

    /// Send a request. Returns the stream ID.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        extra_headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        // 4 pseudo-headers + up to 16 user headers = 20 max
        if 4 + extra_headers.len() > 20 {
            return Err(Error::TooManyHeaders);
        }
        let mut headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = headers.push((b":method", method.as_bytes()));
        let _ = headers.push((b":path", path.as_bytes()));
        let _ = headers.push((b":scheme", b"https"));
        let _ = headers.push((b":authority", authority.as_bytes()));
        for &(name, value) in extra_headers {
            let _ = headers.push((name, value));
        }
        self.inner
            .open_stream(&mut self.io.as_io(), &headers, end_stream)
    }

    /// Send body data on a stream.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        self.inner
            .send_data(&mut self.io.as_io(), stream_id, data, end_stream)
    }

    /// Read response headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.inner.recv_headers(stream_id, emit)
    }

    /// Read response body.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.inner.recv_body(&mut self.io.as_io(), stream_id, buf)
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
    for H2Client<MAX_STREAMS, BUF, HDRBUF, DATABUF>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::connection::CONNECTION_PREFACE;
    use crate::h2::server::H2Server;

    #[test]
    fn client_creation() {
        let _client = H2Client::<16, 4096>::new();
    }

    #[test]
    fn client_sends_preface() {
        let mut client = H2Client::<16, 4096>::new();
        let mut buf = [0u8; 4096];
        let output = client.poll_output(&mut buf).unwrap();
        assert!(output.starts_with(CONNECTION_PREFACE));
    }

    #[test]
    fn client_max_headers_succeeds() {
        let mut client = H2Client::<16, 16384>::new();
        let hdrs: [(&[u8], &[u8]); 16] = [
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
        ];
        let result = client.send_request("GET", "/", "example.com", &hdrs, true);
        assert!(result.is_ok());
    }

    #[test]
    fn client_too_many_headers() {
        let mut client = H2Client::<16, 16384>::new();
        let hdrs: [(&[u8], &[u8]); 17] = [
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
        ];
        let result = client.send_request("GET", "/", "example.com", &hdrs, true);
        assert_eq!(result, Err(crate::error::Error::TooManyHeaders));
    }

    #[test]
    fn client_server_e2e() {
        let mut client = H2Client::<16, 16384>::new();
        let mut server = H2Server::<16, 16384>::new();

        // Exchange handshake
        for _ in 0..5 {
            let mut buf = [0u8; 8192];
            while let Some(data) = client.poll_output(&mut buf) {
                let copy: heapless::Vec<u8, 8192> = {
                    let mut v = heapless::Vec::new();
                    let _ = v.extend_from_slice(data);
                    v
                };
                let _ = server.feed_data(&copy);
            }
            let mut buf2 = [0u8; 8192];
            while let Some(data) = server.poll_output(&mut buf2) {
                let copy: heapless::Vec<u8, 8192> = {
                    let mut v = heapless::Vec::new();
                    let _ = v.extend_from_slice(data);
                    v
                };
                let _ = client.feed_data(&copy);
            }
        }

        // Client sends request
        let stream_id = client
            .send_request("GET", "/", "example.com", &[], true)
            .unwrap();

        // Exchange
        let mut buf = [0u8; 8192];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy: heapless::Vec<u8, 8192> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            let _ = server.feed_data(&copy);
        }

        // Server sees headers
        let mut got_headers = false;
        let mut header_stream = 0u64;
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                got_headers = true;
                header_stream = sid;
            }
        }
        assert!(got_headers);

        // Server sends response
        server
            .send_response(
                header_stream,
                200,
                &[(b"content-type", b"text/plain")],
                false,
            )
            .unwrap();
        server
            .send_body(header_stream, b"Hello from H2!", true)
            .unwrap();

        // Exchange
        let mut buf2 = [0u8; 8192];
        while let Some(data) = server.poll_output(&mut buf2) {
            let copy: heapless::Vec<u8, 8192> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            let _ = client.feed_data(&copy);
        }

        // Client reads response
        let mut got_resp = false;
        let mut got_data = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                H2Event::Headers(sid) if sid == stream_id => got_resp = true,
                H2Event::Data(sid) if sid == stream_id => got_data = true,
                _ => {}
            }
        }
        assert!(got_resp);
        assert!(got_data);

        let mut body = [0u8; 256];
        let (n, _fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(&body[..n], b"Hello from H2!");
    }
}
