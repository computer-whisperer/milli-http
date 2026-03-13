//! HTTP/1.1 client wrapper.

use super::connection::{Http1Connection, Http1Event};
use super::io::Http1IoBufs;
use crate::error::Error;

/// HTTP/1.1 client — owns both the connection state and I/O buffers.
pub struct Http1Client<
    const BUF: usize = 8192,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    inner: Http1Connection<HDRBUF, DATABUF>,
    io: Http1IoBufs<BUF>,
}

impl<const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Http1Client<BUF, HDRBUF, DATABUF>
{
    /// Create a new HTTP/1.1 client connection.
    pub fn new() -> Self {
        Self {
            inner: Http1Connection::new_client(),
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

    /// Send a request. Returns the pseudo-stream ID.
    ///
    /// Encodes `{METHOD} {path} HTTP/1.1\r\n` + Host header + headers + `\r\n`.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        extra_headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        // 3 pseudo-headers + up to 17 user headers = 20 max
        if 3 + extra_headers.len() > 20 {
            return Err(Error::TooManyHeaders);
        }
        let mut headers: heapless::Vec<(&[u8], &[u8]), 20> = heapless::Vec::new();
        let _ = headers.push((b":method", method.as_bytes()));
        let _ = headers.push((b":path", path.as_bytes()));
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
        self.inner.recv_body(stream_id, buf)
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
    for Http1Client<BUF, HDRBUF, DATABUF>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::server::Http1Server;

    #[test]
    fn client_creation() {
        let _client = Http1Client::<4096>::new();
    }

    #[test]
    fn client_sends_request() {
        let mut client = Http1Client::<4096>::new();
        let stream_id = client
            .send_request("GET", "/", "example.com", &[], true)
            .unwrap();
        assert_eq!(stream_id, 1);

        let mut buf = [0u8; 4096];
        let data = client.poll_output(&mut buf).unwrap();
        let s = core::str::from_utf8(data).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn client_max_headers_succeeds() {
        let mut client = Http1Client::<8192>::new();
        // 3 pseudo + 17 user = 20, at the limit
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
        assert!(result.is_ok());
    }

    #[test]
    fn client_too_many_headers() {
        let mut client = Http1Client::<8192>::new();
        // 3 pseudo + 18 user = 21, over the limit
        let hdrs: [(&[u8], &[u8]); 18] = [
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
        ];
        let result = client.send_request("GET", "/", "example.com", &hdrs, true);
        assert_eq!(result, Err(crate::error::Error::TooManyHeaders));
    }

    #[test]
    fn client_server_e2e() {
        let mut client = Http1Client::<8192, 1024, 2048>::new();
        let mut server = Http1Server::<8192, 1024, 2048>::new();

        // Client sends request
        let stream_id = client
            .send_request("GET", "/hello", "localhost", &[], true)
            .unwrap();

        // Transfer client → server
        let mut buf = [0u8; 8192];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy: heapless::Vec<u8, 8192> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            server.feed_data(&copy).unwrap();
        }

        // Server receives request
        let mut got_request = false;
        let mut request_sid = 0u64;
        while let Some(ev) = server.poll_event() {
            if let Http1Event::Headers(stream_id) = ev {
                got_request = true;
                request_sid = stream_id;
            }
        }
        assert!(got_request);

        // Server reads method
        let mut method = heapless::Vec::<u8, 16>::new();
        server
            .recv_headers(request_sid, |name, value| {
                if name == b":method" {
                    let _ = method.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(method.as_slice(), b"GET");

        // Server sends response
        let body = b"Hello from HTTP/1.1!";
        let cl = body.len();
        let mut cl_buf = [0u8; 10];
        let cl_len = format_usize(cl, &mut cl_buf);
        server
            .send_response(
                request_sid,
                200,
                &[
                    (b"content-type", b"text/plain"),
                    (b"content-length", &cl_buf[..cl_len]),
                ],
                false,
            )
            .unwrap();
        server.send_body(request_sid, body, true).unwrap();

        // Transfer server → client
        let mut buf2 = [0u8; 8192];
        while let Some(data) = server.poll_output(&mut buf2) {
            let copy: heapless::Vec<u8, 8192> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            client.feed_data(&copy).unwrap();
        }

        // Client receives response
        let mut got_headers = false;
        let mut got_data = false;
        let mut got_finished = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                Http1Event::Headers(sid) if sid == stream_id => got_headers = true,
                Http1Event::Data(sid) if sid == stream_id => got_data = true,
                Http1Event::Finished(sid) if sid == stream_id => got_finished = true,
                _ => {}
            }
        }
        assert!(got_headers);
        assert!(got_data);
        assert!(got_finished);

        // Read status
        let mut status = heapless::Vec::<u8, 16>::new();
        client
            .recv_headers(stream_id, |name, value| {
                if name == b":status" {
                    let _ = status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(status.as_slice(), b"200");

        // Read body
        let mut resp_body = [0u8; 256];
        let (n, fin) = client.recv_body(stream_id, &mut resp_body).unwrap();
        assert_eq!(&resp_body[..n], b"Hello from HTTP/1.1!");
        assert!(fin);
    }

    /// Format a usize into a decimal ASCII buffer. Returns the number of bytes written.
    fn format_usize(mut n: usize, buf: &mut [u8]) -> usize {
        if n == 0 {
            buf[0] = b'0';
            return 1;
        }
        let mut tmp = [0u8; 20];
        let mut len = 0;
        while n > 0 {
            tmp[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        for i in 0..len {
            buf[i] = tmp[len - 1 - i];
        }
        len
    }
}
