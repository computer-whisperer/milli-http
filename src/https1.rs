//! HTTPS/1.1 composed connection — TLS 1.3 + HTTP/1.1 with shared buffers.
//!
//! This wrapper composes [`TlsConnection`] and [`Http1Connection`] into a
//! single type that shares application-layer buffers between the two protocol
//! layers. Instead of 6 separate buffers (4 TLS + 2 HTTP), this uses only 3:
//!
//! | Buffer | Purpose |
//! |--------|---------|
//! | `net_recv` | Encrypted TLS records, decrypted in place = HTTP recv buffer |
//! | `net_send` | Holds encrypted TLS records to send to the network |
//! | `app_send` | HTTP send buffer = TLS plaintext to encrypt |
//!
//! The receive path: `feed_data(encrypted)` → TLS decrypt in place → HTTP parse → events
//!
//! The send path: HTTP frame → `app_send` → TLS encrypt → `net_send` → `poll_output()`

use crate::buf::Buf;
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::http1::connection::{Http1Connection, Http1Event};
use crate::http1::io::Http1Io;
use crate::tcp_tls::connection::TlsConnection;
use crate::tcp_tls::io::TlsIo;
use crate::tls::handshake::{ServerTlsConfig, TlsConfig};

/// HTTPS/1.1 client — TLS 1.3 + HTTP/1.1 with shared buffers.
///
/// Generic parameters:
/// - `C`: Crypto provider
/// - `BUF`: Buffer size for all I/O buffers (18432 = max TLS record)
/// - `HDRBUF`: HTTP header storage buffer size
/// - `DATABUF`: HTTP body data buffer size
pub struct Https1Client<
    C: CryptoProvider,
    const BUF: usize = 18432,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    tls: TlsConnection<C>,
    http: Http1Connection<HDRBUF, DATABUF>,
    net_recv: Buf<BUF>,
    net_send: Buf<BUF>,
    app_send: Buf<BUF>,
}

impl<C: CryptoProvider, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Https1Client<C, BUF, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    /// Create a new HTTPS/1.1 client connection.
    pub fn new(provider: C, config: TlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        Self {
            tls: TlsConnection::new_client(provider, config, secret, random),
            http: Http1Connection::new_client(),
            net_recv: Buf::new(),
            net_send: Buf::new(),
            app_send: Buf::new(),
        }
    }

    /// Feed received TCP data (encrypted).
    ///
    /// During TLS handshake, this processes handshake messages.
    /// After handshake, decrypted plaintext is automatically fed to the HTTP layer.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        {
            let mut tls_io: TlsIo<'_, BUF> = TlsIo {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.net_send,
                app_send_buf: &mut self.app_send,
            };
            self.tls.feed_data(&mut tls_io, data)?;
        }

        // TLS may have decrypted plaintext in place: net_recv's visible
        // prefix IS HTTP's recv_buf, so trigger HTTP processing.
        if !self.net_recv.is_empty() {
            let mut http_io: Http1Io<'_, BUF> = Http1Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.http.feed_data(&mut http_io, &[])?;
        }

        Ok(())
    }

    /// Pull outgoing TCP data (encrypted).
    ///
    /// During handshake, returns TLS handshake messages.
    /// After handshake, encrypts any pending HTTP frames before returning.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.poll_output(&mut tls_io, buf)
    }

    /// Poll for HTTP events.
    ///
    /// Returns `None` until the TLS handshake completes and HTTP data arrives.
    pub fn poll_event(&mut self) -> Option<Http1Event> {
        self.http.poll_event()
    }

    /// Whether the TLS handshake is complete and HTTP requests can be sent.
    pub fn is_established(&self) -> bool {
        self.tls.is_active()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.tls.is_closed() || self.http.is_closed()
    }

    /// Send an HTTP request over the encrypted connection.
    ///
    /// Returns the pseudo-stream ID. Fails if the TLS handshake is not complete.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        extra_headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        if !self.tls.is_active() {
            return Err(Error::InvalidState);
        }
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
        let mut http_io: Http1Io<'_, BUF> = Http1Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.http.open_stream(&mut http_io, &headers, end_stream)
    }

    /// Send body data on a stream.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        if !self.tls.is_active() {
            return Err(Error::InvalidState);
        }
        let mut http_io: Http1Io<'_, BUF> = Http1Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.http
            .send_data(&mut http_io, stream_id, data, end_stream)
    }

    /// Read response headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.http.recv_headers(stream_id, emit)
    }

    /// Read response body.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.http.recv_body(stream_id, buf)
    }

    /// Configure timeouts.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.http.set_timeouts(config, now);
    }

    /// Return the earliest deadline at which `handle_timeout` should be called.
    pub fn next_timeout(&self) -> Option<u64> {
        self.http.next_timeout()
    }

    /// Check timeouts and emit events if they fire.
    pub fn handle_timeout(&mut self, now: u64) {
        self.http.handle_timeout(now);
    }

    /// Feed data with timestamp tracking.
    pub fn feed_data_timed(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        {
            let mut tls_io: TlsIo<'_, BUF> = TlsIo {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.net_send,
                app_send_buf: &mut self.app_send,
            };
            self.tls.feed_data(&mut tls_io, data)?;
        }

        if !self.net_recv.is_empty() {
            let mut http_io: Http1Io<'_, BUF> = Http1Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.http.feed_data_timed(&mut http_io, &[], now)?;
        }

        Ok(())
    }

    /// Get negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }

    /// Initiate graceful close.
    pub fn close(&mut self) -> Result<(), Error> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.close(&mut tls_io)
    }
}

/// HTTPS/1.1 server — TLS 1.3 + HTTP/1.1 with shared buffers.
pub struct Https1Server<
    C: CryptoProvider,
    const BUF: usize = 18432,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    tls: TlsConnection<C>,
    http: Http1Connection<HDRBUF, DATABUF>,
    net_recv: Buf<BUF>,
    net_send: Buf<BUF>,
    app_send: Buf<BUF>,
}

impl<C: CryptoProvider, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    Https1Server<C, BUF, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    /// Create a new HTTPS/1.1 server connection.
    pub fn new(provider: C, config: ServerTlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        Self {
            tls: TlsConnection::new_server(provider, config, secret, random),
            http: Http1Connection::new_server(),
            net_recv: Buf::new(),
            net_send: Buf::new(),
            app_send: Buf::new(),
        }
    }

    /// Create from pre-handshaked TLS parts (used by connection manager after ALPN).
    #[cfg(feature = "tcp-tls")]
    pub fn from_parts(parts: crate::tcp_tls::TlsParts<C, BUF>) -> Self {
        Self {
            tls: parts.tls,
            http: Http1Connection::new_server(),
            net_recv: parts.net_recv,
            net_send: parts.net_send,
            app_send: parts.app_send,
        }
    }

    /// Feed received TCP data (encrypted).
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        {
            let mut tls_io: TlsIo<'_, BUF> = TlsIo {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.net_send,
                app_send_buf: &mut self.app_send,
            };
            self.tls.feed_data(&mut tls_io, data)?;
        }

        if !self.net_recv.is_empty() {
            let mut http_io: Http1Io<'_, BUF> = Http1Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.http.feed_data(&mut http_io, &[])?;
        }

        Ok(())
    }

    /// Pull outgoing TCP data (encrypted).
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.poll_output(&mut tls_io, buf)
    }

    /// Poll for HTTP events.
    pub fn poll_event(&mut self) -> Option<Http1Event> {
        self.http.poll_event()
    }

    /// Whether the TLS handshake is complete.
    pub fn is_established(&self) -> bool {
        self.tls.is_active()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.tls.is_closed() || self.http.is_closed()
    }

    /// Read request headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.http.recv_headers(stream_id, emit)
    }

    /// Read request body.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.http.recv_body(stream_id, buf)
    }

    /// Send response headers.
    pub fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        if !self.tls.is_active() {
            return Err(Error::InvalidState);
        }
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
        let mut http_io: Http1Io<'_, BUF> = Http1Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.http
            .send_headers(&mut http_io, stream_id, &all_headers, end_stream)
    }

    /// Send response body data.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        if !self.tls.is_active() {
            return Err(Error::InvalidState);
        }
        let mut http_io: Http1Io<'_, BUF> = Http1Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.http
            .send_data(&mut http_io, stream_id, data, end_stream)
    }

    /// Configure timeouts.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.http.set_timeouts(config, now);
    }

    /// Return the earliest deadline at which `handle_timeout` should be called.
    pub fn next_timeout(&self) -> Option<u64> {
        self.http.next_timeout()
    }

    /// Check timeouts and emit events if they fire.
    pub fn handle_timeout(&mut self, now: u64) {
        self.http.handle_timeout(now);
    }

    /// Feed data with timestamp tracking.
    pub fn feed_data_timed(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        {
            let mut tls_io: TlsIo<'_, BUF> = TlsIo {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.net_send,
                app_send_buf: &mut self.app_send,
            };
            self.tls.feed_data(&mut tls_io, data)?;
        }

        if !self.net_recv.is_empty() {
            let mut http_io: Http1Io<'_, BUF> = Http1Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.http.feed_data_timed(&mut http_io, &[], now)?;
        }

        Ok(())
    }

    /// Get negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }

    /// Initiate graceful close.
    pub fn close(&mut self) -> Result<(), Error> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.close(&mut tls_io)
    }
}

fn map_http1_event(ev: Http1Event) -> crate::http::server_conn::HttpEvent {
    use crate::http::server_conn::HttpEvent;
    match ev {
        Http1Event::Connected => HttpEvent::Connected,
        Http1Event::Headers(s) => HttpEvent::Headers(s),
        Http1Event::Data(s) => HttpEvent::Data(s),
        Http1Event::Finished(s) => HttpEvent::Finished(s),
        Http1Event::Timeout => HttpEvent::Timeout,
    }
}

impl<C: CryptoProvider, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    crate::http::server_conn::HttpServerConn for Https1Server<C, BUF, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    fn poll_event(&mut self, _scratch: &mut [u8]) -> Option<crate::http::server_conn::HttpEvent> {
        self.poll_event().map(map_http1_event)
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        Https1Server::recv_headers(self, stream_id, emit)
    }

    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        Https1Server::recv_body(self, stream_id, buf)
    }

    fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        Https1Server::send_response(self, stream_id, status, headers, end_stream)
    }

    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        Https1Server::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        Https1Server::is_established(self)
    }

    fn is_closed(&self) -> bool {
        Https1Server::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        Https1Server::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        Https1Server::handle_timeout(self, now);
    }

    fn tcp_feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        Https1Server::feed_data(self, data)
    }

    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        Https1Server::poll_output(self, buf)
    }

    fn reclaim_buffers(&mut self) -> Option<crate::tcp_tls::TlsBufKit> {
        // Recover the three I/O buffers' `'static` slices only if all three
        // are static-backed (they are constructed uniformly via `from_parts`).
        let net_recv = self.net_recv.take_static();
        let net_send = self.net_send.take_static();
        let app_send = self.app_send.take_static();
        match (net_recv, net_send, app_send) {
            (Some(net_recv), Some(net_send), Some(app_send)) => Some(crate::tcp_tls::TlsBufKit {
                net_recv,
                net_send,
                app_send,
            }),
            _ => None,
        }
    }
}

impl<C: CryptoProvider, const BUF: usize, const HDRBUF: usize, const DATABUF: usize>
    crate::http::server_conn::HttpServerConn for Https1Client<C, BUF, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    fn poll_event(&mut self, _scratch: &mut [u8]) -> Option<crate::http::server_conn::HttpEvent> {
        self.poll_event().map(map_http1_event)
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        Https1Client::recv_headers(self, stream_id, emit)
    }

    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        Https1Client::recv_body(self, stream_id, buf)
    }

    fn send_response(
        &mut self,
        _stream_id: u64,
        _status: u16,
        _headers: &[(&[u8], &[u8])],
        _end_stream: bool,
    ) -> Result<(), Error> {
        Err(Error::InvalidState) // clients don't send responses
    }

    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        Https1Client::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        Https1Client::is_established(self)
    }

    fn is_closed(&self) -> bool {
        Https1Client::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        Https1Client::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        Https1Client::handle_timeout(self, now);
    }

    fn tcp_feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        Https1Client::feed_data(self, data)
    }

    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        Https1Client::poll_output(self, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    use crate::tls::TransportParams;

    const TEST_SEED: [u8; 32] = [0x01u8; 32];

    fn test_cert_der() -> Vec<u8> {
        let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&TEST_SEED);
        let mut buf = [0u8; 512];
        let len = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut buf).unwrap();
        buf[..len].to_vec()
    }

    type TestClient = Https1Client<Aes128GcmProvider, 32768, 1024, 2048>;
    type TestServer = Https1Server<Aes128GcmProvider, 32768, 1024, 2048>;

    fn make_client() -> TestClient {
        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"http/1.1"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        Https1Client::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
    }

    fn make_server(cert: &'static [u8]) -> TestServer {
        let config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"http/1.1"],
            transport_params: TransportParams::default_params(),
        };
        Https1Server::new(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
    }

    /// Exchange TLS data between client and server until no more output.
    fn exchange(client: &mut TestClient, server: &mut TestServer) {
        for _ in 0..20 {
            let mut buf = [0u8; 32768];
            let mut progress = false;

            while let Some(data) = client.poll_output(&mut buf) {
                let copy = data.to_vec();
                server.feed_data(&copy).unwrap();
                progress = true;
            }

            let mut buf2 = [0u8; 32768];
            while let Some(data) = server.poll_output(&mut buf2) {
                let copy = data.to_vec();
                client.feed_data(&copy).unwrap();
                progress = true;
            }

            if !progress {
                break;
            }
        }
    }

    #[test]
    fn https1_creation() {
        let cert: &'static [u8] = test_cert_der().leak();
        let _client = make_client();
        let _server = make_server(cert);
    }

    #[test]
    fn https1_handshake() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);
        exchange(&mut client, &mut server);
        assert!(client.is_established());
        assert!(server.is_established());
    }

    #[test]
    fn https1_request_before_handshake_fails() {
        let mut client = make_client();
        let result = client.send_request("GET", "/", "localhost", &[], true);
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn https1_e2e() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        // Complete TLS handshake
        exchange(&mut client, &mut server);
        assert!(client.is_established());
        assert!(server.is_established());

        // Client sends GET request
        let stream_id = client
            .send_request("GET", "/hello", "test.local", &[], true)
            .unwrap();

        // Transfer client → server
        exchange(&mut client, &mut server);

        // Server should see the request
        let mut got_headers = false;
        let mut request_sid = 0u64;
        while let Some(ev) = server.poll_event() {
            match ev {
                Http1Event::Headers(sid) => {
                    got_headers = true;
                    request_sid = sid;
                }
                _ => {}
            }
        }
        assert!(got_headers);

        // Server reads request headers
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
        server
            .send_response(request_sid, 200, &[(b"content-length", b"13")], false)
            .unwrap();
        server
            .send_body(request_sid, b"Hello, HTTPS!", true)
            .unwrap();

        // Transfer server → client
        exchange(&mut client, &mut server);

        // Client reads response
        let mut got_resp_headers = false;
        let mut got_data = false;
        let mut got_finished = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                Http1Event::Headers(sid) if sid == stream_id => got_resp_headers = true,
                Http1Event::Data(sid) if sid == stream_id => got_data = true,
                Http1Event::Finished(sid) if sid == stream_id => got_finished = true,
                _ => {}
            }
        }
        assert!(got_resp_headers);
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
        let mut body = [0u8; 64];
        let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(&body[..n], b"Hello, HTTPS!");
        assert!(fin);
    }
}
