//! HTTP/2 over TLS 1.3 composed connection with shared buffers.
//!
//! Same buffer-sharing pattern as [`https1`](crate::https1): three buffers
//! instead of six. TLS decrypts records in place, so H2 parses frames straight
//! out of `net_recv`'s plaintext prefix; `app_send` is shared with H2 `send`.

use crate::buf::Buf;
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::h2::connection::{H2Connection, H2Event};
use crate::h2::io::H2Io;
use crate::tcp_tls::connection::TlsConnection;
use crate::tcp_tls::io::TlsIo;
use crate::tls::handshake::{ServerTlsConfig, TlsConfig};

/// HTTP/2 over TLS client — shared buffer composition.
pub struct H2TlsClient<
    C: CryptoProvider,
    const BUF: usize = 18432,
    const MAX_STREAMS: usize = 8,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    tls: TlsConnection<C>,
    h2: H2Connection<MAX_STREAMS, HDRBUF, DATABUF>,
    net_recv: Buf<BUF>,
    net_send: Buf<BUF>,
    app_send: Buf<BUF>,
}

impl<
    C: CryptoProvider,
    const BUF: usize,
    const MAX_STREAMS: usize,
    const HDRBUF: usize,
    const DATABUF: usize,
> H2TlsClient<C, BUF, MAX_STREAMS, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    /// Create a new HTTP/2 over TLS client connection.
    pub fn new(provider: C, config: TlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        Self {
            tls: TlsConnection::new_client(provider, config, secret, random),
            h2: H2Connection::new_client(),
            net_recv: Buf::new(),
            net_send: Buf::new(),
            app_send: Buf::new(),
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

        // Feed decrypted plaintext to H2
        if !self.net_recv.is_empty() {
            let mut h2_io: H2Io<'_, BUF> = H2Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.h2.feed_data(&mut h2_io, &[])?;
        }

        Ok(())
    }

    /// Pull outgoing TCP data (encrypted).
    ///
    /// During handshake, returns TLS handshake messages.
    /// After handshake, H2 frames are generated into the shared send buffer
    /// and encrypted by TLS before output.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        // Have H2 generate pending frames (SETTINGS, etc.) into app_send.
        // We call generate_output (not poll_output) because we don't want H2
        // to drain the buffer — TLS will consume it via flush_app_send.
        {
            let mut h2_io: H2Io<'_, BUF> = H2Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.h2.generate_output(&mut h2_io);
        }

        // TLS encrypts from app_send (H2 frames) and outputs encrypted data
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.poll_output(&mut tls_io, buf)
    }

    /// Poll for H2 events.
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.h2.poll_event()
    }

    /// Whether the TLS handshake is complete and H2 SETTINGS are exchanged.
    pub fn is_established(&self) -> bool {
        self.tls.is_active() && self.h2.is_established()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.tls.is_closed() || self.h2.is_closed()
    }

    /// Send an HTTP/2 request. Returns the stream ID.
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
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.open_stream(&mut h2_io, &headers, end_stream)
    }

    /// Send body data on a stream.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.send_data(&mut h2_io, stream_id, data, end_stream)
    }

    /// Read response headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.h2.recv_headers(stream_id, emit)
    }

    /// Read response body.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.recv_body(&mut h2_io, stream_id, buf)
    }

    /// Cancel a stream: stop receiving its response body (see
    /// [`H2Connection::discard_body`]). Discards buffered/in-flight body
    /// data, restores flow-control credit, and sends RST_STREAM with
    /// `error_code` unless the peer already finished the stream. Use to
    /// abandon a long-lived response stream (e.g. a telemetry subscription)
    /// without tearing down the shared connection — other streams are
    /// unaffected, and late frames the peer already had in flight are
    /// ignored.
    ///
    /// [`H2Connection::discard_body`]: crate::h2::connection::H2Connection::discard_body
    pub fn discard_body(&mut self, stream_id: u64, error_code: u32) -> Result<(), Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.discard_body(&mut h2_io, stream_id, error_code)
    }

    /// Configure timeouts.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.h2.set_timeouts(config, now);
    }

    /// Return the earliest deadline at which `handle_timeout` should be called.
    pub fn next_timeout(&self) -> Option<u64> {
        self.h2.next_timeout()
    }

    /// Check timeouts and emit events if they fire.
    pub fn handle_timeout(&mut self, now: u64) {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.handle_timeout(&mut h2_io, now);
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
            let mut h2_io: H2Io<'_, BUF> = H2Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.h2.feed_data_timed(&mut h2_io, &[], now)?;
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

/// HTTP/2 over TLS server — shared buffer composition.
pub struct H2TlsServer<
    C: CryptoProvider,
    const BUF: usize = 18432,
    const MAX_STREAMS: usize = 8,
    const HDRBUF: usize = 2048,
    // Per-stream body buffer. DATA frames are consumed incrementally (see
    // H2Connection::process_recv / pump_partial_data), so this need NOT hold a
    // whole max-size (16384) frame: the pump fills it, stops, and the runner
    // applies TCP backpressure (see HttpServerConn::recv_blocked) until the
    // consumer drains via recv_body. Keeping it small (4 KB) bounds per-stream
    // heap — a full-size data_buf was the allocation that OOM'd a memory-tight
    // h2 upload. The advertised stream receive window equals DATABUF, so the
    // peer is paced to our drain rate once it has processed our SETTINGS; a
    // legal pre-SETTINGS-ack burst (RFC 9113 §6.9.2) is absorbed by the same
    // backpressure rather than rejected.
    const DATABUF: usize = 4096,
> {
    tls: TlsConnection<C>,
    h2: H2Connection<MAX_STREAMS, HDRBUF, DATABUF>,
    net_recv: Buf<BUF>,
    net_send: Buf<BUF>,
    app_send: Buf<BUF>,
}

impl<
    C: CryptoProvider,
    const BUF: usize,
    const MAX_STREAMS: usize,
    const HDRBUF: usize,
    const DATABUF: usize,
> H2TlsServer<C, BUF, MAX_STREAMS, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    /// Create a new HTTP/2 over TLS server connection.
    pub fn new(provider: C, config: ServerTlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        Self {
            tls: TlsConnection::new_server(provider, config, secret, random),
            h2: H2Connection::new_server(),
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
            h2: H2Connection::new_server(),
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
            let mut h2_io: H2Io<'_, BUF> = H2Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.h2.feed_data(&mut h2_io, &[])?;
        }

        Ok(())
    }

    /// Pull outgoing TCP data (encrypted).
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        {
            let mut h2_io: H2Io<'_, BUF> = H2Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.h2.generate_output(&mut h2_io);
        }

        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.poll_output(&mut tls_io, buf)
    }

    /// Poll for H2 events.
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.h2.poll_event()
    }

    /// Whether TLS handshake is complete and H2 SETTINGS are exchanged.
    pub fn is_established(&self) -> bool {
        self.tls.is_active() && self.h2.is_established()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.tls.is_closed() || self.h2.is_closed()
    }

    /// Read request headers.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        self.h2.recv_headers(stream_id, emit)
    }

    /// Read request body.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.recv_body(&mut h2_io, stream_id, buf)
    }

    /// Stop receiving a stream's request body (see
    /// [`H2Connection::discard_body`]): discards buffered/in-flight body
    /// data, restores flow-control credit, and sends RST_STREAM with
    /// `error_code` unless the peer already finished the stream. Use when
    /// responding without consuming the body.
    ///
    /// [`H2Connection::discard_body`]: crate::h2::connection::H2Connection::discard_body
    pub fn discard_body(&mut self, stream_id: u64, error_code: u32) -> Result<(), Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.discard_body(&mut h2_io, stream_id, error_code)
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
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2
            .send_headers(&mut h2_io, stream_id, &all_headers, end_stream)
    }

    /// Send response body data.
    pub fn send_body(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.send_data(&mut h2_io, stream_id, data, end_stream)
    }

    /// Configure timeouts.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.h2.set_timeouts(config, now);
    }

    /// Return the earliest deadline at which `handle_timeout` should be called.
    pub fn next_timeout(&self) -> Option<u64> {
        self.h2.next_timeout()
    }

    /// Check timeouts and emit events if they fire.
    pub fn handle_timeout(&mut self, now: u64) {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.handle_timeout(&mut h2_io, now);
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
            let mut h2_io: H2Io<'_, BUF> = H2Io {
                recv_buf: &mut self.net_recv,
                send_buf: &mut self.app_send,
            };
            self.h2.feed_data_timed(&mut h2_io, &[], now)?;
        }

        Ok(())
    }

    /// Send GOAWAY.
    pub fn send_goaway(&mut self, error_code: u32) -> Result<(), Error> {
        let mut h2_io: H2Io<'_, BUF> = H2Io {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.app_send,
        };
        self.h2.send_goaway(&mut h2_io, error_code)
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

fn map_h2_event(ev: H2Event) -> crate::http::server_conn::HttpEvent {
    use crate::http::server_conn::HttpEvent;
    match ev {
        H2Event::Connected => HttpEvent::Connected,
        H2Event::Headers(s) => HttpEvent::Headers(s),
        H2Event::Data(s) => HttpEvent::Data(s),
        H2Event::Finished(s) => HttpEvent::Finished(s),
        H2Event::StreamReset(s, code) => HttpEvent::StreamReset {
            stream_id: s,
            error_code: code as u64,
        },
        H2Event::GoAway(_, code) => HttpEvent::GoAway {
            error_code: code as u64,
        },
        H2Event::Timeout => HttpEvent::Timeout,
    }
}

impl<
    C: CryptoProvider,
    const BUF: usize,
    const MAX_STREAMS: usize,
    const HDRBUF: usize,
    const DATABUF: usize,
> crate::http::server_conn::HttpServerConn for H2TlsServer<C, BUF, MAX_STREAMS, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    fn poll_event(&mut self, _scratch: &mut [u8]) -> Option<crate::http::server_conn::HttpEvent> {
        H2TlsServer::poll_event(self).map(map_h2_event)
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        H2TlsServer::recv_headers(self, stream_id, emit)
    }

    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        H2TlsServer::recv_body(self, stream_id, buf)
    }

    fn send_response(
        &mut self,
        stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        H2TlsServer::send_response(self, stream_id, status, headers, end_stream)
    }

    fn send_capacity(&self, stream_id: u64) -> Option<usize> {
        self.h2.send_capacity(stream_id)
    }

    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        H2TlsServer::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        H2TlsServer::is_established(self)
    }

    fn is_closed(&self) -> bool {
        H2TlsServer::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        H2TlsServer::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        H2TlsServer::handle_timeout(self, now);
    }

    fn discard_body(&mut self, stream_id: u64, error_code: u32) -> Result<(), Error> {
        H2TlsServer::discard_body(self, stream_id, error_code)
    }

    fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        H2TlsServer::set_timeouts(self, config, now);
    }

    fn tcp_feed_data(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        H2TlsServer::feed_data_timed(self, data, now)
    }

    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        H2TlsServer::poll_output(self, buf)
    }

    fn recv_blocked(&self) -> bool {
        // A DATA frame is mid-flight (pump stalled on a full data_buf) AND
        // there is still unprocessed plaintext parked in net_recv's visible
        // prefix. Reading more TCP now would only grow net_recv toward the
        // BUF ceiling; instead the runner should re-drive the pump so the body
        // consumer can drain. Once the plaintext is consumed we resume reading
        // to fetch the rest of the frame.
        self.h2.has_partial_data() && !self.net_recv.is_empty()
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

impl<
    C: CryptoProvider,
    const BUF: usize,
    const MAX_STREAMS: usize,
    const HDRBUF: usize,
    const DATABUF: usize,
> crate::http::server_conn::HttpServerConn for H2TlsClient<C, BUF, MAX_STREAMS, HDRBUF, DATABUF>
where
    C::Hkdf: Default,
{
    fn poll_event(&mut self, _scratch: &mut [u8]) -> Option<crate::http::server_conn::HttpEvent> {
        H2TlsClient::poll_event(self).map(map_h2_event)
    }

    fn recv_headers(
        &mut self,
        stream_id: u64,
        emit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Error> {
        H2TlsClient::recv_headers(self, stream_id, emit)
    }

    fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        H2TlsClient::recv_body(self, stream_id, buf)
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

    fn send_capacity(&self, stream_id: u64) -> Option<usize> {
        self.h2.send_capacity(stream_id)
    }

    fn send_body(&mut self, stream_id: u64, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        H2TlsClient::send_body(self, stream_id, data, end_stream)
    }

    fn is_established(&self) -> bool {
        H2TlsClient::is_established(self)
    }

    fn is_closed(&self) -> bool {
        H2TlsClient::is_closed(self)
    }

    fn next_timeout(&self) -> Option<u64> {
        H2TlsClient::next_timeout(self)
    }

    fn handle_timeout(&mut self, now: u64) {
        H2TlsClient::handle_timeout(self, now);
    }

    fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        H2TlsClient::set_timeouts(self, config, now);
    }

    fn tcp_feed_data(&mut self, data: &[u8], now: u64) -> Result<(), Error> {
        H2TlsClient::feed_data_timed(self, data, now)
    }

    fn tcp_poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        H2TlsClient::poll_output(self, buf)
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

    type TestClient = H2TlsClient<Aes128GcmProvider, 32768, 8>;
    type TestServer = H2TlsServer<Aes128GcmProvider, 32768, 8>;

    fn make_client() -> TestClient {
        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        H2TlsClient::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
    }

    fn make_server(cert: &'static [u8]) -> TestServer {
        let config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
        };
        H2TlsServer::new(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
    }

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

    /// Reproduce the firmware OTA failure: server with hardware buffer sizes
    /// (BUF=18432, DATABUF=16384), client that bursts DATA before processing
    /// the server's SETTINGS (like curl/nghttp2 does), fed in runner-style
    /// 1500-byte chunks with one event drained per "poll cycle".
    #[test]
    fn h2_tls_hw_sized_upload_burst() {
        extern crate std;
        use std::println;
        use std::vec::Vec;

        type HwServer = H2TlsServer<Aes128GcmProvider, 18432, 8, 2048, 16384>;
        // Client gets a big BUF so it can stage full records.
        type BigClient = H2TlsClient<Aes128GcmProvider, 65536, 8, 2048, 4096>;

        let cert: &'static [u8] = test_cert_der().leak();
        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        let mut client = BigClient::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32]);
        let server_config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
        };
        let mut server = HwServer::new(Aes128GcmProvider, server_config, [0xCC; 32], [0xDD; 32]);

        // TLS handshake: full exchange, but capture server->client bytes and
        // STOP delivering them to the client as soon as the client's TLS layer
        // is active — emulating curl, which has the server's h2 SETTINGS still
        // in flight when it starts sending DATA.
        for _ in 0..40 {
            let mut buf = [0u8; 65536];
            let mut progress = false;
            while let Some(data) = client.poll_output(&mut buf) {
                let copy = data.to_vec();
                server.feed_data(&copy).unwrap();
                progress = true;
            }
            let mut buf2 = [0u8; 65536];
            while let Some(data) = server.poll_output(&mut buf2) {
                let copy = data.to_vec();
                if !client.tls.is_active() {
                    client.feed_data(&copy).unwrap();
                }
                // else: drop — still "in flight" from the client's perspective
                progress = true;
            }
            if !progress {
                break;
            }
        }
        assert!(client.tls.is_active(), "client TLS should be active");
        assert!(server.tls.is_active(), "server TLS should be active");

        // Client sends HEADERS then bursts DATA under the assumed RFC default
        // windows (65535 stream / 65535 conn), since it never processed the
        // server's SETTINGS (initial_window = DATABUF = 16384).
        let stream_id = client
            .send_request("POST", "/system/update", "test.local", &[], false)
            .unwrap();

        let payload = [0xA5u8; 16384];
        let mut sent_total = 0usize;
        let mut backlog: Vec<u8> = Vec::new();
        let mut out = [0u8; 4096];
        // Interleave send_body and poll_output until the client's view of the
        // windows is exhausted.
        loop {
            match client.send_body(stream_id, &payload, false) {
                Ok(n) if n > 0 => {
                    sent_total += n;
                }
                _ => {
                    // Drain staged output; if still can't send, windows are dry.
                    let mut drained = false;
                    while let Some(data) = client.poll_output(&mut out) {
                        backlog.extend_from_slice(data);
                        drained = true;
                    }
                    if !drained {
                        break;
                    }
                    match client.send_body(stream_id, &payload, false) {
                        Ok(n) if n > 0 => sent_total += n,
                        _ => break,
                    }
                }
            }
        }
        while let Some(data) = client.poll_output(&mut out) {
            backlog.extend_from_slice(data);
        }
        println!(
            "client burst: {} h2 body bytes, {} TLS wire bytes",
            sent_total,
            backlog.len()
        );
        assert!(sent_total > 16384, "burst should exceed the server window");

        // Now replay the firmware runner: 4 reads x 1500 bytes per cycle, then
        // pop ONE event; on Data, drain recv_body fully (1024-byte chunks) the
        // way UpdateService::feed does. Track where it dies.
        let mut consumed = 0usize;
        let mut offset = 0usize;
        let mut sink = [0u8; 4096];
        let mut cycle = 0usize;
        let mut feed_err: Option<Error> = None;
        'outer: while offset < backlog.len() || consumed < sent_total {
            cycle += 1;
            if cycle > 10_000 {
                println!("stalled: consumed {} of {}", consumed, sent_total);
                break;
            }
            for _ in 0..4 {
                if offset >= backlog.len() {
                    break;
                }
                let end = (offset + 1500).min(backlog.len());
                if let Err(e) = server.feed_data(&backlog[offset..end]) {
                    println!(
                        "server.feed_data FAILED at wire offset {} (consumed {} body bytes): {:?}",
                        offset, consumed, e
                    );
                    feed_err = Some(e);
                    break 'outer;
                }
                offset = end;
            }
            // Server output (SETTINGS, WINDOW_UPDATE, ...) drains to nowhere —
            // the client never processes it, same as curl mid-burst.
            let mut obuf = [0u8; 4096];
            while server.poll_output(&mut obuf).is_some() {}
            if let Some(ev) = server.poll_event() {
                if let H2Event::Data(sid) = ev {
                    loop {
                        match server.recv_body(sid, &mut sink) {
                            Ok((0, _)) => break,
                            Ok((n, _)) => consumed += n,
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        println!(
            "result: consumed {} of {} body bytes; feed_err = {:?}",
            consumed, sent_total, feed_err
        );
        assert!(
            feed_err.is_none() && consumed == sent_total,
            "server must absorb a legal pre-SETTINGS-ack burst: consumed {} of {}, err {:?}",
            consumed,
            sent_total,
            feed_err
        );
    }

    #[test]
    fn h2_tls_creation() {
        let cert: &'static [u8] = test_cert_der().leak();
        let _client = make_client();
        let _server = make_server(cert);
    }

    #[test]
    fn h2_tls_handshake() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);
        exchange(&mut client, &mut server);
        assert!(client.is_established());
        assert!(server.is_established());
    }

    #[test]
    fn h2_tls_e2e() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut server = make_server(cert);

        // Complete TLS handshake + H2 SETTINGS exchange
        exchange(&mut client, &mut server);
        assert!(client.is_established());
        assert!(server.is_established());

        // Client sends request
        let stream_id = client
            .send_request("GET", "/hello", "test.local", &[], true)
            .unwrap();

        // Transfer
        exchange(&mut client, &mut server);

        // Server sees request headers
        let mut got_headers = false;
        let mut request_sid = 0u64;
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                got_headers = true;
                request_sid = sid;
            }
        }
        assert!(got_headers);

        // Server sends response
        server
            .send_response(request_sid, 200, &[(b"content-type", b"text/plain")], false)
            .unwrap();
        server
            .send_body(request_sid, b"Hello from H2-TLS!", true)
            .unwrap();

        // Transfer
        exchange(&mut client, &mut server);

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
        assert_eq!(&body[..n], b"Hello from H2-TLS!");
    }
}
