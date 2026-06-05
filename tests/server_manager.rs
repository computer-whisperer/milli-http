//! ServerManager integration tests.
//!
//! Tests the pure-logic connection manager with TCP (TLS→HTTP) and UDP (QUIC→H3).

#![cfg(feature = "server")]

use milli_http::connection::HandshakePool;
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::http::server_conn::HttpEvent;
use milli_http::server::{ServerConfig, ServerEvent, ServerManager};
use milli_http::tls::handshake::{ServerTlsConfig, TlsConfig};
use milli_http::tls::transport_params::TransportParams;
use milli_http::transport::Rng;

const TEST_SEED: [u8; 32] = [0x01u8; 32];

fn test_cert_der() -> Vec<u8> {
    let pk = milli_http::crypto::ed25519::ed25519_public_key_from_seed(&TEST_SEED);
    let mut buf = [0u8; 512];
    let len = milli_http::crypto::ed25519::build_ed25519_cert_der(&pk, &mut buf).unwrap();
    buf[..len].to_vec()
}

struct TestRng(u8);
impl Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn make_server_config(cert: &'static [u8]) -> ServerTlsConfig {
    ServerTlsConfig {
        cert_der: cert,
        private_key_der: Box::leak(Box::new(TEST_SEED)),
        alpn_protocols: &[b"http/1.1", b"h2"],
        transport_params: TransportParams::default_params(),
    }
}

// -----------------------------------------------------------------------
// TCP tests
// -----------------------------------------------------------------------

#[test]
fn tcp_accept_creates_connection() {
    let cert: &'static [u8] = test_cert_der().leak();
    let config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, config, ServerConfig::default());
    let mut rng = TestRng(0x10);

    let id = manager.accept_tcp(&mut rng, 0).unwrap();
    assert_eq!(id.0, 0);

    let id2 = manager.accept_tcp(&mut rng, 0).unwrap();
    assert_eq!(id2.0, 1);
}

#[test]
fn tcp_handshake_and_http1_request() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x10);

    // Accept a TCP connection in the manager
    let conn_id = manager.accept_tcp(&mut rng, 0).unwrap();

    // Create a corresponding client
    let client_config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    let mut client = milli_http::https1::Https1Client::<Aes128GcmProvider, 32768>::new(
        Aes128GcmProvider,
        client_config,
        [0xAA; 32],
        [0xBB; 32],
    );

    // Run TLS handshake: client↔manager
    for _ in 0..20 {
        let mut buf = [0u8; 32768];
        let mut progress = false;

        // Client → Manager
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
            progress = true;
        }

        // Manager → Client
        let mut buf2 = [0u8; 32768];
        while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }

        if !progress {
            break;
        }
    }

    // Client should be established
    assert!(
        client.is_established(),
        "client TLS handshake should complete"
    );

    let mut scratch = [0u8; 2048];

    // Manager should emit Connected event
    let mut got_connected = false;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if matches!(ev, ServerEvent::Connected(id) if id == conn_id) {
            got_connected = true;
            break;
        }
    }
    assert!(got_connected, "manager should emit Connected event");

    // Client sends HTTP/1.1 request
    let stream_id = client
        .send_request("GET", "/hello", "test.local", &[], true)
        .unwrap();

    // Transfer request: client → manager
    let mut buf = [0u8; 32768];
    while let Some(data) = client.poll_output(&mut buf) {
        let copy = data.to_vec();
        manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
    }

    // Manager should have request headers event
    let mut got_headers = false;
    let mut header_stream = 0u64;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if let ServerEvent::Http {
            conn,
            event: HttpEvent::Headers(sid),
        } = ev
        {
            if conn == conn_id {
                got_headers = true;
                header_stream = sid;
            }
        }
    }
    assert!(got_headers, "manager should receive HTTP headers");

    // Read headers through manager
    let mut method = Vec::new();
    manager
        .recv_headers(conn_id, header_stream, &mut |name: &[u8], value: &[u8]| {
            if name == b":method" {
                method.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"GET");

    // Send response through manager
    manager
        .send_response(
            conn_id,
            header_stream,
            200,
            &[(b"content-length", b"5")],
            false,
        )
        .unwrap();
    manager
        .send_body(conn_id, header_stream, b"Hello", true)
        .unwrap();

    // Transfer response: manager → client
    let mut buf2 = [0u8; 32768];
    while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
        let copy = data.to_vec();
        client.feed_data(&copy).unwrap();
    }

    // Client reads response
    let mut got_resp = false;
    while let Some(ev) = client.poll_event() {
        if let milli_http::http1::connection::Http1Event::Headers(sid) = ev {
            if sid == stream_id {
                got_resp = true;
            }
        }
    }
    assert!(got_resp, "client should receive response headers");

    // Read status
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    // Read body
    let mut body = [0u8; 64];
    let (n, _fin) = client.recv_body(stream_id, &mut body).unwrap();
    assert_eq!(&body[..n], b"Hello");
}

// -----------------------------------------------------------------------
// H2 over TLS tests
// -----------------------------------------------------------------------

#[test]
fn tcp_handshake_h2_negotiation() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x20);

    let conn_id = manager.accept_tcp(&mut rng, 0).unwrap();

    // Create H2 client
    let client_config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    let mut client = milli_http::h2_tls::H2TlsClient::<Aes128GcmProvider, 32768>::new(
        Aes128GcmProvider,
        client_config,
        [0xCC; 32],
        [0xDD; 32],
    );

    // Run TLS + H2 handshake
    for _ in 0..20 {
        let mut buf = [0u8; 32768];
        let mut progress = false;

        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
            progress = true;
        }

        let mut buf2 = [0u8; 32768];
        while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }

        if !progress {
            break;
        }
    }

    assert!(client.is_established(), "H2 client should be established");

    let mut scratch = [0u8; 2048];

    // Check manager emitted Connected
    let mut got_connected = false;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if matches!(ev, ServerEvent::Connected(id) if id == conn_id) {
            got_connected = true;
        }
    }
    assert!(got_connected, "manager should emit Connected for H2");
}

// -----------------------------------------------------------------------
// UDP/QUIC tests
// -----------------------------------------------------------------------

/// Helper: exchange UDP packets between an H3Client and ServerManager.
fn exchange_udp<const STREAM_BUF: usize, const H3_DATA_BUF: usize>(
    client: &mut milli_http::h3::client::H3Client<
        Aes128GcmProvider,
        32,
        128,
        4,
        STREAM_BUF,
        16,
        512,
        H3_DATA_BUF,
    >,
    manager: &mut ServerManager<Aes128GcmProvider, u32>,
    peer_addr: u32,
    now: u64,
    rng: &mut TestRng,
    pool: &mut HandshakePool<Aes128GcmProvider, 4>,
) {
    for _ in 0..20 {
        let mut any_sent = false;

        // Client → Manager
        loop {
            let mut buf = [0u8; 4096];
            match client.poll_transmit(&mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let _ = manager.udp_feed::<4096>(&data, peer_addr, now, rng, pool);
                    any_sent = true;
                }
                None => break,
            }
        }

        // Manager → Client
        loop {
            let mut buf = [0u8; 4096];
            match manager.udp_poll_transmit::<4096>(&mut buf, now, pool) {
                Some((_addr, len)) => {
                    let data = buf[..len].to_vec();
                    let mut scratch = [0u8; 4096];
                    let _ = client.recv::<4096>(&data, &mut scratch, now, pool);
                    any_sent = true;
                }
                None => break,
            }
        }

        if !any_sent {
            break;
        }
    }
}

fn make_h3_server_config(cert: &'static [u8]) -> ServerTlsConfig {
    ServerTlsConfig {
        cert_der: cert,
        private_key_der: Box::leak(Box::new(TEST_SEED)),
        alpn_protocols: &[b"h3"],
        transport_params: TransportParams::default_params(),
    }
}

#[test]
fn udp_quic_handshake_and_h3_request() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x30);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    // Create H3 client
    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut client: milli_http::h3::client::H3Client<Aes128GcmProvider> =
        milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 42;
    let now = 1_000_000u64;
    let mut scratch = [0u8; 2048];

    // Run QUIC handshake + H3 setup.
    // H3 control stream setup is triggered by poll_event(), so we must
    // interleave packet exchange with event polling on both sides.
    let mut client_connected = false;
    let mut conn_id = None;
    for _ in 0..20 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );

        // Poll manager events (triggers H3 setup when QUIC handshake completes)
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                conn,
                event: HttpEvent::Connected,
            } = ev
            {
                conn_id = Some(conn);
            }
        }

        // Poll client events
        while let Some(ev) = client.poll_event(&mut scratch) {
            if ev == milli_http::h3::H3Event::Connected {
                client_connected = true;
            }
        }

        if client_connected && conn_id.is_some() {
            break;
        }
    }
    assert!(client_connected, "H3 client should be connected");
    let conn_id = conn_id.expect("manager should emit Connected for QUIC connection");

    // Client sends GET request
    let stream_id = client
        .send_request("GET", "/hello", "test.local", &[], false)
        .unwrap();
    client.send_body(stream_id, &[], true).unwrap();

    // Exchange so manager receives request
    exchange_udp(
        &mut client,
        &mut manager,
        peer_addr,
        now,
        &mut rng,
        &mut pool,
    );

    // Manager should have Headers event
    let mut got_headers = false;
    let mut header_stream = 0u64;
    for _ in 0..10 {
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                conn,
                event: HttpEvent::Headers(sid),
            } = ev
            {
                if conn == conn_id {
                    got_headers = true;
                    header_stream = sid;
                }
            }
        }
        if got_headers {
            break;
        }
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
    }
    assert!(got_headers, "manager should receive H3 request headers");

    // Read request headers through manager
    let mut method = Vec::new();
    let mut path = Vec::new();
    manager
        .recv_headers(conn_id, header_stream, &mut |name: &[u8], value: &[u8]| {
            if name == b":method" {
                method.extend_from_slice(value);
            }
            if name == b":path" {
                path.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"GET");
    assert_eq!(path, b"/hello");

    // Send response through manager
    manager
        .send_response(
            conn_id,
            header_stream,
            200,
            &[(b"content-length", b"5")],
            false,
        )
        .unwrap();
    manager
        .send_body(conn_id, header_stream, b"Hello", true)
        .unwrap();

    // Exchange so client receives response
    exchange_udp(
        &mut client,
        &mut manager,
        peer_addr,
        now,
        &mut rng,
        &mut pool,
    );

    // Client reads response
    let mut got_resp = false;
    for _ in 0..10 {
        while let Some(ev) = client.poll_event(&mut scratch) {
            if let milli_http::h3::H3Event::Headers(sid) = ev {
                if sid == stream_id {
                    got_resp = true;
                }
            }
        }
        if got_resp {
            break;
        }
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
    }
    assert!(got_resp, "client should receive response headers");

    // Read status
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    // Read body
    let mut body = [0u8; 64];
    // May need another exchange for Data frame
    exchange_udp(
        &mut client,
        &mut manager,
        peer_addr,
        now,
        &mut rng,
        &mut pool,
    );
    while let Some(_) = client.poll_event(&mut scratch) {} // drain events
    let (n, _fin) = client.recv_body(stream_id, &mut body).unwrap();
    assert_eq!(&body[..n], b"Hello");
}

// -----------------------------------------------------------------------
// Lifecycle tests
// -----------------------------------------------------------------------

#[test]
fn close_tcp_connection() {
    let cert: &'static [u8] = test_cert_der().leak();
    let config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, config, ServerConfig::default());
    let mut rng = TestRng(0x40);

    let id = manager.accept_tcp(&mut rng, 0).unwrap();
    assert!(!manager.is_closed(id));

    manager.close(id).unwrap();
    assert!(manager.is_closed(id));

    let mut scratch = [0u8; 2048];

    // Should emit Closed event
    let mut got_closed = false;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if matches!(ev, ServerEvent::Closed(cid) if cid == id) {
            got_closed = true;
        }
    }
    assert!(got_closed, "manager should emit Closed event");
}

#[test]
fn unknown_connection_returns_error() {
    let cert: &'static [u8] = test_cert_der().leak();
    let config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, config, ServerConfig::default());

    let fake_id = milli_http::server::ConnId(999);
    assert!(manager.close(fake_id).is_err());
    assert!(manager.tcp_feed(fake_id, &[0], 0).is_err());
    assert!(manager.is_closed(fake_id)); // not found = closed
}

/// Cleartext (non-TLS) HTTP/1.1 over the manager: `accept_tcp_cleartext` starts
/// the connection established, raw HTTP/1.1 bytes route through the same event
/// stream, and the response comes back as plaintext. This is the path used for
/// dual HTTP/HTTPS serving alongside the TLS `accept_tcp`.
#[cfg(feature = "http1")]
#[test]
fn tcp_cleartext_http1_request() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());

    // Cleartext accept: no TLS handshake, no rng — established immediately.
    let conn_id = manager.accept_tcp_cleartext(0).unwrap();

    let mut scratch = [0u8; 2048];

    // Cleartext accept emits Connected right away.
    let mut got_connected = false;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if matches!(ev, ServerEvent::Connected(id) if id == conn_id) {
            got_connected = true;
        }
    }
    assert!(got_connected, "cleartext accept should emit Connected");

    // Feed a raw plaintext HTTP/1.1 request.
    manager
        .tcp_feed(
            conn_id,
            b"GET /hello HTTP/1.1\r\nHost: test.local\r\n\r\n",
            1_000_000,
        )
        .unwrap();

    // Manager surfaces request headers through the unified event stream.
    let mut header_stream = None;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if let ServerEvent::Http {
            conn,
            event: HttpEvent::Headers(sid),
        } = ev
        {
            if conn == conn_id {
                header_stream = Some(sid);
            }
        }
    }
    let header_stream = header_stream.expect("manager should receive cleartext HTTP headers");

    let mut method = Vec::new();
    manager
        .recv_headers(conn_id, header_stream, &mut |name: &[u8], value: &[u8]| {
            if name == b":method" {
                method.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"GET");

    // Response goes back out as plaintext HTTP/1.1 (no TLS records).
    manager
        .send_response(
            conn_id,
            header_stream,
            200,
            &[(b"content-length", b"2")],
            false,
        )
        .unwrap();
    manager
        .send_body(conn_id, header_stream, b"ok", true)
        .unwrap();

    let mut out = Vec::new();
    let mut buf = [0u8; 32768];
    while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf) {
        out.extend_from_slice(data);
    }
    let text = core::str::from_utf8(&out).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"), "got: {text}");
    assert!(text.ends_with("ok"), "got: {text}");
}

// -----------------------------------------------------------------------
// Streaming (SSE-style) response tests
//
// A server-sent-events response is `200` with `content-type:
// text/event-stream`, no content-length, `end_stream = false`, followed by
// body frames pushed incrementally as application events occur. These tests
// prove each frame is deliverable (and observable by the client) *before*
// the next one exists, on all three protocol paths.
// -----------------------------------------------------------------------

const SSE_HEADERS: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];

#[test]
fn tcp_http1_streaming_response() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x50);

    let conn_id = manager.accept_tcp(&mut rng, 0).unwrap();

    let client_config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    let mut client = milli_http::https1::Https1Client::<Aes128GcmProvider, 32768>::new(
        Aes128GcmProvider,
        client_config,
        [0xAA; 32],
        [0xBB; 32],
    );

    // TLS handshake
    for _ in 0..20 {
        let mut buf = [0u8; 32768];
        let mut progress = false;
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
            progress = true;
        }
        let mut buf2 = [0u8; 32768];
        while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }
        if !progress {
            break;
        }
    }
    assert!(client.is_established());

    let mut scratch = [0u8; 2048];
    while manager.poll_event(&mut scratch).is_some() {}

    // Subscribe
    let stream_id = client
        .send_request("GET", "/events", "test.local", &[], true)
        .unwrap();
    let mut buf = [0u8; 32768];
    while let Some(data) = client.poll_output(&mut buf) {
        let copy = data.to_vec();
        manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
    }
    let mut header_stream = None;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if let ServerEvent::Http {
            event: HttpEvent::Headers(sid),
            ..
        } = ev
        {
            header_stream = Some(sid);
        }
    }
    let header_stream = header_stream.expect("request headers");

    // Open the stream: no content-length, not finished.
    manager
        .send_response(conn_id, header_stream, 200, SSE_HEADERS, false)
        .unwrap();
    let mut buf2 = [0u8; 32768];
    while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
        let copy = data.to_vec();
        client.feed_data(&copy).unwrap();
    }
    while client.poll_event().is_some() {}
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    // Push frames one at a time; each must arrive before the next is sent.
    for i in 0..3u32 {
        let frame = format!("event: volume\ndata: {i}\n\n");
        manager
            .send_body(conn_id, header_stream, frame.as_bytes(), false)
            .unwrap();
        let mut buf3 = [0u8; 32768];
        while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf3) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
        }
        while client.poll_event().is_some() {}
        let mut body = [0u8; 256];
        let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(
            core::str::from_utf8(&body[..n]).unwrap(),
            frame,
            "frame {i} should arrive incrementally"
        );
        assert!(!fin, "stream must stay open after frame {i}");
    }

    // SSE streams over HTTP/1.1 end by closing the connection.
    manager.close(conn_id).unwrap();
}

#[test]
fn tcp_h2_streaming_response() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, (), 32768> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x60);

    let conn_id = manager.accept_tcp(&mut rng, 0).unwrap();

    let client_config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    let mut client = milli_http::h2_tls::H2TlsClient::<Aes128GcmProvider, 32768>::new(
        Aes128GcmProvider,
        client_config,
        [0xCC; 32],
        [0xDD; 32],
    );

    // TLS + H2 handshake
    for _ in 0..20 {
        let mut buf = [0u8; 32768];
        let mut progress = false;
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
            progress = true;
        }
        let mut buf2 = [0u8; 32768];
        while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }
        if !progress {
            break;
        }
    }
    assert!(client.is_established());

    let mut scratch = [0u8; 2048];
    while manager.poll_event(&mut scratch).is_some() {}
    while client.poll_event().is_some() {}

    // Subscribe
    let stream_id = client
        .send_request("GET", "/events", "test.local", &[], true)
        .unwrap();
    let mut buf = [0u8; 32768];
    while let Some(data) = client.poll_output(&mut buf) {
        let copy = data.to_vec();
        manager.tcp_feed(conn_id, &copy, 1_000_000).unwrap();
    }
    let mut header_stream = None;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if let ServerEvent::Http {
            event: HttpEvent::Headers(sid),
            ..
        } = ev
        {
            header_stream = Some(sid);
        }
    }
    let header_stream = header_stream.expect("request headers");

    // Open the stream
    manager
        .send_response(conn_id, header_stream, 200, SSE_HEADERS, false)
        .unwrap();
    let mut buf2 = [0u8; 32768];
    while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf2) {
        let copy = data.to_vec();
        client.feed_data(&copy).unwrap();
    }
    while client.poll_event().is_some() {}
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    // Push frames one at a time
    for i in 0..3u32 {
        let frame = format!("event: volume\ndata: {i}\n\n");
        manager
            .send_body(conn_id, header_stream, frame.as_bytes(), false)
            .unwrap();
        let mut buf3 = [0u8; 32768];
        while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf3) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
        }
        while client.poll_event().is_some() {}
        let mut body = [0u8; 256];
        let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(
            core::str::from_utf8(&body[..n]).unwrap(),
            frame,
            "frame {i} should arrive incrementally"
        );
        assert!(!fin, "stream must stay open after frame {i}");
    }

    // H2 ends the stream cleanly with END_STREAM.
    manager
        .send_body(conn_id, header_stream, &[], true)
        .unwrap();
    let mut buf4 = [0u8; 32768];
    while let Some(data) = manager.tcp_poll_output(conn_id, &mut buf4) {
        let copy = data.to_vec();
        client.feed_data(&copy).unwrap();
    }
    while client.poll_event().is_some() {}
    let mut body = [0u8; 64];
    let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
    assert_eq!(n, 0);
    assert!(fin, "client should observe END_STREAM");
}

#[test]
fn udp_quic_h3_streaming_response() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x70);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut client: milli_http::h3::client::H3Client<Aes128GcmProvider> =
        milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 43;
    let now = 1_000_000u64;
    let mut scratch = [0u8; 2048];

    // QUIC handshake + H3 setup
    let mut client_connected = false;
    let mut conn_id = None;
    for _ in 0..20 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                conn,
                event: HttpEvent::Connected,
            } = ev
            {
                conn_id = Some(conn);
            }
        }
        while let Some(ev) = client.poll_event(&mut scratch) {
            if ev == milli_http::h3::H3Event::Connected {
                client_connected = true;
            }
        }
        if client_connected && conn_id.is_some() {
            break;
        }
    }
    assert!(client_connected);
    let conn_id = conn_id.expect("Connected");

    // Subscribe
    let stream_id = client
        .send_request("GET", "/events", "test.local", &[], false)
        .unwrap();
    client.send_body(stream_id, &[], true).unwrap();

    let mut header_stream = None;
    for _ in 0..10 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                event: HttpEvent::Headers(sid),
                ..
            } = ev
            {
                header_stream = Some(sid);
            }
        }
        if header_stream.is_some() {
            break;
        }
    }
    let header_stream = header_stream.expect("request headers");

    // Open the stream
    manager
        .send_response(conn_id, header_stream, 200, SSE_HEADERS, false)
        .unwrap();
    let mut got_headers = false;
    for _ in 0..10 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(ev) = client.poll_event(&mut scratch) {
            if let milli_http::h3::H3Event::Headers(sid) = ev {
                if sid == stream_id {
                    got_headers = true;
                }
            }
        }
        if got_headers {
            break;
        }
    }
    assert!(got_headers, "client should receive stream headers");
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    // Push frames one at a time
    for i in 0..3u32 {
        let frame = format!("event: volume\ndata: {i}\n\n");
        manager
            .send_body(conn_id, header_stream, frame.as_bytes(), false)
            .unwrap();
        let mut collected = Vec::new();
        for _ in 0..10 {
            exchange_udp(
                &mut client,
                &mut manager,
                peer_addr,
                now,
                &mut rng,
                &mut pool,
            );
            while client.poll_event(&mut scratch).is_some() {}
            let mut body = [0u8; 256];
            if let Ok((n, _fin)) = client.recv_body(stream_id, &mut body) {
                collected.extend_from_slice(&body[..n]);
            }
            if collected.len() >= frame.len() {
                break;
            }
        }
        assert_eq!(
            core::str::from_utf8(&collected).unwrap(),
            frame,
            "frame {i} should arrive incrementally"
        );
    }

    // H3 ends the stream cleanly with FIN.
    manager
        .send_body(conn_id, header_stream, &[], true)
        .unwrap();
    let mut got_fin = false;
    for _ in 0..10 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while client.poll_event(&mut scratch).is_some() {}
        let mut body = [0u8; 64];
        if let Ok((_n, fin)) = client.recv_body(stream_id, &mut body) {
            if fin {
                got_fin = true;
                break;
            }
        }
    }
    assert!(got_fin, "client should observe stream FIN");
}

#[test]
fn udp_initial_fragments_route_to_existing_conn() {
    // A ClientHello large enough to span multiple Initial datagrams (e.g.
    // post-quantum key shares from real ngtcp2/OpenSSL clients) sends every
    // fragment under the client-chosen original DCID — the server hasn't
    // spoken yet, so the client knows no other CID. Each fragment must route
    // to the connection created by the first one; with max_quic_conns: 1 a
    // routing miss surfaces as StreamLimitExhausted (observed live as a
    // handshake that stalls after one ACK).
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> = ServerManager::new(
        Aes128GcmProvider,
        server_config,
        ServerConfig {
            max_quic_conns: 1,
            ..ServerConfig::default()
        },
    );
    let mut rng = TestRng(0x80);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut client: milli_http::h3::client::H3Client<Aes128GcmProvider> =
        milli_http::h3::client::H3Client::new(client_conn);

    // First Initial datagram creates the connection.
    let mut buf = [0u8; 4096];
    let tx = client
        .poll_transmit(&mut buf, 1_000_000, &mut pool)
        .expect("client initial");
    let initial = tx.data.to_vec();
    manager
        .udp_feed::<4096>(&initial, 42, 1_000_000, &mut rng, &mut pool)
        .expect("first initial accepted");

    // A second datagram under the same (client-chosen) DCID — as fragment 2
    // of a multi-datagram flight would be — must route to that connection,
    // not bounce off the connection limit as a new-connection attempt.
    manager
        .udp_feed::<4096>(&initial, 42, 1_001_000, &mut rng, &mut pool)
        .expect("same-DCID datagram must route to the existing connection");
}

#[test]
fn udp_quic_handshake_with_small_transmit_buffer() {
    // The server handshake flight (EE+Cert+CertVerify+Finished) is routinely
    // larger than one UDP datagram, and embedded drivers drain
    // `udp_poll_transmit` through MTU-sized buffers. The CRYPTO stream must
    // split across datagrams — pre-fix, whatever didn't fit the first packet
    // was pulled out of the TLS engine and silently dropped, stalling the
    // handshake after one datagram (observed live against curl/ngtcp2).
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x90);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut client: milli_http::h3::client::H3Client<Aes128GcmProvider> =
        milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 44;
    let now = 1_000_000u64;
    let mut scratch = [0u8; 2048];

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..30 {
        // Client -> manager (client flights are small; 4096 is fine)
        loop {
            let mut buf = [0u8; 4096];
            match client.poll_transmit(&mut buf, now, &mut pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let _ = manager.udp_feed::<4096>(&data, peer_addr, now, &mut rng, &mut pool);
                }
                None => break,
            }
        }
        // Manager -> client through an MTU-sized datagram buffer (what an
        // embedded driver uses): the padded 1200-byte Initial leaves only a
        // few hundred bytes for the coalesced Handshake packet, forcing the
        // server flight to fragment across datagrams.
        loop {
            let mut buf = [0u8; 1500];
            match manager.udp_poll_transmit::<4096>(&mut buf, now, &mut pool) {
                Some((_addr, len)) => {
                    let data = buf[..len].to_vec();
                    let mut s = [0u8; 4096];
                    let _ = client.recv::<4096>(&data, &mut s, now, &mut pool);
                }
                None => break,
            }
        }
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                event: HttpEvent::Connected,
                ..
            } = ev
            {
                server_connected = true;
            }
        }
        while let Some(ev) = client.poll_event(&mut scratch) {
            if ev == milli_http::h3::H3Event::Connected {
                client_connected = true;
            }
        }
        if client_connected && server_connected {
            break;
        }
    }
    assert!(
        client_connected && server_connected,
        "handshake must complete when the server flight is drained through \
         a small transmit buffer (client={client_connected} server={server_connected})"
    );
}

/// Regression: a response body much larger than the per-entry stream
/// buffer (STREAM_BUF = 256 by default) must arrive intact over h3.
///
/// Previously `send_data` encoded the whole body into a single DATA
/// frame, `stream_send` silently queued only the first STREAM_BUF bytes
/// (and recorded the FIN at the truncated offset), and the peer saw a
/// malformed DATA frame — curl killed the connection mid-body when the
/// firmware served its 3.4 KB dev page.
#[test]
fn udp_quic_h3_large_body_response() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0x90);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    // Client with 4 KiB stream/data buffers so the whole body fits in
    // flight (a desktop client like curl buffers far more than this).
    let mut client: milli_http::h3::client::H3Client<
        Aes128GcmProvider,
        32,
        128,
        4,
        4096,
        16,
        512,
        4096,
    > = milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 77;
    let now = 1_000_000u64;
    let mut scratch = [0u8; 4096];

    // Handshake + H3 setup.
    let mut client_connected = false;
    let mut conn_id = None;
    for _ in 0..20 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                conn,
                event: HttpEvent::Connected,
            } = ev
            {
                conn_id = Some(conn);
            }
        }
        while let Some(ev) = client.poll_event(&mut scratch) {
            if ev == milli_http::h3::H3Event::Connected {
                client_connected = true;
            }
        }
        if client_connected && conn_id.is_some() {
            break;
        }
    }
    assert!(client_connected, "H3 client should be connected");
    let conn_id = conn_id.expect("manager should emit Connected");

    // Request.
    let stream_id = client
        .send_request("GET", "/big", "test.local", &[], false)
        .unwrap();
    client.send_body(stream_id, &[], true).unwrap();

    let mut header_stream = None;
    for _ in 0..10 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                event: HttpEvent::Headers(sid),
                ..
            } = ev
            {
                header_stream = Some(sid);
            }
        }
        if header_stream.is_some() {
            break;
        }
    }
    let header_stream = header_stream.expect("manager should receive request headers");

    // Respond with a 3.5 KB patterned body, the size class of the
    // firmware's gzipped dev page.
    let body: Vec<u8> = (0..3500usize).map(|i| (i % 251) as u8).collect();
    manager
        .send_response(
            conn_id,
            header_stream,
            200,
            &[(b"content-length", b"3500")],
            false,
        )
        .unwrap();

    // send_body may accept only part of the body per call; loop,
    // draining packets between calls, until everything is queued.
    let mut offset = 0;
    let mut received = Vec::new();
    let mut got_fin = false;
    for _ in 0..50 {
        if offset < body.len() {
            let n = manager
                .send_body(conn_id, header_stream, &body[offset..], true)
                .unwrap();
            offset += n;
        }
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(_) = client.poll_event(&mut scratch) {}

        // Drain whatever body bytes have arrived at the client.
        loop {
            let mut chunk = [0u8; 512];
            match client.recv_body(stream_id, &mut chunk) {
                Ok((n, fin)) => {
                    received.extend_from_slice(&chunk[..n]);
                    if fin {
                        got_fin = true;
                    }
                    if n == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if got_fin {
            break;
        }
    }

    assert_eq!(offset, body.len(), "all body bytes should be accepted");
    assert!(got_fin, "client should see end of stream");
    assert_eq!(received.len(), body.len(), "body length must match");
    assert_eq!(received, body, "body must arrive intact");
}

/// Regression: a QUIC handshake that never completes must be reaped at the
/// handshake deadline, releasing both the conn slot and the handshake pool
/// slot.
///
/// Previously a stalled handshake (e.g. the server flight was dropped by the
/// network and the client gave up) pinned the conn slot and its handshake
/// pool slot forever — with max_quic_conns=1 the server silently ignored
/// every subsequent connection attempt until reboot.
#[test]
fn stalled_quic_handshake_is_reaped_and_releases_pool_slot() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> = ServerManager::new(
        Aes128GcmProvider,
        server_config,
        ServerConfig {
            max_quic_conns: 1,
            ..ServerConfig::default()
        },
    );
    let mut rng = TestRng(0xA0);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();
    let now = 1_000_000u64;

    // Client sends its Initial flight; the manager processes it (claiming a
    // handshake slot) but its response is never delivered, so the handshake
    // can never complete.
    let mut client_conn: milli_http::Connection<Aes128GcmProvider> =
        milli_http::Connection::client(
            Aes128GcmProvider,
            "test.local",
            &[b"h3"],
            TransportParams::default_params(),
            &mut rng,
            &mut pool,
        )
        .unwrap();
    let mut sio = milli_http::connection::io::QuicStreamIoBufs::<32, 1024, 16>::new();
    let mut buf = [0u8; 4096];
    while let Some(tx) = client_conn.poll_transmit(&mut sio.as_io(), &mut buf, now, &mut pool) {
        let data = tx.data.to_vec();
        manager
            .udp_feed::<4096>(&data, 7u32, now, &mut rng, &mut pool)
            .unwrap();
    }
    assert_eq!(pool.slots_in_use(), 2, "client + stalled server handshake");

    // Before the deadline: the conn stays.
    manager.handle_timeouts::<4096>(now + 1_000_000, &mut pool);
    assert_eq!(pool.slots_in_use(), 2);

    // Past the deadline (default 10 s): reaped, slot released, Closed emitted.
    manager.handle_timeouts::<4096>(now + 10_000_001, &mut pool);
    assert_eq!(pool.slots_in_use(), 1, "server handshake slot released");
    let mut scratch = [0u8; 2048];
    let mut got_closed = false;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if matches!(ev, ServerEvent::Closed(_)) {
            got_closed = true;
        }
    }
    assert!(got_closed, "reaped conn should emit Closed");

    // The conn slot is free again: a new connection attempt is accepted
    // rather than bouncing off max_quic_conns.
    let mut client2: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut sio2 = milli_http::connection::io::QuicStreamIoBufs::<32, 1024, 16>::new();
    let later = now + 11_000_000;
    while let Some(tx) = client2.poll_transmit(&mut sio2.as_io(), &mut buf, later, &mut pool) {
        let data = tx.data.to_vec();
        manager
            .udp_feed::<4096>(&data, 8u32, later, &mut rng, &mut pool)
            .expect("new connection must be accepted after reaping");
    }
}

/// Regression: an established QUIC connection whose peer disappears without
/// a CONNECTION_CLOSE must be reaped by the idle timeout (RFC 9000 §10.1).
///
/// Previously `idle_timeout` was never wired from the negotiated
/// max_idle_timeout transport params, so abandoned connections lived forever.
#[test]
fn idle_quic_connection_is_reaped() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0xB0);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut client: milli_http::h3::client::H3Client<Aes128GcmProvider> =
        milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 9;
    let now = 1_000_000u64;
    let mut scratch = [0u8; 2048];

    // Complete the handshake.
    let mut conn_id = None;
    for _ in 0..20 {
        exchange_udp(
            &mut client,
            &mut manager,
            peer_addr,
            now,
            &mut rng,
            &mut pool,
        );
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                conn,
                event: HttpEvent::Connected,
            } = ev
            {
                conn_id = Some(conn);
            }
        }
        while let Some(_) = client.poll_event(&mut scratch) {}
        if conn_id.is_some() {
            break;
        }
    }
    let conn_id = conn_id.expect("handshake should complete");

    // Idle for less than the negotiated 30 s: conn stays.
    manager.handle_timeouts::<4096>(now + 10_000_000, &mut pool);
    assert!(!manager.is_closed(conn_id));

    // Idle past it: reaped with a Closed event.
    manager.handle_timeouts::<4096>(now + 31_000_000, &mut pool);
    let mut got_closed = false;
    while let Some(ev) = manager.poll_event(&mut scratch) {
        if matches!(ev, ServerEvent::Closed(id) if id == conn_id) {
            got_closed = true;
        }
    }
    assert!(got_closed, "idle conn should be reaped with Closed event");
}

/// Regression: a lost server flight must be retransmitted on PTO.
///
/// This replays the field failure: the server's Initial+Handshake flight is
/// dropped by the network (on hardware, a neighbor-cache miss ate it), while
/// the client keeps retransmitting its Initial. Previously the server never
/// re-sent CRYPTO data — one lost flight deadlocked the handshake forever.
#[test]
fn lost_server_flight_is_retransmitted_on_pto() {
    let cert: &'static [u8] = test_cert_der().leak();
    let server_config = make_h3_server_config(cert);
    let mut manager: ServerManager<Aes128GcmProvider, u32> =
        ServerManager::new(Aes128GcmProvider, server_config, ServerConfig::default());
    let mut rng = TestRng(0xC0);
    let mut pool: HandshakePool<Aes128GcmProvider, 4> = HandshakePool::new();

    let client_conn: milli_http::Connection<Aes128GcmProvider> = milli_http::Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        &mut pool,
    )
    .unwrap();
    let mut client: milli_http::h3::client::H3Client<Aes128GcmProvider> =
        milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 13;
    let t0 = 1_000_000u64;
    let mut scratch = [0u8; 4096];

    // Client sends its Initial; the manager processes it and queues its
    // flight.
    let mut ch_datagram = Vec::new();
    {
        let mut buf = [0u8; 4096];
        while let Some(tx) = client.poll_transmit(&mut buf, t0, &mut pool) {
            ch_datagram = tx.data.to_vec();
            manager
                .udp_feed::<4096>(&ch_datagram, peer_addr, t0, &mut rng, &mut pool)
                .unwrap();
        }
    }
    assert!(!ch_datagram.is_empty());

    // The server's flight is LOST: drain its transmits into the void.
    let mut lost = 0;
    {
        let mut buf = [0u8; 4096];
        while let Some((_addr, len)) = manager.udp_poll_transmit::<4096>(&mut buf, t0, &mut pool) {
            lost += len;
        }
    }
    assert!(
        lost > 1000,
        "server should have sent a flight (got {lost} B)"
    );

    // ~1 s later the client retransmits its Initial (as curl does). This
    // also feeds the server's anti-amplification budget.
    let t1 = t0 + 1_000_000;
    manager
        .udp_feed::<4096>(&ch_datagram, peer_addr, t1, &mut rng, &mut pool)
        .unwrap();

    // PTO fires.
    let t2 = t0 + 2_000_000;
    manager.handle_timeouts::<4096>(t2, &mut pool);

    // The server must now retransmit its flight; deliver it this time and
    // run the exchange to completion.
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..20 {
        let mut retransmitted = 0;
        {
            let mut buf = [0u8; 4096];
            while let Some((_addr, len)) =
                manager.udp_poll_transmit::<4096>(&mut buf, t2, &mut pool)
            {
                retransmitted += len;
                let data = buf[..len].to_vec();
                let mut rx_scratch = [0u8; 4096];
                let _ = client.recv::<4096>(&data, &mut rx_scratch, t2, &mut pool);
            }
        }
        {
            let mut buf = [0u8; 4096];
            while let Some(tx) = client.poll_transmit(&mut buf, t2, &mut pool) {
                let data = tx.data.to_vec();
                let _ = manager.udp_feed::<4096>(&data, peer_addr, t2, &mut rng, &mut pool);
            }
        }
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http {
                event: HttpEvent::Connected,
                ..
            } = ev
            {
                server_connected = true;
            }
        }
        while let Some(ev) = client.poll_event(&mut scratch) {
            if ev == milli_http::h3::H3Event::Connected {
                client_connected = true;
            }
        }
        if client_connected && server_connected {
            break;
        }
        let _ = retransmitted;
    }

    assert!(
        client_connected && server_connected,
        "handshake must complete after the lost flight is retransmitted on PTO \
         (client={client_connected} server={server_connected})"
    );
}
