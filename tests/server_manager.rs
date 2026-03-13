//! ServerManager integration tests.
//!
//! Tests the pure-logic connection manager with TCP (TLS→HTTP) and UDP (QUIC→H3).

#![cfg(feature = "server")]

use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::connection::HandshakePool;
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
    assert!(client.is_established(), "client TLS handshake should complete");

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
        if let ServerEvent::Http { conn, event: HttpEvent::Headers(sid) } = ev {
            if conn == conn_id {
                got_headers = true;
                header_stream = sid;
            }
        }
    }
    assert!(got_headers, "manager should receive HTTP headers");

    // Read headers through manager
    let mut method = Vec::new();
    manager.recv_headers(conn_id, header_stream, &mut |name: &[u8], value: &[u8]| {
        if name == b":method" {
            method.extend_from_slice(value);
        }
    }).unwrap();
    assert_eq!(method, b"GET");

    // Send response through manager
    manager.send_response(conn_id, header_stream, 200, &[(b"content-length", b"5")], false).unwrap();
    manager.send_body(conn_id, header_stream, b"Hello", true).unwrap();

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
    client.recv_headers(stream_id, |name, value| {
        if name == b":status" {
            status.extend_from_slice(value);
        }
    }).unwrap();
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
fn exchange_udp(
    client: &mut milli_http::h3::client::H3Client<Aes128GcmProvider>,
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
    ).unwrap();
    let mut client = milli_http::h3::client::H3Client::new(client_conn);

    let peer_addr: u32 = 42;
    let now = 1_000_000u64;
    let mut scratch = [0u8; 2048];

    // Run QUIC handshake + H3 setup.
    // H3 control stream setup is triggered by poll_event(), so we must
    // interleave packet exchange with event polling on both sides.
    let mut client_connected = false;
    let mut conn_id = None;
    for _ in 0..20 {
        exchange_udp(&mut client, &mut manager, peer_addr, now, &mut rng, &mut pool);

        // Poll manager events (triggers H3 setup when QUIC handshake completes)
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http { conn, event: HttpEvent::Connected } = ev {
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
    exchange_udp(&mut client, &mut manager, peer_addr, now, &mut rng, &mut pool);

    // Manager should have Headers event
    let mut got_headers = false;
    let mut header_stream = 0u64;
    for _ in 0..10 {
        while let Some(ev) = manager.poll_event(&mut scratch) {
            if let ServerEvent::Http { conn, event: HttpEvent::Headers(sid) } = ev {
                if conn == conn_id {
                    got_headers = true;
                    header_stream = sid;
                }
            }
        }
        if got_headers { break; }
        exchange_udp(&mut client, &mut manager, peer_addr, now, &mut rng, &mut pool);
    }
    assert!(got_headers, "manager should receive H3 request headers");

    // Read request headers through manager
    let mut method = Vec::new();
    let mut path = Vec::new();
    manager.recv_headers(conn_id, header_stream, &mut |name: &[u8], value: &[u8]| {
        if name == b":method" { method.extend_from_slice(value); }
        if name == b":path" { path.extend_from_slice(value); }
    }).unwrap();
    assert_eq!(method, b"GET");
    assert_eq!(path, b"/hello");

    // Send response through manager
    manager.send_response(conn_id, header_stream, 200, &[(b"content-length", b"5")], false).unwrap();
    manager.send_body(conn_id, header_stream, b"Hello", true).unwrap();

    // Exchange so client receives response
    exchange_udp(&mut client, &mut manager, peer_addr, now, &mut rng, &mut pool);

    // Client reads response
    let mut got_resp = false;
    for _ in 0..10 {
        while let Some(ev) = client.poll_event(&mut scratch) {
            if let milli_http::h3::H3Event::Headers(sid) = ev {
                if sid == stream_id { got_resp = true; }
            }
        }
        if got_resp { break; }
        exchange_udp(&mut client, &mut manager, peer_addr, now, &mut rng, &mut pool);
    }
    assert!(got_resp, "client should receive response headers");

    // Read status
    let mut status = Vec::new();
    client.recv_headers(stream_id, |name, value| {
        if name == b":status" { status.extend_from_slice(value); }
    }).unwrap();
    assert_eq!(status, b"200");

    // Read body
    let mut body = [0u8; 64];
    // May need another exchange for Data frame
    exchange_udp(&mut client, &mut manager, peer_addr, now, &mut rng, &mut pool);
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
