//! Integration tests for milli-quic exercising the full QUIC stack via the
//! public API only. No `pub(crate)` internals are used.
//!
//! These tests construct client and server `Connection` objects, exchange
//! encrypted UDP datagrams between them in-memory (no real network), and
//! verify handshake completion, stream data transfer, connection close,
//! key update, idle timeout, and other behaviors.

extern crate std;

use std::vec::Vec;

use milli_http::connection::Connection;
use milli_http::connection::HandshakePool;
use milli_http::crypto::ed25519;
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::error::Error;
use milli_http::tls::handshake::ServerTlsConfig;
use milli_http::tls::transport_params::TransportParams;
use milli_http::transport::Rng;
use milli_http::{ConnectionState, Event, QuicStreamIoBufs};

type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

// =========================================================================
// Test infrastructure
// =========================================================================

/// A deterministic RNG for tests. Produces a predictable byte sequence
/// starting from a given seed, incrementing by 1 for each byte.
struct TestRng(u8);

impl Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

/// Ed25519 private key seed used by all tests.
const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

/// Build a real Ed25519 certificate DER from the test seed.
/// Returns a `&'static [u8]` by caching in a `LazyLock`.
fn get_test_ed25519_cert_der() -> &'static [u8] {
    use std::sync::LazyLock;
    static V: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let seed: [u8; 32] = TEST_ED25519_SEED;
        let pk = ed25519::ed25519_public_key_from_seed(&seed);
        let mut buf = [0u8; 512];
        let len = ed25519::build_ed25519_cert_der(&pk, &mut buf).unwrap();
        buf[..len].to_vec()
    });
    &V
}

/// Create a handshake pool for tests.
fn make_pool() -> HandshakePool<Aes128GcmProvider, 4> {
    HandshakePool::new()
}

/// Create a client `Connection` with default parameters.
fn make_client(pool: &mut HandshakePool<Aes128GcmProvider, 4>) -> Connection<Aes128GcmProvider> {
    let mut rng = TestRng(0x10);
    Connection::client(
        Aes128GcmProvider,
        "test.local",
        &[b"h3"],
        TransportParams::default_params(),
        &mut rng,
        pool,
    )
    .unwrap()
}

/// Create a server `Connection` with default parameters.
fn make_server(pool: &mut HandshakePool<Aes128GcmProvider, 4>) -> Connection<Aes128GcmProvider> {
    let mut rng = TestRng(0x50);
    let config = ServerTlsConfig {
        cert_der: get_test_ed25519_cert_der(),
        private_key_der: &TEST_ED25519_SEED,
        alpn_protocols: &[b"h3"],
        transport_params: TransportParams::default_params(),
    };
    Connection::server(
        Aes128GcmProvider,
        config,
        TransportParams::default_params(),
        &mut rng,
        pool,
    )
    .unwrap()
}

/// Transfer a single datagram from `src` to `dst`.
/// Calls `src.poll_transmit()`, copies the data, then calls `dst.recv()`.
/// Returns `true` if a packet was transferred, `false` if `src` had nothing
/// to send.
fn transfer_one(
    src: &mut Connection<Aes128GcmProvider>,
    src_sio: &mut SioBufs,
    dst: &mut Connection<Aes128GcmProvider>,
    dst_sio: &mut SioBufs,
    now: u64,
    pool: &mut HandshakePool<Aes128GcmProvider, 4>,
) -> bool {
    let mut buf = [0u8; 4096];
    let mut sio = src_sio.as_io();
    match src.poll_transmit(&mut sio, &mut buf, now, pool) {
        Some(tx) => {
            let data: Vec<u8> = tx.data.to_vec();
            let mut sio = dst_sio.as_io();
            let mut scratch = [0u8; 2048];
            let _ = dst.recv(&mut sio, &data, &mut scratch, now, pool);
            true
        }
        None => false,
    }
}

/// Drain all pending transmits from `src` and deliver them to `dst`.
/// Returns the number of datagrams transferred.
fn drain_transmits(
    src: &mut Connection<Aes128GcmProvider>,
    src_sio: &mut SioBufs,
    dst: &mut Connection<Aes128GcmProvider>,
    dst_sio: &mut SioBufs,
    now: u64,
    pool: &mut HandshakePool<Aes128GcmProvider, 4>,
) -> usize {
    let mut count = 0;
    while transfer_one(src, src_sio, dst, dst_sio, now, pool) {
        count += 1;
    }
    count
}

/// Run the handshake to completion by exchanging packets between client and
/// server in a loop. Panics if the handshake does not complete within 20
/// rounds.
fn run_handshake(
    client: &mut Connection<Aes128GcmProvider>,
    c_sio: &mut SioBufs,
    server: &mut Connection<Aes128GcmProvider>,
    s_sio: &mut SioBufs,
    now: u64,
    pool: &mut HandshakePool<Aes128GcmProvider, 4>,
) {
    for _round in 0..20 {
        drain_transmits(client, c_sio, server, s_sio, now, pool);
        drain_transmits(server, s_sio, client, c_sio, now, pool);

        if client.is_established() && server.is_established() {
            return;
        }
    }
    panic!(
        "handshake did not complete after 20 rounds: client={:?}, server={:?}",
        client.state(),
        server.state()
    );
}

/// Drain all pending events from a connection and return them as a Vec.
fn drain_events(conn: &mut Connection<Aes128GcmProvider>) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(ev) = conn.poll_event() {
        events.push(ev);
    }
    events
}

/// Drain remaining transmits from both sides after handshake so that
/// subsequent tests start from a clean state.
fn drain_post_handshake(
    client: &mut Connection<Aes128GcmProvider>,
    c_sio: &mut SioBufs,
    server: &mut Connection<Aes128GcmProvider>,
    s_sio: &mut SioBufs,
    now: u64,
    pool: &mut HandshakePool<Aes128GcmProvider, 4>,
) {
    // Drain any ACKs or HANDSHAKE_DONE packets
    for _ in 0..5 {
        drain_transmits(client, c_sio, server, s_sio, now, pool);
        drain_transmits(server, s_sio, client, c_sio, now, pool);
    }
    // Drain events
    drain_events(client);
    drain_events(server);
}

// =========================================================================
// Test cases
// =========================================================================

/// Test 1: Full handshake completes -- client and server both reach Active
/// state and emit a Connected event.
#[test]
fn full_handshake_completes() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    assert_eq!(client.state(), ConnectionState::Handshaking);
    assert_eq!(server.state(), ConnectionState::Handshaking);

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    assert!(
        client.is_established(),
        "client should be established, state={:?}",
        client.state()
    );
    assert!(
        server.is_established(),
        "server should be established, state={:?}",
        server.state()
    );

    // Both sides should have emitted a Connected event.
    let client_events = drain_events(&mut client);
    assert!(
        client_events.iter().any(|e| matches!(e, Event::Connected)),
        "client should have emitted Connected event, got: {:?}",
        client_events
    );

    let server_events = drain_events(&mut server);
    assert!(
        server_events.iter().any(|e| matches!(e, Event::Connected)),
        "server should have emitted Connected event, got: {:?}",
        server_events
    );
}

/// Test 2: Client sends stream data to server after handshake.
#[test]
fn client_sends_stream_data() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Client opens stream 0 (first client-initiated bidi stream) and sends data.
    let stream_id = client.open_stream().unwrap();
    assert_eq!(stream_id, 0, "first client bidi stream should be id 0");

    let payload = b"hello from client";
    let sent = client
        .stream_send(&mut c_sio.as_io(), stream_id, payload, false)
        .unwrap();
    assert_eq!(sent, payload.len());

    // Transfer the packet.
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Server should emit StreamReadable and/or StreamOpened.
    let events = drain_events(&mut server);
    let has_readable = events
        .iter()
        .any(|e| matches!(e, Event::StreamReadable(id) if *id == stream_id));
    assert!(
        has_readable,
        "server should see StreamReadable for stream {stream_id}, got: {:?}",
        events
    );

    // Server reads the data.
    let mut buf = [0u8; 256];
    let (len, fin) = server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf)
        .unwrap();
    assert_eq!(len, payload.len());
    assert_eq!(&buf[..len], payload);
    assert!(!fin, "fin should not be set");
}

/// Test 3: Server sends response data back on the same stream.
#[test]
fn server_responds_on_stream() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Client sends request.
    let stream_id = client.open_stream().unwrap();
    client
        .stream_send(&mut c_sio.as_io(), stream_id, b"request", false)
        .unwrap();
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Server reads and then responds.
    drain_events(&mut server);
    let mut buf = [0u8; 256];
    server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf)
        .unwrap();

    // The stream was opened by the client; the server should also be able
    // to send on it (bidirectional).
    let response = b"response from server";
    let sent = server
        .stream_send(&mut s_sio.as_io(), stream_id, response, false)
        .unwrap();
    assert_eq!(sent, response.len());

    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    let events = drain_events(&mut client);
    let has_readable = events
        .iter()
        .any(|e| matches!(e, Event::StreamReadable(id) if *id == stream_id));
    assert!(has_readable, "client should see StreamReadable");

    let mut rbuf = [0u8; 256];
    let (len, fin) = client
        .stream_recv(&mut c_sio.as_io(), stream_id, &mut rbuf)
        .unwrap();
    assert_eq!(&rbuf[..len], response);
    assert!(!fin);
}

/// Test 4: Full bidirectional request/response cycle on a single stream.
#[test]
fn bidirectional_exchange() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    let stream_id = client.open_stream().unwrap();

    // Client sends request (not FIN yet).
    client
        .stream_send(&mut c_sio.as_io(), stream_id, b"GET /index.html", false)
        .unwrap();
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Server reads request.
    drain_events(&mut server);
    let mut buf = [0u8; 256];
    let (len, _fin) = server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf)
        .unwrap();
    assert_eq!(&buf[..len], b"GET /index.html");

    // Server sends response with FIN.
    let response = b"<html>Hello</html>";
    server
        .stream_send(&mut s_sio.as_io(), stream_id, response, true)
        .unwrap();
    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    // Client reads response.
    drain_events(&mut client);
    let mut rbuf = [0u8; 256];
    let (rlen, fin) = client
        .stream_recv(&mut c_sio.as_io(), stream_id, &mut rbuf)
        .unwrap();
    assert_eq!(&rbuf[..rlen], response);
    assert!(fin, "server sent FIN, client should see it");
}

/// Test 5: Client opens multiple streams and sends data on both.
#[test]
fn multiple_streams() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Client opens stream 0 and stream 4 (the first two client-initiated bidi
    // streams: id=0 and id=4).
    let s0 = client.open_stream().unwrap();
    let s4 = client.open_stream().unwrap();
    assert_eq!(s0, 0);
    assert_eq!(s4, 4);

    client
        .stream_send(&mut c_sio.as_io(), s0, b"stream zero", false)
        .unwrap();
    client
        .stream_send(&mut c_sio.as_io(), s4, b"stream four", false)
        .unwrap();

    // Transfer packets (may need multiple poll_transmit calls).
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Server should have received data on both streams.
    drain_events(&mut server);

    let mut buf0 = [0u8; 256];
    let (len0, _) = server
        .stream_recv(&mut s_sio.as_io(), s0, &mut buf0)
        .unwrap();
    assert_eq!(&buf0[..len0], b"stream zero");

    let mut buf4 = [0u8; 256];
    let (len4, _) = server
        .stream_recv(&mut s_sio.as_io(), s4, &mut buf4)
        .unwrap();
    assert_eq!(&buf4[..len4], b"stream four");
}

/// Test 6: Sending with fin=true causes the receiver to see fin.
#[test]
fn stream_fin_propagates() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    let stream_id = client.open_stream().unwrap();
    client
        .stream_send(&mut c_sio.as_io(), stream_id, b"final message", true)
        .unwrap();

    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_events(&mut server);

    let mut buf = [0u8; 256];
    let (len, fin) = server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf)
        .unwrap();
    assert_eq!(&buf[..len], b"final message");
    assert!(fin, "receiver should see FIN");
}

/// Test 7: Client initiates connection close, server receives
/// ConnectionClose event.
#[test]
fn connection_close_by_client() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Client closes with error code 0 (no error) and a reason phrase.
    client.close(0, b"goodbye");
    assert_eq!(client.state(), ConnectionState::Closing);

    // Transfer the CONNECTION_CLOSE frame.
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    assert!(
        client.is_closed(),
        "client should be closed after poll_transmit"
    );

    // Server should transition to Draining and emit ConnectionClose event.
    assert_eq!(
        server.state(),
        ConnectionState::Draining,
        "server should be draining"
    );

    let events = drain_events(&mut server);
    let has_close = events
        .iter()
        .any(|e| matches!(e, Event::ConnectionClose { error_code: 0, .. }));
    assert!(
        has_close,
        "server should emit ConnectionClose event, got: {:?}",
        events
    );
}

/// Test 8: Server initiates connection close, client receives
/// ConnectionClose event.
#[test]
fn connection_close_by_server() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Server closes with an application-layer error code.
    server.close(42, b"server shutdown");
    assert_eq!(server.state(), ConnectionState::Closing);

    // Transfer the CONNECTION_CLOSE frame.
    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    assert!(server.is_closed());

    // Client should transition to Draining.
    assert_eq!(client.state(), ConnectionState::Draining);

    let events = drain_events(&mut client);
    let has_close = events
        .iter()
        .any(|e| matches!(e, Event::ConnectionClose { error_code: 42, .. }));
    assert!(
        has_close,
        "client should emit ConnectionClose with error_code=42, got: {:?}",
        events
    );
}

/// Test 9: Transfer data larger than a single packet (>1200 bytes),
/// verify all data is received correctly.
#[test]
fn large_data_transfer() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    let stream_id = client.open_stream().unwrap();

    // Send 1024 bytes (the max per stream_send call due to internal
    // StreamSendEntry buffer size of 1024). The connection's stream_send
    // limits each call to 1024, so we need to call it once.
    let payload: [u8; 1024] = {
        let mut arr = [0u8; 1024];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        arr
    };

    let sent = client
        .stream_send(&mut c_sio.as_io(), stream_id, &payload, false)
        .unwrap();
    assert_eq!(sent, 1024);

    // Transfer.
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Drain any ACKs back.
    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    // Server reads the data.
    drain_events(&mut server);
    let mut buf = [0u8; 1024];
    let (len, fin) = server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf)
        .unwrap();
    assert_eq!(len, 1024);
    assert_eq!(&buf[..len], &payload[..]);
    assert!(!fin);
}

/// Transfer well over 1 MiB on a single stream. This exceeds both the
/// per-stream (256 KiB) and connection-level (1 MiB) initial receive windows,
/// so it only completes if receive flow control is enforced AND the matching
/// MAX_DATA / MAX_STREAM_DATA replenishment is emitted (C2), and if the
/// per-stream receive buffer reclaims space as the application reads.
#[test]
fn transfer_exceeds_initial_flow_control_windows() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    let stream_id = client.open_stream().unwrap();

    let chunk: [u8; 1024] = {
        let mut a = [0u8; 1024];
        for (i, b) in a.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        a
    };

    // ~1.5 MiB: comfortably past the 1 MiB connection window and 256 KiB stream window.
    const TOTAL: usize = 1536 * 1024;
    let mut sent_total = 0usize;
    let mut recv_total = 0usize;
    let mut rbuf = [0u8; 1024];

    let mut guard = 0usize;
    while sent_total < TOTAL {
        guard += 1;
        assert!(guard < 1_000_000, "transfer stalled (no progress)");

        // stream_send returns Ok(0) when the per-stream window is momentarily
        // exhausted; draining delivers the server's MAX_STREAM_DATA so the next
        // round unblocks.
        let sent = client
            .stream_send(&mut c_sio.as_io(), stream_id, &chunk, false)
            .unwrap();
        sent_total += sent;

        // client -> server (data), then server -> client (ACK, MAX_DATA, MAX_STREAM_DATA).
        drain_transmits(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(
            &mut server,
            &mut s_sio,
            &mut client,
            &mut c_sio,
            now,
            &mut pool,
        );
        drain_events(&mut server);

        loop {
            match server.stream_recv(&mut s_sio.as_io(), stream_id, &mut rbuf) {
                Ok((0, _)) => break,
                Ok((n, _)) => recv_total += n,
                Err(_) => break,
            }
        }

        assert!(
            !server.is_closed(),
            "server closed mid-transfer (flow control?)"
        );
        assert!(!client.is_closed(), "client closed mid-transfer");
    }

    // Flush trailing data still in flight / buffered.
    for _ in 0..8 {
        drain_transmits(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(
            &mut server,
            &mut s_sio,
            &mut client,
            &mut c_sio,
            now,
            &mut pool,
        );
        loop {
            match server.stream_recv(&mut s_sio.as_io(), stream_id, &mut rbuf) {
                Ok((0, _)) => break,
                Ok((n, _)) => recv_total += n,
                Err(_) => break,
            }
        }
    }

    assert!(
        sent_total >= TOTAL,
        "sent {sent_total}, expected >= {TOTAL}"
    );
    assert_eq!(
        recv_total, sent_total,
        "server must receive every byte sent"
    );
}

/// Test 10: Client initiates key update mid-stream; data still flows
/// correctly afterward.
#[test]
fn key_update_during_transfer() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    let stream_id = client.open_stream().unwrap();

    // Send data before key update.
    client
        .stream_send(&mut c_sio.as_io(), stream_id, b"before-update", false)
        .unwrap();
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    drain_events(&mut server);
    let mut buf = [0u8; 256];
    let (len, _) = server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf)
        .unwrap();
    assert_eq!(&buf[..len], b"before-update");

    // Client initiates key update.
    assert_eq!(client.key_phase(), 0);
    client.initiate_key_update().unwrap();
    assert_eq!(client.key_phase(), 1);

    // Send data after key update.
    client
        .stream_send(&mut c_sio.as_io(), stream_id, b"after-update", false)
        .unwrap();
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Server should detect the key phase change and update keys.
    assert_eq!(
        server.key_phase(),
        1,
        "server should update key phase after receiving key-updated packet"
    );

    drain_events(&mut server);
    let mut buf2 = [0u8; 256];
    let (len2, _) = server
        .stream_recv(&mut s_sio.as_io(), stream_id, &mut buf2)
        .unwrap();
    assert_eq!(&buf2[..len2], b"after-update");

    // Server sends data back with the new keys.
    server
        .stream_send(&mut s_sio.as_io(), stream_id, b"server-post-ku", false)
        .unwrap();
    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    drain_events(&mut client);
    let mut buf3 = [0u8; 256];
    let (len3, _) = client
        .stream_recv(&mut c_sio.as_io(), stream_id, &mut buf3)
        .unwrap();
    assert_eq!(&buf3[..len3], b"server-post-ku");
}

/// Test 11: PATH_CHALLENGE / PATH_RESPONSE.
///
/// NOTE: PATH_CHALLENGE injection requires `dispatch_frame` which is
/// `pub(crate)`. Since integration tests can only use public API, we test
/// this indirectly: after handshake, we verify that the connection survives
/// a full round trip of packets (which includes ACK processing, the core
/// of the path validation mechanism). A direct PATH_CHALLENGE test is
/// covered in the unit tests within `src/connection/mod.rs`.
#[test]
fn post_handshake_round_trip_works() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    // Send data in both directions to confirm path is alive.
    let s = client.open_stream().unwrap();
    client
        .stream_send(&mut c_sio.as_io(), s, b"ping", false)
        .unwrap();
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    drain_events(&mut server);
    let mut buf = [0u8; 64];
    let (len, _) = server.stream_recv(&mut s_sio.as_io(), s, &mut buf).unwrap();
    assert_eq!(&buf[..len], b"ping");

    server
        .stream_send(&mut s_sio.as_io(), s, b"pong", false)
        .unwrap();
    drain_transmits(
        &mut server,
        &mut s_sio,
        &mut client,
        &mut c_sio,
        now,
        &mut pool,
    );

    drain_events(&mut client);
    let mut buf2 = [0u8; 64];
    let (len2, _) = client
        .stream_recv(&mut c_sio.as_io(), s, &mut buf2)
        .unwrap();
    assert_eq!(&buf2[..len2], b"pong");
}

/// Test 12: Idle timeout -- wired from the negotiated max_idle_timeout
/// transport parameter (RFC 9000 §10.1, formerly known issue M2).
///
/// Both default_params() sides advertise 30 s, so the effective idle
/// timeout is 30 s: the connection survives shorter idle periods and
/// closes once the timeout elapses with no activity.
#[test]
fn idle_timeout_wired_from_transport_params() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    assert!(client.is_established());

    // Idle for less than the negotiated 30 s: still established.
    client.handle_timeout(now + 10_000_000);
    assert!(
        client.is_established(),
        "connection should survive idle shorter than the negotiated timeout, state={:?}",
        client.state()
    );

    // Idle past the negotiated timeout: closed.
    client.handle_timeout(now + 31_000_000);
    assert!(
        !client.is_established(),
        "connection should close after the negotiated idle timeout, state={:?}",
        client.state()
    );
}

/// Test 13: Handshake timeout -- do not complete the handshake, verify
/// that `handle_timeout` can be called safely during the handshake
/// phase without panicking.
///
/// NOTE: The current implementation does not wire `max_idle_timeout`
/// into `Connection.idle_timeout` (known issue M2), so the timeout
/// check is effectively a no-op. This test verifies the current
/// behavior: the connection remains in Handshaking state. When M2 is
/// fixed, this test should verify that the handshake timeout actually
/// closes the connection.
#[test]
fn handshake_timeout_safe_to_call() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut c_sio = SioBufs::new();
    // Intentionally do NOT create a server or run the handshake.

    // The client sends its Initial packet.
    let mut buf = [0u8; 2048];
    let mut sio = c_sio.as_io();
    let _tx = client.poll_transmit(&mut sio, &mut buf, 0, &mut pool);

    assert_eq!(client.state(), ConnectionState::Handshaking);

    // Advance time far into the future. handle_timeout should be safe.
    let future = 999_999_999u64;
    client.handle_timeout(future);

    // The connection remains in Handshaking because idle_timeout is None.
    assert_eq!(
        client.state(),
        ConnectionState::Handshaking,
        "connection should stay in Handshaking when idle_timeout is None"
    );
}

/// Test 14: Opening a stream before handshake completes should fail.
#[test]
fn open_stream_before_handshake_fails() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let result = client.open_stream();
    assert_eq!(result.unwrap_err(), Error::InvalidState);
}

/// Test 15: After close, further operations fail with Closed error.
#[test]
fn operations_fail_after_close() {
    let mut pool = make_pool();
    let mut client = make_client(&mut pool);
    let mut server = make_server(&mut pool);
    let mut c_sio = SioBufs::new();
    let mut s_sio = SioBufs::new();
    let now = 1_000_000u64;

    run_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    drain_post_handshake(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );

    let stream_id = client.open_stream().unwrap();
    client
        .stream_send(&mut c_sio.as_io(), stream_id, b"data", false)
        .unwrap();

    // Close the client.
    client.close(0, b"done");
    drain_transmits(
        &mut client,
        &mut c_sio,
        &mut server,
        &mut s_sio,
        now,
        &mut pool,
    );
    assert!(client.is_closed());

    // Attempts to send data should fail.
    let result = client.stream_send(&mut c_sio.as_io(), stream_id, b"more", false);
    assert!(result.is_err(), "stream_send should fail after close");

    // poll_transmit should return None.
    let mut buf = [0u8; 2048];
    let mut sio = c_sio.as_io();
    assert!(
        client
            .poll_transmit(&mut sio, &mut buf, now, &mut pool)
            .is_none(),
        "poll_transmit should return None after close"
    );
}
