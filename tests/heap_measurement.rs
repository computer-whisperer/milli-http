//! Actual heap measurement using a tracking allocator.
//!
//! This test binary uses a custom global allocator that records current and
//! peak heap usage. Each test creates real protocol instances, runs real
//! handshakes and data flows, and reports measured heap consumption.
//!
//! **Important:** Because `#[global_allocator]` is per-binary, this must be
//! a separate integration test file. Tests run sequentially (not in parallel)
//! to get accurate per-scenario measurements.

#![cfg(all(feature = "alloc", any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]

extern crate alloc;

use core::mem::size_of;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

// ===========================================================================
// Tracking allocator
// ===========================================================================

struct TrackingAllocator {
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    fn reset_peak(&self) {
        self.peak.store(self.current.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn reset_all(&self) {
        // Don't reset current — that tracks live allocations.
        // Reset peak to current so the next scenario starts fresh.
        self.reset_peak();
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let prev = self.current.fetch_add(layout.size(), Ordering::Relaxed);
            let new = prev + layout.size();
            // Update peak (relaxed CAS loop)
            let mut peak = self.peak.load(Ordering::Relaxed);
            while new > peak {
                match self.peak.compare_exchange_weak(peak, new, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(actual) => peak = actual,
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator::new();

// ===========================================================================
// Protocol imports
// ===========================================================================

use milli_http::connection::Connection;
use milli_http::connection::HandshakePool;
use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h3::{H3Client, H3Event, H3Server};
use milli_http::http1::Http1Event;
use milli_http::https1::{Https1Client, Https1Server};
use milli_http::tcp_tls::connection::TlsConnection;
use milli_http::tcp_tls::io::TlsIoBufs;
use milli_http::tls::handshake::{ServerTlsConfig, TlsConfig};
use milli_http::tls::transport_params::TransportParams;
use milli_http::QuicStreamIoBufs;
use milli_http::Rng;

type C = Aes128GcmProvider;

// ===========================================================================
// Test infrastructure
// ===========================================================================

const TEST_SEED: [u8; 32] = [0x01u8; 32];

fn get_test_cert() -> &'static [u8] {
    use std::sync::LazyLock;
    static V: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let pk = ed25519_public_key_from_seed(&TEST_SEED);
        let mut buf = [0u8; 512];
        let n = build_ed25519_cert_der(&pk, &mut buf).unwrap();
        buf[..n].to_vec()
    });
    &V
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

/// Snapshot of allocator state for a measurement window.
struct HeapSnapshot {
    baseline: usize,
    peak: usize,
    current: usize,
}

impl HeapSnapshot {
    /// Start a measurement window. Call `finish()` when done.
    fn begin() -> Self {
        // Force a small allocation to stabilize any lazy init.
        let _v: Vec<u8> = Vec::with_capacity(1);
        drop(_v);

        let baseline = ALLOC.current();
        ALLOC.reset_peak();
        Self {
            baseline,
            peak: 0,
            current: 0,
        }
    }

    fn finish(mut self) -> Self {
        self.peak = ALLOC.peak();
        self.current = ALLOC.current();
        self
    }

    /// Peak heap usage above baseline (bytes allocated at peak minus baseline).
    fn peak_above_baseline(&self) -> usize {
        self.peak.saturating_sub(self.baseline)
    }

    /// Current heap usage above baseline (live allocations minus baseline).
    fn current_above_baseline(&self) -> usize {
        self.current.saturating_sub(self.baseline)
    }
}

// ===========================================================================
// H3 helpers
// ===========================================================================

fn make_pool() -> Box<HandshakePool<C, 4>> {
    Box::new(HandshakePool::new())
}

fn make_quic_client(pool: &mut HandshakePool<C, 4>) -> Connection<C> {
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

fn make_quic_server(pool: &mut HandshakePool<C, 4>) -> Connection<C> {
    let mut rng = TestRng(0x50);
    let config = ServerTlsConfig {
        cert_der: get_test_cert(),
        private_key_der: &TEST_SEED,
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

fn run_quic_handshake(
    client: &mut Connection<C>,
    server: &mut Connection<C>,
    now: u64,
    pool: &mut HandshakePool<C, 4>,
) {
    let mut client_sio = QuicStreamIoBufs::<32, 1024, 16>::new();
    let mut server_sio = QuicStreamIoBufs::<32, 1024, 16>::new();

    for _ in 0..20 {
        loop {
            let mut buf = [0u8; 4096];
            let mut cio = client_sio.as_io();
            match client.poll_transmit(&mut cio, &mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let mut sio = server_sio.as_io();
                    let _ = server.recv(&mut sio, &data, now, pool);
                }
                None => break,
            }
        }
        loop {
            let mut buf = [0u8; 4096];
            let mut sio = server_sio.as_io();
            match server.poll_transmit(&mut sio, &mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let mut cio = client_sio.as_io();
                    let _ = client.recv(&mut cio, &data, now, pool);
                }
                None => break,
            }
        }
        if client.is_established() && server.is_established() {
            return;
        }
    }
    panic!("QUIC handshake did not complete");
}

fn exchange_h3(
    client: &mut H3Client<C>,
    server: &mut H3Server<C>,
    now: u64,
    pool: &mut HandshakePool<C, 4>,
) {
    for _ in 0..10 {
        let mut any = false;
        loop {
            let mut buf = [0u8; 4096];
            match client.poll_transmit(&mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let _ = server.recv(&data, now, pool);
                    any = true;
                }
                None => break,
            }
        }
        loop {
            let mut buf = [0u8; 4096];
            match server.poll_transmit(&mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let _ = client.recv(&data, now, pool);
                    any = true;
                }
                None => break,
            }
        }
        if !any {
            break;
        }
    }
}

fn setup_h3_pair() -> (H3Client<C>, H3Server<C>, u64, Box<HandshakePool<C, 4>>) {
    let now = 1_000_000u64;
    let mut pool = make_pool();
    let mut qc = make_quic_client(&mut pool);
    let mut qs = make_quic_server(&mut pool);
    run_quic_handshake(&mut qc, &mut qs, now, &mut pool);

    let mut client = H3Client::new(qc);
    let mut server = H3Server::new(qs);

    let _ = client.poll_event();
    let _ = server.poll_event();
    exchange_h3(&mut client, &mut server, now, &mut pool);

    // Drain until both see H3Event::Connected.
    for _ in 0..10 {
        while let Some(_) = client.poll_event() {}
        while let Some(_) = server.poll_event() {}
        exchange_h3(&mut client, &mut server, now, &mut pool);
    }

    (client, server, now, pool)
}

// ===========================================================================
// TLS helpers
// ===========================================================================

fn make_tls_client() -> TlsConnection<C> {
    let config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    TlsConnection::new_client(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
}

fn make_tls_server() -> TlsConnection<C> {
    let config = ServerTlsConfig {
        cert_der: get_test_cert(),
        private_key_der: &TEST_SEED,
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
    };
    TlsConnection::new_server(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
}

type TestTlsIo = TlsIoBufs<8192>;

fn tls_transfer(
    src: &mut TlsConnection<C>,
    sio: &mut TestTlsIo,
    dst: &mut TlsConnection<C>,
    dio: &mut TestTlsIo,
) -> bool {
    let mut any = false;
    let mut buf = [0u8; 16384];
    while let Some(data) = src.poll_output(&mut sio.as_io(), &mut buf) {
        let copy = data.to_vec();
        dst.feed_data(&mut dio.as_io(), &copy).unwrap();
        any = true;
    }
    any
}

fn tls_handshake(
    client: &mut TlsConnection<C>,
    cio: &mut TestTlsIo,
    server: &mut TlsConnection<C>,
    sio: &mut TestTlsIo,
) {
    for _ in 0..20 {
        let a = tls_transfer(client, cio, server, sio);
        let b = tls_transfer(server, sio, client, cio);
        if !a && !b {
            break;
        }
    }
}

// ===========================================================================
// HTTPS/1.1 helpers
// ===========================================================================

type TestHttps1Client = Https1Client<C, 8192, 1024, 2048>;
type TestHttps1Server = Https1Server<C, 8192, 1024, 2048>;

fn make_https1_client() -> TestHttps1Client {
    let config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    Https1Client::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
}

fn make_https1_server() -> TestHttps1Server {
    let config = ServerTlsConfig {
        cert_der: get_test_cert(),
        private_key_der: &TEST_SEED,
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
    };
    Https1Server::new(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
}

fn https1_exchange(client: &mut TestHttps1Client, server: &mut TestHttps1Server) {
    for _ in 0..20 {
        let mut any = false;
        let mut buf = [0u8; 16384];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
            any = true;
        }
        let mut buf2 = [0u8; 16384];
        while let Some(data) = server.poll_output(&mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            any = true;
        }
        if !any {
            break;
        }
    }
}

// ===========================================================================
// Tests — run sequentially with `cargo test --test heap_measurement -- --test-threads=1`
// ===========================================================================

#[test]
fn measure_h3_handshake_and_data() {
    println!();
    println!("============================================================");
    println!("  ACTUAL HEAP MEASUREMENT (tracking allocator)");
    println!("============================================================");
    println!();

    // --- Measure H3 pair setup (QUIC handshake + H3 settings) ---
    let snap = HeapSnapshot::begin();

    let (mut client, mut server, now, mut pool) = setup_h3_pair();

    let snap = snap.finish();
    let h3_pair_peak = snap.peak_above_baseline();
    let h3_pair_current = snap.current_above_baseline();

    println!("--- H3 pair (2 connections + pool, established) ---");
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", h3_pair_peak, h3_pair_peak as f64 / 1024.0);
    println!("  Current heap: {:>8} bytes  ({:.1} KB)", h3_pair_current, h3_pair_current as f64 / 1024.0);
    println!("  (includes HandshakePool<4>, H3Client, H3Server, QuicStreamIoBufs)");
    println!();

    // --- Measure H3 request/response data flow ---
    let snap = HeapSnapshot::begin();

    let stream_id = client.send_request("GET", "/test", "test.local", &[], false).unwrap();
    client.send_body(stream_id, &[], true).unwrap();
    exchange_h3(&mut client, &mut server, now, &mut pool);

    // Server receives and responds
    for _ in 0..5 {
        while let Some(ev) = server.poll_event() {
            if let H3Event::Headers(sid) = ev {
                server.recv_headers(sid, |_, _| {}).unwrap();
                server.send_response(sid, 200, &[], false).unwrap();
                server.send_body(sid, b"Hello, HTTP/3!", true).unwrap();
            }
        }
        exchange_h3(&mut client, &mut server, now, &mut pool);
    }

    // Client reads response
    while let Some(ev) = client.poll_event() {
        if let H3Event::Headers(sid) = ev {
            client.recv_headers(sid, |_, _| {}).unwrap();
        }
        if let H3Event::Data(sid) = ev {
            let mut buf = [0u8; 256];
            let _ = client.recv_body(sid, &mut buf);
        }
    }

    let snap = snap.finish();
    let data_peak = snap.peak_above_baseline();
    println!("--- H3 request/response data flow (additional) ---");
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", data_peak, data_peak as f64 / 1024.0);
    println!();

    // Drop everything and verify cleanup
    drop(client);
    drop(server);
    drop(pool);

    println!("--- After dropping all H3 state ---");
    println!("  Remaining:    {:>8} bytes", ALLOC.current());
    println!();
}

#[test]
fn measure_https1_handshake_and_data() {
    println!();

    // --- Measure HTTPS/1.1 handshake ---
    let snap = HeapSnapshot::begin();

    let mut client = make_https1_client();
    let mut server = make_https1_server();
    https1_exchange(&mut client, &mut server);

    let snap = snap.finish();
    let hs_peak = snap.peak_above_baseline();
    let hs_current = snap.current_above_baseline();

    assert!(client.is_established(), "HTTPS/1.1 handshake should complete");
    assert!(server.is_established());

    println!("--- HTTPS/1.1 pair (established) ---");
    println!("  Peak heap during handshake: {:>8} bytes  ({:.1} KB)", hs_peak, hs_peak as f64 / 1024.0);
    println!("  Current heap (post-shrink): {:>8} bytes  ({:.1} KB)", hs_current, hs_current as f64 / 1024.0);
    println!("  Struct size (client+server): {:>7} bytes", 2 * size_of::<TestHttps1Server>());
    println!();

    // --- Measure data flow ---
    // Drain handshake events
    while let Some(_) = client.poll_event() {}
    while let Some(_) = server.poll_event() {}

    let snap = HeapSnapshot::begin();

    let _sid = client.send_request("GET", "/hello", "test.local", &[], true).unwrap();
    https1_exchange(&mut client, &mut server);

    // Server reads and responds
    while let Some(ev) = server.poll_event() {
        if let Http1Event::Headers(sid) = ev {
            server.recv_headers(sid, |_, _| {}).unwrap();
            server.send_response(sid, 200, &[(b"content-length", b"14")], false).unwrap();
            server.send_body(sid, b"Hello, HTTPS1!", true).unwrap();
        }
    }
    https1_exchange(&mut client, &mut server);

    let snap = snap.finish();
    let data_peak = snap.peak_above_baseline();
    println!("--- HTTPS/1.1 request/response (additional) ---");
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", data_peak, data_peak as f64 / 1024.0);
    println!();

    drop(client);
    drop(server);

    println!("--- After dropping all HTTPS/1.1 state ---");
    println!("  Remaining:    {:>8} bytes", ALLOC.current());
    println!();
}

#[test]
fn measure_tls_connection_only() {
    println!();

    // --- TLS connection pair (no HTTP layer) ---
    let snap = HeapSnapshot::begin();

    let mut client = make_tls_client();
    let mut cio = TestTlsIo::new();
    let mut server = make_tls_server();
    let mut sio = TestTlsIo::new();

    let snap_pre_hs = snap.finish();
    let create_peak = snap_pre_hs.peak_above_baseline();
    let create_current = snap_pre_hs.current_above_baseline();

    println!("--- TLS connection pair (created, before handshake) ---");
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", create_peak, create_peak as f64 / 1024.0);
    println!("  Current heap: {:>8} bytes  ({:.1} KB)", create_current, create_current as f64 / 1024.0);
    println!("  Struct size (conn+io): {:>7} bytes each", size_of::<TlsConnection<C>>() + size_of::<TestTlsIo>());
    println!();

    let snap = HeapSnapshot::begin();
    tls_handshake(&mut client, &mut cio, &mut server, &mut sio);
    let snap = snap.finish();
    let hs_peak = snap.peak_above_baseline();

    // Drain events
    while let Some(_) = client.poll_event() {}
    while let Some(_) = server.poll_event() {}

    let _post_hs_current = ALLOC.current();

    assert!(client.is_active());
    assert!(server.is_active());

    println!("--- TLS handshake ---");
    println!("  Peak heap during handshake: {:>8} bytes  ({:.1} KB)", hs_peak, hs_peak as f64 / 1024.0);
    println!();

    // Measure post-handshake steady state
    let snap = HeapSnapshot::begin();
    client.send_app_data(&mut cio.as_io(), b"Hello from client").unwrap();
    tls_transfer(&mut client, &mut cio, &mut server, &mut sio);
    while let Some(_) = server.poll_event() {}
    let mut recv = [0u8; 256];
    let _ = server.recv_app_data(&mut sio.as_io(), &mut recv);

    let snap = snap.finish();
    let data_peak = snap.peak_above_baseline();

    println!("--- TLS app data exchange ---");
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", data_peak, data_peak as f64 / 1024.0);
    println!();
}

#[test]
fn measure_target_config() {
    // Simulate the target: 1 HTTPS/1.1 + 4 H3 connections (2 handshaking)
    // We measure peak heap during the most memory-intensive phase.
    println!();
    println!("============================================================");
    println!("  TARGET CONFIG: 1 HTTPS/1.1 + 4 H3 (peak measurement)");
    println!("============================================================");
    println!();

    let snap = HeapSnapshot::begin();

    // Create HTTPS/1.1 pair
    let mut h1_client = make_https1_client();
    let mut h1_server = make_https1_server();
    https1_exchange(&mut h1_client, &mut h1_server);
    assert!(h1_client.is_established());
    while let Some(_) = h1_client.poll_event() {}
    while let Some(_) = h1_server.poll_event() {}

    // Create 2 established H3 pairs (using one shared pool)
    // We create them sequentially, each pair reusing the pool
    let now = 1_000_000u64;
    let mut pool = make_pool();

    // H3 pair 1 (established)
    let mut qc1 = make_quic_client(&mut pool);
    let mut qs1 = make_quic_server(&mut pool);
    run_quic_handshake(&mut qc1, &mut qs1, now, &mut pool);
    let mut h3c1 = H3Client::new(qc1);
    let mut h3s1 = H3Server::new(qs1);
    let _ = h3c1.poll_event();
    let _ = h3s1.poll_event();
    exchange_h3(&mut h3c1, &mut h3s1, now, &mut pool);
    for _ in 0..5 {
        while let Some(_) = h3c1.poll_event() {}
        while let Some(_) = h3s1.poll_event() {}
        exchange_h3(&mut h3c1, &mut h3s1, now, &mut pool);
    }

    // H3 pair 2 (established)
    let mut qc2 = make_quic_client(&mut pool);
    let mut qs2 = make_quic_server(&mut pool);
    run_quic_handshake(&mut qc2, &mut qs2, now, &mut pool);
    let mut h3c2 = H3Client::new(qc2);
    let mut h3s2 = H3Server::new(qs2);
    let _ = h3c2.poll_event();
    let _ = h3s2.poll_event();
    exchange_h3(&mut h3c2, &mut h3s2, now, &mut pool);
    for _ in 0..5 {
        while let Some(_) = h3c2.poll_event() {}
        while let Some(_) = h3s2.poll_event() {}
        exchange_h3(&mut h3c2, &mut h3s2, now, &mut pool);
    }

    let snap_established = snap.finish();
    let established_current = snap_established.current_above_baseline();
    let established_peak = snap_established.peak_above_baseline();

    println!("--- Phase 1: 1 HTTPS/1.1 + 2 established H3 ---");
    println!("  Current heap: {:>8} bytes  ({:.1} KB)", established_current, established_current as f64 / 1024.0);
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", established_peak, established_peak as f64 / 1024.0);
    println!();

    // Now add 2 more H3 connections in handshaking state
    // This is the peak — 2 established + 2 handshaking + 1 HTTPS/1.1
    let snap = HeapSnapshot::begin();

    let mut qc3 = make_quic_client(&mut pool);
    let mut qs3 = make_quic_server(&mut pool);
    let mut qc4 = make_quic_client(&mut pool);
    let mut qs4 = make_quic_server(&mut pool);

    // Start handshakes (partial — don't complete them)
    let mut sio3 = QuicStreamIoBufs::<32, 1024, 16>::new();
    let mut sio3s = QuicStreamIoBufs::<32, 1024, 16>::new();
    let mut sio4 = QuicStreamIoBufs::<32, 1024, 16>::new();
    let mut sio4s = QuicStreamIoBufs::<32, 1024, 16>::new();

    // Do a few rounds of handshake to get crypto state allocated
    for _ in 0..5 {
        let mut buf = [0u8; 4096];
        let mut io3 = sio3.as_io();
        if let Some(tx) = qc3.poll_transmit(&mut io3, &mut buf, now, &mut *pool) {
            let data = tx.data.to_vec();
            let mut io3s = sio3s.as_io();
            let _ = qs3.recv(&mut io3s, &data, now, &mut *pool);
        }
        let mut io3s = sio3s.as_io();
        if let Some(tx) = qs3.poll_transmit(&mut io3s, &mut buf, now, &mut *pool) {
            let data = tx.data.to_vec();
            let mut io3 = sio3.as_io();
            let _ = qc3.recv(&mut io3, &data, now, &mut *pool);
        }

        let mut io4 = sio4.as_io();
        if let Some(tx) = qc4.poll_transmit(&mut io4, &mut buf, now, &mut *pool) {
            let data = tx.data.to_vec();
            let mut io4s = sio4s.as_io();
            let _ = qs4.recv(&mut io4s, &data, now, &mut *pool);
        }
        let mut io4s = sio4s.as_io();
        if let Some(tx) = qs4.poll_transmit(&mut io4s, &mut buf, now, &mut *pool) {
            let data = tx.data.to_vec();
            let mut io4 = sio4.as_io();
            let _ = qc4.recv(&mut io4, &data, now, &mut *pool);
        }
    }

    let snap = snap.finish();
    let handshaking_peak = snap.peak_above_baseline();

    println!("--- Phase 2: +2 handshaking H3 connections (additional) ---");
    println!("  Peak heap:    {:>8} bytes  ({:.1} KB)", handshaking_peak, handshaking_peak as f64 / 1024.0);
    println!();

    // Grand total
    let total_current = ALLOC.current();
    println!("--- Combined state (all connections live) ---");
    println!("  Total heap:   {:>8} bytes  ({:.1} KB)", total_current, total_current as f64 / 1024.0);
    println!("  Total peak:   {:>8} bytes  ({:.1} KB)", established_peak + handshaking_peak, (established_peak + handshaking_peak) as f64 / 1024.0);

    // Struct sizes (note: this test runs BOTH client and server per connection)
    let struct_both = // full test: client+server pairs
        size_of::<TestHttps1Client>() + size_of::<TestHttps1Server>()
        + 4 * (size_of::<H3Client<C>>() + size_of::<H3Server<C>>())
        + size_of::<HandshakePool<C, 4>>();
    let struct_server_only = // real deployment: server side only
        size_of::<TestHttps1Server>()
        + 4 * size_of::<H3Server<C>>()
        + size_of::<HandshakePool<C, 4>>();

    println!("  Struct (both sides): {:>8} bytes  ({:.1} KB)", struct_both, struct_both as f64 / 1024.0);
    println!("  Struct (server only): {:>7} bytes  ({:.1} KB)", struct_server_only, struct_server_only as f64 / 1024.0);
    println!("  Both+heap:   {:>8} bytes  ({:.1} KB)",
        struct_both + total_current,
        (struct_both + total_current) as f64 / 1024.0);
    // Rough server-only estimate: heap is ~half (only one side's buffers)
    let server_heap_est = total_current / 2;
    println!("  Server+heap (est): {:>5} bytes  ({:.1} KB)",
        struct_server_only + server_heap_est,
        (struct_server_only + server_heap_est) as f64 / 1024.0);
    println!();
    println!("  NOTE: heap includes BOTH client and server allocations.");
    println!("  A real server would use roughly half the heap.");
    println!();

    let goal: usize = 102400;
    let combined = struct_server_only + server_heap_est;
    if combined <= goal {
        println!("  UNDER BUDGET by {} bytes ({:.1} KB)",
            goal - combined, (goal - combined) as f64 / 1024.0);
    } else {
        println!("  OVER BUDGET by {} bytes ({:.1} KB)",
            combined - goal, (combined - goal) as f64 / 1024.0);
    }
    println!("============================================================");
}
