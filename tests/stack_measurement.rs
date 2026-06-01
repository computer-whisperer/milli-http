//! Actual stack high-water measurement via stack painting.
//!
//! This mirrors the embedded technique (FreeRTOS `uxTaskGetStackHighWaterMark`,
//! Cortex-M stack-fill): each scenario runs on a dedicated thread with a fixed
//! stack; we paint the stack below the entry frame with a sentinel, run the
//! workload, then scan for the deepest disturbed byte. The result is the
//! *written* stack high-water for that scenario — the number that matters for
//! sizing an MCU task stack.
//!
//! Method notes / limitations:
//!   - This measures *written* depth. A frame that reserves stack but leaves
//!     locals uninitialized can read slightly low; in practice call frames write
//!     return addresses + saved registers near their top, so the estimate tracks
//!     claimed depth closely. This is the same trade-off every paint-based
//!     embedded high-water tool makes.
//!   - All long-lived protocol state (connections, pool, I/O buffers) is boxed
//!     onto the heap *before* painting, so the measured stack reflects only the
//!     transient call-path cost — exactly what sits on top of static/heap-
//!     resident connection state on the target. The driver-side scratch buffers
//!     (the `[0u8; 4096]` tx buffer, `[0u8; 2048]` scratch) are kept as locals
//!     because a real embedded caller would have them too.
//!   - Subtract the `baseline (noop)` row from each scenario to get the
//!     workload-attributable stack (it removes the harness's own call overhead).
//!
//! Run with: cargo test --features "h3,http1,tcp-tls,h2,rustcrypto-chacha,std,alloc" \
//!   --test stack_measurement -- --test-threads=1 --nocapture

#![cfg(all(
    feature = "alloc",
    any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")
))]

extern crate alloc;

use alloc::boxed::Box;

// ===========================================================================
// Stack-painting harness
// ===========================================================================

const SENTINEL_BYTE: u8 = 0xC5;
const SENTINEL_WORD: usize = usize::from_ne_bytes([SENTINEL_BYTE; core::mem::size_of::<usize>()]);

/// Default probe geometry: paint up to 2 MiB below the entry frame on an 8 MiB
/// thread stack. Scenarios use far less; the assert in `measure_stack` fires if
/// any workload ever reaches the probe limit.
const STACK_SIZE: usize = 8 * 1024 * 1024;
const PROBE: usize = 2 * 1024 * 1024;

/// Paint `[lo, ceil)` with the sentinel, where `ceil` is computed *inside* this
/// function to stay clear of our own live frame. Uses volatile writes so the
/// fill is not elided.
#[inline(never)]
fn paint(lo: usize) {
    let here = 0u8;
    // Stay well below this function's own frame.
    let ceil = (&here as *const u8 as usize).saturating_sub(256);
    let mut p = lo;
    let word = core::mem::size_of::<usize>();
    // SAFETY (test-only): `[lo, ceil)` lies below our live frame within the
    // current thread's stack, above its guard page (PROBE << STACK_SIZE). We
    // hold no references into this region while painting.
    unsafe {
        // Byte-fill up to the first word boundary.
        while p % word != 0 && p < ceil {
            core::ptr::write_volatile(p as *mut u8, SENTINEL_BYTE);
            p += 1;
        }
        while p + word <= ceil {
            core::ptr::write_volatile(p as *mut usize, SENTINEL_WORD);
            p += word;
        }
        while p < ceil {
            core::ptr::write_volatile(p as *mut u8, SENTINEL_BYTE);
            p += 1;
        }
    }
    core::hint::black_box(&here);
}

/// Scan `[lo, anchor)` upward; return the lowest disturbed address (= deepest
/// point the stack pointer wrote). Returns `anchor` if nothing was disturbed.
#[inline(never)]
fn scan(lo: usize, anchor: usize) -> usize {
    let mut p = lo;
    // SAFETY (test-only): same region painted by `paint`; read-only scan.
    unsafe {
        while p < anchor {
            if core::ptr::read_volatile(p as *const u8) != SENTINEL_BYTE {
                return p;
            }
            p += 1;
        }
    }
    anchor
}

/// Run `setup` (not measured), then paint, run `run` (measured), and return the
/// stack high-water in bytes consumed by `run`.
fn measure_stack<S, Setup, Run>(setup: Setup, run: Run) -> usize
where
    S: Send + 'static,
    Setup: FnOnce() -> S + Send + 'static,
    Run: FnOnce(&mut S) + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || {
            // Build long-lived state first; its construction frames unwind
            // before we capture the anchor and paint.
            let mut state = setup();

            let anchor_local = 0u8;
            let anchor = &anchor_local as *const u8 as usize;
            let lo = anchor - PROBE;

            paint(lo);
            run(&mut state);
            let deepest = scan(lo, anchor);
            drop(state);

            let used = anchor - deepest;
            assert!(
                used < PROBE,
                "stack high-water {used} reached probe limit {PROBE}; increase PROBE"
            );
            core::hint::black_box(&anchor_local);
            used
        })
        .expect("spawn measurement thread")
        .join()
        .expect("measurement thread panicked")
}

fn kb(n: usize) -> f64 {
    n as f64 / 1024.0
}

// ===========================================================================
// Protocol setup helpers (mirrors tests/heap_measurement.rs)
// ===========================================================================

use milli_http::QuicStreamIoBufs;
use milli_http::Rng;
use milli_http::connection::Connection;
use milli_http::connection::HandshakePool;
use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h2::H2Event;
use milli_http::h2_tls::{H2TlsClient, H2TlsServer};
use milli_http::h3::{H3Client, H3Event, H3Server};
use milli_http::http1::Http1Event;
use milli_http::https1::{Https1Client, Https1Server};
use milli_http::tcp_tls::connection::TlsConnection;
use milli_http::tcp_tls::io::TlsIoBufs;
use milli_http::tls::handshake::{ServerTlsConfig, TlsConfig};
use milli_http::tls::transport_params::TransportParams;

type C = Aes128GcmProvider;
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

/// Drive a QUIC handshake to completion. Returns once both sides are established.
fn run_quic_handshake(
    client: &mut Connection<C>,
    server: &mut Connection<C>,
    client_sio: &mut QuicStreamIoBufs<32, 1024, 16>,
    server_sio: &mut QuicStreamIoBufs<32, 1024, 16>,
    now: u64,
    pool: &mut HandshakePool<C, 4>,
) {
    // Driver-side I/O staging lives on the heap: a real integrator would keep
    // network buffers in static/pool RAM, not on the call stack, so excluding
    // them isolates milli-http's own call-path stack.
    let mut scratch = alloc::vec![0u8; 2048];
    let mut buf = alloc::vec![0u8; 4096];
    for _ in 0..20 {
        loop {
            let mut cio = client_sio.as_io();
            match client.poll_transmit(&mut cio, &mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let mut sio = server_sio.as_io();
                    let _ = server.recv(&mut sio, &data, &mut scratch, now, pool);
                }
                None => break,
            }
        }
        loop {
            let mut sio = server_sio.as_io();
            match server.poll_transmit(&mut sio, &mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let mut cio = client_sio.as_io();
                    let _ = client.recv(&mut cio, &data, &mut scratch, now, pool);
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
    let mut scratch = alloc::vec![0u8; 2048];
    let mut buf = alloc::vec![0u8; 4096];
    for _ in 0..10 {
        let mut any = false;
        loop {
            match client.poll_transmit(&mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let _ = server.recv(&data, &mut scratch, now, pool);
                    any = true;
                }
                None => break,
            }
        }
        loop {
            match server.poll_transmit(&mut buf, now, pool) {
                Some(tx) => {
                    let data = tx.data.to_vec();
                    let _ = client.recv(&data, &mut scratch, now, pool);
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

// ===========================================================================
// TLS / HTTPS1 / H2 helpers
// ===========================================================================

type TestTlsIo = TlsIoBufs<8192>;

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

fn tls_transfer(
    src: &mut TlsConnection<C>,
    sio: &mut TestTlsIo,
    dst: &mut TlsConnection<C>,
    dio: &mut TestTlsIo,
) -> bool {
    let mut any = false;
    let mut buf = alloc::vec![0u8; 16384];
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
    let mut buf = alloc::vec![0u8; 16384];
    let mut buf2 = alloc::vec![0u8; 16384];
    for _ in 0..20 {
        let mut any = false;
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
            any = true;
        }
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

type TestH2TlsClient = H2TlsClient<C, 8192, 8, 2048, 4096>;
type TestH2TlsServer = H2TlsServer<C, 8192, 8, 2048, 4096>;

fn make_h2tls_client() -> TestH2TlsClient {
    let config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    H2TlsClient::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
}

fn make_h2tls_server() -> TestH2TlsServer {
    let config = ServerTlsConfig {
        cert_der: get_test_cert(),
        private_key_der: &TEST_SEED,
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
    };
    H2TlsServer::new(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
}

fn h2tls_exchange(client: &mut TestH2TlsClient, server: &mut TestH2TlsServer) {
    let mut buf = alloc::vec![0u8; 16384];
    let mut buf2 = alloc::vec![0u8; 16384];
    for _ in 0..20 {
        let mut any = false;
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
            any = true;
        }
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
// Scenario state bundles (boxed so they stay off the measured stack)
// ===========================================================================

struct QuicHs {
    client: Box<Connection<C>>,
    server: Box<Connection<C>>,
    pool: Box<HandshakePool<C, 4>>,
    csio: Box<QuicStreamIoBufs<32, 1024, 16>>,
    ssio: Box<QuicStreamIoBufs<32, 1024, 16>>,
    now: u64,
}

fn setup_quic_fresh() -> QuicHs {
    let mut pool = make_pool();
    let client = Box::new(make_quic_client(&mut pool));
    let server = Box::new(make_quic_server(&mut pool));
    QuicHs {
        client,
        server,
        pool,
        csio: Box::new(QuicStreamIoBufs::new()),
        ssio: Box::new(QuicStreamIoBufs::new()),
        now: 1_000_000,
    }
}

struct H3Pair {
    client: Box<H3Client<C>>,
    server: Box<H3Server<C>>,
    pool: Box<HandshakePool<C, 4>>,
    now: u64,
}

fn setup_h3_established() -> H3Pair {
    let now = 1_000_000u64;
    let mut pool = make_pool();
    let mut qc = make_quic_client(&mut pool);
    let mut qs = make_quic_server(&mut pool);
    let mut csio = QuicStreamIoBufs::<32, 1024, 16>::new();
    let mut ssio = QuicStreamIoBufs::<32, 1024, 16>::new();
    run_quic_handshake(&mut qc, &mut qs, &mut csio, &mut ssio, now, &mut pool);

    let mut client = H3Client::new(qc);
    let mut server = H3Server::new(qs);
    let mut scratch = [0u8; 2048];
    let _ = client.poll_event(&mut scratch);
    let _ = server.poll_event(&mut scratch);
    exchange_h3(&mut client, &mut server, now, &mut pool);
    for _ in 0..10 {
        while client.poll_event(&mut scratch).is_some() {}
        while server.poll_event(&mut scratch).is_some() {}
        exchange_h3(&mut client, &mut server, now, &mut pool);
    }
    H3Pair {
        client: Box::new(client),
        server: Box::new(server),
        pool,
        now,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// Validate the harness against a known stack footprint: a function that writes
/// a 16 KiB local array should measure ~16 KiB above the noop baseline. Guards
/// against the harness silently under- or over-counting.
#[test]
fn harness_self_check() {
    #[inline(never)]
    fn burn(bytes: usize) {
        let mut buf = [0u8; 16 * 1024];
        let n = bytes.min(buf.len());
        for i in 0..n {
            buf[i] = core::hint::black_box(i as u8);
        }
        core::hint::black_box(&buf[..n]);
    }

    let baseline = measure_stack(|| (), |_| {});
    let measured = measure_stack(|| (), |_| burn(16 * 1024));
    let above = measured.saturating_sub(baseline);
    println!(
        "harness self-check: 16 KiB burn measured {} B above noop ({:.1} KB)",
        above,
        kb(above)
    );
    // Allow slack for frame overhead / write-depth semantics, but it must be
    // unmistakably in the 16 KiB neighborhood — not near-zero (under-count) and
    // not wildly larger (over-count).
    assert!(
        (14 * 1024..20 * 1024).contains(&above),
        "self-check measured {above} B; expected ~16 KiB"
    );
}

#[test]
fn measure_stack_high_water() {
    println!();
    println!("============================================================");
    println!("  STACK HIGH-WATER (paint method, written depth)");
    println!("============================================================");
    println!();

    let baseline = measure_stack(|| (), |_| {});

    let mut rows: Vec<(&str, usize)> = Vec::new();

    // --- QUIC handshake (the deep nested-frame path) ---
    rows.push((
        "QUIC handshake (client+server drive)",
        measure_stack(setup_quic_fresh, |s| {
            run_quic_handshake(
                &mut s.client,
                &mut s.server,
                &mut s.csio,
                &mut s.ssio,
                s.now,
                &mut s.pool,
            );
        }),
    ));

    // --- H3 request/response over an established pair ---
    rows.push((
        "H3 request + response (established)",
        measure_stack(setup_h3_established, |s| {
            let sid = s
                .client
                .send_request("GET", "/test", "test.local", &[], false)
                .unwrap();
            s.client.send_body(sid, &[], true).unwrap();
            exchange_h3(&mut s.client, &mut s.server, s.now, &mut s.pool);
            let mut scratch = alloc::vec![0u8; 2048];
            for _ in 0..5 {
                while let Some(ev) = s.server.poll_event(&mut scratch) {
                    if let H3Event::Headers(rid) = ev {
                        s.server.recv_headers(rid, |_, _| {}).unwrap();
                        s.server.send_response(rid, 200, &[], false).unwrap();
                        s.server.send_body(rid, b"Hello, HTTP/3!", true).unwrap();
                    }
                }
                exchange_h3(&mut s.client, &mut s.server, s.now, &mut s.pool);
            }
            while let Some(ev) = s.client.poll_event(&mut scratch) {
                match ev {
                    H3Event::Headers(rid) => {
                        s.client.recv_headers(rid, |_, _| {}).unwrap();
                    }
                    H3Event::Data(rid) => {
                        let mut buf = [0u8; 256];
                        let _ = s.client.recv_body(rid, &mut buf);
                    }
                    _ => {}
                }
            }
        }),
    ));

    // --- Isolated server-side recv of one request packet (per-packet path) ---
    rows.push((
        "H3 server.recv() one request packet",
        measure_stack(
            || {
                let mut pair = setup_h3_established();
                // Produce one request packet from the client, captured as bytes.
                let sid = pair
                    .client
                    .send_request("GET", "/test", "test.local", &[], true)
                    .unwrap();
                let _ = sid;
                let mut buf = [0u8; 4096];
                let mut packet: Vec<u8> = Vec::new();
                if let Some(tx) = pair
                    .client
                    .poll_transmit(&mut buf, pair.now, &mut *pair.pool)
                {
                    packet = tx.data.to_vec();
                }
                (pair, packet)
            },
            |(pair, packet)| {
                let mut scratch = alloc::vec![0u8; 2048];
                let _ = pair
                    .server
                    .recv(&packet[..], &mut scratch, pair.now, &mut *pair.pool);
            },
        ),
    ));

    // --- Raw TLS handshake ---
    rows.push((
        "TLS 1.3 handshake (client+server drive)",
        measure_stack(
            || {
                (
                    Box::new(make_tls_client()),
                    Box::new(TestTlsIo::new()),
                    Box::new(make_tls_server()),
                    Box::new(TestTlsIo::new()),
                )
            },
            |(c, cio, s, sio)| tls_handshake(c, cio, s, sio),
        ),
    ));

    // --- HTTPS/1.1 handshake + request ---
    rows.push((
        "HTTPS/1.1 handshake + request",
        measure_stack(
            || {
                (
                    Box::new(make_https1_client()),
                    Box::new(make_https1_server()),
                )
            },
            |(client, server)| {
                https1_exchange(client, server);
                while client.poll_event().is_some() {}
                while server.poll_event().is_some() {}
                let _ = client
                    .send_request("GET", "/hello", "test.local", &[], true)
                    .unwrap();
                https1_exchange(client, server);
                while let Some(ev) = server.poll_event() {
                    if let Http1Event::Headers(sid) = ev {
                        server.recv_headers(sid, |_, _| {}).unwrap();
                        server
                            .send_response(sid, 200, &[(b"content-length", b"14")], false)
                            .unwrap();
                        server.send_body(sid, b"Hello, HTTPS1!", true).unwrap();
                    }
                }
                https1_exchange(client, server);
            },
        ),
    ));

    // --- H2/TLS handshake + request ---
    rows.push((
        "H2/TLS handshake + request",
        measure_stack(
            || (Box::new(make_h2tls_client()), Box::new(make_h2tls_server())),
            |(client, server)| {
                h2tls_exchange(client, server);
                while client.poll_event().is_some() {}
                while server.poll_event().is_some() {}
                let _ = client
                    .send_request("GET", "/hello", "test.local", &[], true)
                    .unwrap();
                h2tls_exchange(client, server);
                while let Some(ev) = server.poll_event() {
                    if let H2Event::Headers(sid) = ev {
                        server.recv_headers(sid, |_, _| {}).unwrap();
                        server
                            .send_response(sid, 200, &[(b"content-length", b"14")], false)
                            .unwrap();
                        server.send_body(sid, b"Hello from H2!", true).unwrap();
                    }
                }
                h2tls_exchange(client, server);
            },
        ),
    ));

    println!("  {:<42} {:>10}  {:>12}", "scenario", "raw", "above noop");
    println!("  {:-<42} {:->10}  {:->12}", "", "", "");
    println!("  {:<42} {:>7} B  {:>10}", "baseline (noop)", baseline, "-");
    for (name, used) in &rows {
        let above = used.saturating_sub(baseline);
        println!(
            "  {:<42} {:>7} B  {:>8} B  ({:.1} KB)",
            name,
            used,
            above,
            kb(above)
        );
    }
    println!();

    let worst = rows.iter().map(|(_, u)| *u).max().unwrap_or(0);
    println!(
        "  Worst-case measured high-water: {} B ({:.1} KB)",
        worst,
        kb(worst)
    );
    println!("============================================================");
}
