//! Peak-heap regression guard for the decrypt-in-place invariant.
//!
//! This guards the decrypt-in-place invariant — **3 shared TLS buffers per
//! connection, not 4.** Before decrypt-in-place, a TLS connection held four
//! `Buf<BUF>` byte buffers (net_recv, app_recv, net_send, app_send); decrypting
//! records in place inside `net_recv` removed the whole `app_recv` buffer. On a
//! memory-tight RP2350 (~140 KB heap) that fourth ~18 KB buffer — plus its
//! realloc churn — was the difference between a 2 MB firmware upload completing
//! and OOMing during response/teardown. That OOM was invisible to the rest of
//! the suite because every other test runs on the host's unbounded heap.
//!
//! This test installs a tracking global allocator, drives a large h2/TLS upload
//! against a hardware-sized server, and asserts the peak heap stays under a
//! documented budget chosen so that reintroducing a fourth per-connection
//! `Buf<BUF>` (an `app_recv` regression) trips the assertion. See
//! `SERVER_PEAK_BUDGET`.
//!
//! Because `#[global_allocator]` is per-binary, this lives in its own test file
//! and runs single-threaded (one `#[test]`), so the counter never races.

#![cfg(all(
    feature = "alloc",
    feature = "h2",
    feature = "tcp-tls",
    any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")
))]

extern crate alloc;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::error::Error;
use milli_http::h2::H2Event;
use milli_http::h2_tls::{H2TlsClient, H2TlsServer};
use milli_http::tls::handshake::{ServerTlsConfig, TlsConfig};
use milli_http::tls::transport_params::TransportParams;

// ===========================================================================
// Tracking allocator: live-bytes counter + peak watermark via fetch_max.
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
    /// Reset the watermark down to the current live total, so a later `peak()`
    /// reflects only allocation growth after this point.
    fn reset_peak(&self) {
        self.peak
            .store(self.current.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let new = self.current.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            self.peak.fetch_max(new, Ordering::Relaxed);
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
// Configuration + budget
// ===========================================================================

const BUF: usize = 18432; // one max-size TLS record + header; the firmware value

// Isolation: the process runs both client and server, so the counter sees both
// plus harness noise. We attribute the peak to the SERVER by making the client
// cheap and bounded:
//
//   * Client BUF = CLIENT_BUF (same as server) so neither side has an outsized
//     I/O footprint, and the client's three buffers are a known, fixed quantity
//     we account for in the budget headroom.
//   * We reset the peak watermark AFTER the handshake (a transient cost that is
//     not the steady-state footprint we care about) and measure only the bulk
//     upload + response/teardown, where the per-connection I/O buffers reach
//     capacity — and where a 4th server buffer would manifest.
//   * The harness's own staging Vecs (`to_server`, the chunk builder) are kept
//     small and bounded per cycle.
const CLIENT_BUF: usize = BUF;

// Total peak-heap ceiling for the measured window (server's per-connection
// footprint + the client's bounded footprint + small harness buffers).
//
// The dominant live allocations in the measured window are the per-connection
// `Buf<BUF>` byte buffers (3 server + 3 client) plus each side's one active H2
// stream body buffer, the HPACK tables, event deques, the post-handshake-shrunk
// TlsEngine remnants, and the harness's small per-cycle staging Vecs. Note the
// six TLS buffers do NOT all sit at the full 18432 simultaneously — the sender
// drains as it encrypts, the receiver compacts in place — so the real peak is
// well below the naive 6 x 18432 sum.
//
// Empirically the measured peak is ~113 KB (printed by the test). The budget is
// chosen against the actual measurement, not the upper-bound estimate:
//
//   measured peak (P)            ~ 116 KB
//   one TLS Buf<BUF>             =  18 KB
//   P + BUF                      ~ 134 KB
//
// We set the budget at 126 KB — about 10 KB above the measured peak (slack for
// Vec-doubling jitter so the test is not flaky) and a clear ~8 KB BELOW P + BUF.
// A regression reintroducing a fourth per-connection `Buf<BUF>` adds ~18 KB,
// pushing the peak to ~134 KB > 126 KB and tripping the upper-bound assert.
//
// The test also asserts the LOWER bound `peak + BUF > budget`: if the real peak
// ever drifts so far under budget that one extra buffer would NOT breach it,
// that assert fires telling you to retighten this constant — so the guard can
// never silently go toothless.
const SERVER_PEAK_BUDGET: usize = 126 * 1024;

// ===========================================================================
// Fixtures
// ===========================================================================

const TEST_SEED: [u8; 32] = [0x01u8; 32];

type HwServer = H2TlsServer<Aes128GcmProvider, BUF, 8, 2048, 16384>;
type TestClient = H2TlsClient<Aes128GcmProvider, CLIENT_BUF, 8, 2048, 4096>;

fn test_cert() -> &'static [u8] {
    let pk = ed25519_public_key_from_seed(&TEST_SEED);
    let mut buf = [0u8; 512];
    let n = build_ed25519_cert_der(&pk, &mut buf).unwrap();
    buf[..n].to_vec().leak()
}

fn make_client() -> TestClient {
    let config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    TestClient::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
}

fn make_server(cert: &'static [u8]) -> HwServer {
    let config = ServerTlsConfig {
        cert_der: cert,
        private_key_der: &TEST_SEED,
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
    };
    HwServer::new(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
}

fn establish(client: &mut TestClient, server: &mut HwServer) {
    for _ in 0..40 {
        let mut progress = false;
        let mut buf = [0u8; 32768];
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
        if !progress && client.is_established() && server.is_established() {
            break;
        }
    }
    assert!(client.is_established() && server.is_established());
}

// ===========================================================================
// Test
// ===========================================================================

#[test]
fn server_peak_heap_under_budget_for_large_upload() {
    let cert = test_cert();

    // 1 MB body — plenty to reach steady-state buffer occupancy (the buffers
    // peak well before this) while keeping the test fast.
    const BODY_LEN: usize = 1024 * 1024;
    let byte_at = |i: usize| (i % 251) as u8;

    let mut client = make_client();
    let mut server = make_server(cert);
    establish(&mut client, &mut server);

    let stream_id = client
        .send_request("POST", "/system/update", "test.local", &[], false)
        .unwrap();

    // Reset the peak watermark now that the (transient) handshake is done. The
    // measured window is the steady-state upload + response/teardown — exactly
    // where per-connection I/O buffers fill and where a regressed 4th buffer
    // would appear.
    let baseline = ALLOC.current();
    ALLOC.reset_peak();

    let mut sent = 0usize;
    let mut recv = 0usize;
    let mut to_server: Vec<u8> = Vec::new();
    let mut send_done = false;
    let mut cobuf = [0u8; 8192];
    let mut sobuf = [0u8; 4096];
    let mut sink = [0u8; 4096];
    let mut guard = 0usize;

    while recv < BODY_LEN {
        guard += 1;
        assert!(guard < 2_000_000, "stalled: recv {recv} sent {sent}");

        if !send_done {
            loop {
                let remaining = BODY_LEN - sent;
                if remaining == 0 {
                    break;
                }
                let chunk_len = remaining.min(16384);
                let chunk: Vec<u8> = (sent..sent + chunk_len).map(byte_at).collect();
                match client.send_body(stream_id, &chunk, false) {
                    Ok(0) => break,
                    Ok(n) => sent += n,
                    Err(Error::WouldBlock) | Err(Error::BufferTooSmall { .. }) => break,
                    Err(e) => panic!("send_body: {e:?}"),
                }
                while let Some(d) = client.poll_output(&mut cobuf) {
                    to_server.extend_from_slice(d);
                }
            }
            if sent == BODY_LEN {
                client.send_body(stream_id, &[], true).unwrap();
                send_done = true;
            }
        }
        while let Some(d) = client.poll_output(&mut cobuf) {
            to_server.extend_from_slice(d);
        }

        // Runner-style server feed: up to 4 x 1500-byte reads per cycle.
        let mut off = 0usize;
        for _ in 0..4 {
            if off >= to_server.len() {
                break;
            }
            let end = (off + 1500).min(to_server.len());
            server.feed_data(&to_server[off..end]).unwrap();
            off = end;
        }
        to_server.drain(..off);

        while let Some(ev) = server.poll_event() {
            if let H2Event::Data(sid) = ev {
                loop {
                    match server.recv_body(sid, &mut sink) {
                        Ok((0, _)) => break,
                        Ok((n, _)) => recv += n,
                        Err(_) => break,
                    }
                }
            }
        }
        // Recirculate WINDOW_UPDATEs etc. so the client keeps getting credit.
        while let Some(d) = server.poll_output(&mut sobuf) {
            let copy = d.to_vec();
            client.feed_data(&copy).unwrap();
        }
    }

    // Response + teardown — where the hardware OOM struck (sending the 200
    // while receive buffers are still held). Still inside the measured window.
    server.send_response(stream_id, 200, &[], false).unwrap();
    server.send_body(stream_id, b"ok", true).unwrap();
    let mut got_finished = false;
    for _ in 0..200 {
        let mut progress = false;
        while let Some(d) = server.poll_output(&mut sobuf) {
            let copy = d.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }
        while let Some(d) = client.poll_output(&mut cobuf) {
            let copy = d.to_vec();
            server.feed_data(&copy).unwrap();
            progress = true;
        }
        while server.poll_event().is_some() {}
        while let Some(ev) = client.poll_event() {
            if let H2Event::Finished(sid) = ev
                && sid == stream_id
            {
                got_finished = true;
            }
        }
        if got_finished || !progress {
            break;
        }
    }

    let peak = ALLOC.peak().saturating_sub(baseline);

    println!();
    println!(
        "measured peak heap during upload+response: {peak} bytes ({:.1} KB)",
        peak as f64 / 1024.0
    );
    println!(
        "budget: {SERVER_PEAK_BUDGET} bytes ({} KB)",
        SERVER_PEAK_BUDGET / 1024
    );
    println!(
        "one TLS Buf<BUF> = {BUF} bytes; margin to budget = {} bytes; peak+BUF = {} bytes",
        SERVER_PEAK_BUDGET.saturating_sub(peak),
        peak + BUF
    );

    assert_eq!(recv, BODY_LEN, "server must have received the whole body");
    assert!(got_finished, "stream should have finished cleanly");

    // Upper bound: the guard. A reintroduced app_recv buffer (~BUF bytes) trips
    // this.
    assert!(
        peak < SERVER_PEAK_BUDGET,
        "peak heap {peak} exceeded budget {SERVER_PEAK_BUDGET}; \
         decrypt-in-place regressed? a 4th per-connection Buf<{BUF}> adds ~{BUF} bytes"
    );

    // Lower bound: the budget must be tight enough that one extra Buf<BUF>
    // WOULD breach it — otherwise the guard above is toothless. If this fails,
    // the measured peak has drifted far below budget; retighten SERVER_PEAK_BUDGET.
    assert!(
        peak + BUF > SERVER_PEAK_BUDGET,
        "budget too loose: peak {peak} + one Buf<{BUF}> = {} is still under budget \
         {SERVER_PEAK_BUDGET}; a reintroduced app_recv buffer would NOT be caught — \
         retighten SERVER_PEAK_BUDGET",
        peak + BUF
    );
}
