//! Memory budget analysis for an embedded server target.
//!
//! Primary target: 1 HTTPS/1.1 + 4 active H3 + 2 H3 handshake slots
//! Extended target: + 2 H2/TLS (measured separately, not in 100KB budget)
//! Goal: < 100 KB total SRAM (struct + peak heap)

#![cfg(feature = "server")]

use core::mem::size_of;

use milli_http::crypto::rustcrypto::ChaCha20Provider;

// -- Component types --
use milli_http::Event;
use milli_http::connection::Connection;
use milli_http::connection::handshake_pool::{HandshakeContext, HandshakePool};
use milli_http::h2::H2Event;
use milli_http::h2_tls::H2TlsServer;
use milli_http::h3::connection::H3Event;
use milli_http::h3::server::H3Server;
use milli_http::http1::connection::Http1Connection;
use milli_http::https1::Https1Server;
use milli_http::server::ServerManager;
use milli_http::tcp_tls::TlsParts;
use milli_http::tcp_tls::connection::TlsConnection;
use milli_http::tcp_tls::io::TlsIoBufs;
use milli_http::tls::handshake::TlsEngine;
use milli_http::transport::recovery::SentPacket;
use milli_http::transport::stream::StreamState;

type C = ChaCha20Provider;

/// Estimate struct + heap for one H3 connection at given operating parameters.
fn h3_estimate(
    h3_struct: usize,
    active_streams: usize,
    stream_buf_size: usize,
    tracked_packets: usize,
    active_requests: usize,
) -> (usize, usize) {
    let streams_heap = active_streams * 2 * size_of::<Option<StreamState>>(); // bidi = 2 entries
    let sent_heap = tracked_packets * size_of::<Option<SentPacket>>();
    let pn_ranges_heap = 3 * 4 * size_of::<(u64, u64)>();
    let events_heap = 8 * size_of::<Event>();
    let h3_events_heap = 8 * size_of::<H3Event>();
    // RequestStreamState: ~80 bytes struct + header buf + data buf on heap
    let req_streams_heap = active_requests * 80;
    let pending_uni_heap = 4 * size_of::<u64>();
    // Per active stream: recv + send buffers on heap
    let stream_io_heap = active_streams * 2 * stream_buf_size;
    // Request data buffers: headers (512) + data (1024) per request
    let req_data_heap = active_requests * (512 + 1024);

    let heap = streams_heap
        + sent_heap
        + pn_ranges_heap
        + events_heap
        + h3_events_heap
        + req_streams_heap
        + pending_uni_heap
        + stream_io_heap
        + req_data_heap;
    (h3_struct, heap)
}

/// Estimate struct + heap for a handshake context at given crypto buf size.
fn handshake_estimate(crypto_buf: usize) -> usize {
    let hs_ctx = size_of::<HandshakeContext<C, 2048>>();
    // TlsEngine buffers: pending_write + pending_write_hs + server_cert_data
    let tls_bufs = 3 * 2048;
    // pending_crypto x3
    let pending_crypto = 3 * 2048;
    // crypto_reasm x3 at given buf size
    let crypto_reasm = 3 * crypto_buf;
    hs_ctx + tls_bufs + pending_crypto + crypto_reasm
}

/// Estimate struct + heap for HTTPS/1.1 at given TLS I/O buffer size.
fn https1_estimate(
    tls_io_buf: usize,
    http1_hdr_buf: usize,
    http1_data_buf: usize,
) -> (usize, usize) {
    let tls_struct = size_of::<TlsConnection<C>>();
    let http1_struct = size_of::<Http1Connection<1024, 2048>>();
    let io_struct = size_of::<TlsIoBufs<4096>>();
    let struc = tls_struct + http1_struct + io_struct;

    // Post-handshake: TlsEngine bufs shrunk to 0
    let http1_heap = http1_hdr_buf + http1_data_buf;
    let tls_io_heap = 3 * tls_io_buf; // net_recv (in-place decrypt), net_send, app_send
    (struc, http1_heap + tls_io_heap)
}

/// Estimate struct + heap for an H2 over TLS connection.
fn h2_tls_estimate(
    h2_tls_struct: usize,
    active_streams: usize,
    hdrbuf: usize,
    databuf: usize,
    tls_buf_size: usize,
) -> (usize, usize) {
    // H2 stream heap: Vec<H2Stream> grows on demand
    // H2Stream ≈ 48 bytes struct + Buf<HDRBUF> + Buf<DATABUF> heap per stream
    let streams_heap = active_streams * (48 + hdrbuf + databuf);
    // H2 events: VecDeque<H2Event>, typically small
    let events_heap = 8 * size_of::<H2Event>();
    // 3 shared TLS/H2 buffers (net_recv with in-place decrypt, net_send, app_send)
    let tls_io_heap = 3 * tls_buf_size;
    (h2_tls_struct, streams_heap + events_heap + tls_io_heap)
}

#[test]
fn print_memory_budget() {
    println!();
    println!("============================================================");
    println!("  MEMORY BUDGET ANALYSIS");
    println!("============================================================");
    println!();

    // ---- Element sizes ----
    println!("--- Element sizes ---");
    println!(
        "  TlsEngine<C>:               {:>6} bytes",
        size_of::<TlsEngine<C>>()
    );
    println!(
        "  Option<StreamState>:         {:>6} bytes",
        size_of::<Option<StreamState>>()
    );
    println!(
        "  Option<SentPacket>:          {:>6} bytes",
        size_of::<Option<SentPacket>>()
    );
    println!(
        "  Event (QUIC):                {:>6} bytes",
        size_of::<Event>()
    );
    println!(
        "  H3Event:                     {:>6} bytes",
        size_of::<H3Event>()
    );
    println!(
        "  H2Event:                     {:>6} bytes",
        size_of::<H2Event>()
    );
    println!(
        "  HandshakeContext<C>:         {:>6} bytes",
        size_of::<HandshakeContext<C, 2048>>()
    );
    println!();

    // ---- Composite struct sizes ----
    println!("--- Struct sizes (with alloc, excludes heap backing) ---");
    println!(
        "  Connection<C> (defaults):    {:>6} bytes",
        size_of::<Connection<C, 32, 128, 4>>()
    );
    println!(
        "  Connection<C, 8, 32, 2>:     {:>6} bytes",
        size_of::<Connection<C, 8, 32, 2>>()
    );
    println!(
        "  H3Server<C> (defaults):      {:>6} bytes",
        size_of::<H3Server<C>>()
    );
    println!(
        "  H3Server<C, 8,32,2,512,8>:   {:>6} bytes",
        size_of::<H3Server<C, 8, 32, 2, 512, 8>>()
    );
    println!(
        "  H2TlsServer<C> (defaults):   {:>6} bytes",
        size_of::<H2TlsServer<C>>()
    );
    println!(
        "  H2TlsServer<C,8192,4,1024,2048>: {:>4} bytes",
        size_of::<H2TlsServer<C, 8192, 4, 1024, 2048>>()
    );
    println!(
        "  Https1Server<C> (defaults):  {:>6} bytes",
        size_of::<Https1Server<C>>()
    );
    println!(
        "  TlsConnection<C>:           {:>6} bytes",
        size_of::<TlsConnection<C>>()
    );
    println!(
        "  HandshakePool<C, 2>:         {:>6} bytes",
        size_of::<HandshakePool<C, 2, 2048>>()
    );
    println!();

    // ---- ServerManager + TlsParts sizes ----
    println!("--- ServerManager overhead ---");
    println!(
        "  ServerManager<C,()> (defaults): {:>4} bytes",
        size_of::<ServerManager<C, ()>>()
    );
    println!(
        "  TlsParts<C, 4096>:           {:>6} bytes",
        size_of::<TlsParts<C, 4096>>()
    );
    println!(
        "  TlsParts<C, 2048>:           {:>6} bytes",
        size_of::<TlsParts<C, 2048>>()
    );
    // Note: With alloc, Buf<N> is Vec<u8> (24 bytes struct).
    // The BUF param is a capacity cap, not upfront allocation.
    // Peak heap per TlsParts = 4 * BUF (when all 4 bufs are at capacity).
    println!(
        "  -> Peak heap per TlsParts<4096>: {} bytes (4 x 4096)",
        4 * 4096
    );
    println!(
        "  -> Peak heap per TlsParts<2048>: {} bytes (4 x 2048)",
        4 * 2048
    );
    println!();

    // ================================================================
    // PRIMARY TARGET: 1 HTTPS/1.1 + 4 H3 + 2 H3 handshake slots
    // ================================================================

    let pool_struct = size_of::<HandshakePool<C, 2, 2048>>();

    // ---- Compact config ----
    println!("============================================================");
    println!("  COMPACT: 512B stream bufs, 4096B TLS I/O, 2048B crypto");
    println!("  Target: 1 HTTPS/1.1 + 4 H3 (2 est + 2 HS)");
    println!("============================================================");
    println!();

    let h3_struct_compact = size_of::<H3Server<C, 8, 32, 2, 512, 8>>();
    let (h3s, h3h) = h3_estimate(h3_struct_compact, 4, 512, 32, 2);
    let h3_total_compact = h3s + h3h;
    println!(
        "  Per H3 (4 active streams):   {:>6} bytes  (struct {} + heap {})",
        h3_total_compact, h3s, h3h
    );

    let hs_compact = handshake_estimate(2048);
    println!("  Per handshake (additional):  {:>6} bytes", hs_compact);

    let (h1s, h1h) = https1_estimate(4096, 1024, 2048);
    let https1_compact = h1s + h1h;
    println!(
        "  HTTPS/1.1 (established):     {:>6} bytes  (struct {} + heap {})",
        https1_compact, h1s, h1h
    );

    // TCP handshake in progress: TlsParts<C, 4096> peak heap
    let tcp_hs_compact = 4 * 4096; // 4 bufs at capacity during handshake
    println!(
        "  TCP handshake (TlsParts):    {:>6} bytes  (peak heap for 4096B bufs)",
        tcp_hs_compact
    );

    let total_compact = 2 * h3_total_compact
        + 2 * (h3_total_compact + hs_compact)
        + https1_compact
        + tcp_hs_compact
        + pool_struct;
    println!();
    println!(
        "  2x established H3:           {:>6} bytes",
        2 * h3_total_compact
    );
    println!(
        "  2x handshaking H3:           {:>6} bytes",
        2 * (h3_total_compact + hs_compact)
    );
    println!("  1x HTTPS/1.1 (established):  {:>6} bytes", https1_compact);
    println!("  1x TCP handshake in progress:{:>6} bytes", tcp_hs_compact);
    println!("  Pool struct:                 {:>6} bytes", pool_struct);
    println!(
        "  TOTAL:                       {:>6} bytes  ({:.1} KB)",
        total_compact,
        total_compact as f64 / 1024.0
    );
    print_budget_status(total_compact);
    println!();

    // ---- Tight config ----
    println!("============================================================");
    println!("  TIGHT: 256B stream bufs, 2048B TLS I/O, 1024B crypto");
    println!("  Target: 1 HTTPS/1.1 + 4 H3 (2 est + 2 HS)");
    println!("============================================================");
    println!();

    let h3_struct_tight = size_of::<H3Server<C, 4, 16, 2, 256, 4>>();
    let (h3s_t, h3h_t) = h3_estimate(h3_struct_tight, 2, 256, 16, 1);
    let h3_total_tight = h3s_t + h3h_t;
    println!(
        "  Per H3 (2 active streams):   {:>6} bytes  (struct {} + heap {})",
        h3_total_tight, h3s_t, h3h_t
    );

    let hs_tight = handshake_estimate(1024);
    println!("  Per handshake (additional):  {:>6} bytes", hs_tight);

    let (h1s_t, h1h_t) = https1_estimate(2048, 512, 1024);
    let https1_tight = h1s_t + h1h_t;
    println!(
        "  HTTPS/1.1 (established):     {:>6} bytes  (struct {} + heap {})",
        https1_tight, h1s_t, h1h_t
    );

    let tcp_hs_tight = 4 * 2048;
    println!(
        "  TCP handshake (TlsParts):    {:>6} bytes  (peak heap for 2048B bufs)",
        tcp_hs_tight
    );

    let total_tight = 2 * h3_total_tight
        + 2 * (h3_total_tight + hs_tight)
        + https1_tight
        + tcp_hs_tight
        + pool_struct;
    println!();
    println!(
        "  2x established H3:           {:>6} bytes",
        2 * h3_total_tight
    );
    println!(
        "  2x handshaking H3:           {:>6} bytes",
        2 * (h3_total_tight + hs_tight)
    );
    println!("  1x HTTPS/1.1 (established):  {:>6} bytes", https1_tight);
    println!("  1x TCP handshake in progress:{:>6} bytes", tcp_hs_tight);
    println!("  Pool struct:                 {:>6} bytes", pool_struct);
    println!(
        "  TOTAL:                       {:>6} bytes  ({:.1} KB)",
        total_tight,
        total_tight as f64 / 1024.0
    );
    print_budget_status(total_tight);
    println!();

    // ================================================================
    // H2/TLS ADDENDUM (not in 100KB budget)
    // ================================================================
    println!("============================================================");
    println!("  H2/TLS ADDENDUM (not in 100KB budget)");
    println!("============================================================");
    println!();

    let h2_struct_compact = size_of::<H2TlsServer<C, 8192, 4, 1024, 2048>>();
    let (h2s, h2h) = h2_tls_estimate(h2_struct_compact, 4, 1024, 2048, 8192);
    let h2_total_compact = h2s + h2h;
    println!(
        "  H2/TLS compact (4 streams):  {:>6} bytes  (struct {} + heap {})",
        h2_total_compact, h2s, h2h
    );

    let h2_struct_tight = size_of::<H2TlsServer<C, 4096, 2, 512, 1024>>();
    let (h2s_t, h2h_t) = h2_tls_estimate(h2_struct_tight, 2, 512, 1024, 4096);
    let h2_total_tight = h2s_t + h2h_t;
    println!(
        "  H2/TLS tight (2 streams):    {:>6} bytes  (struct {} + heap {})",
        h2_total_tight, h2s_t, h2h_t
    );
    println!();

    println!("============================================================");
}

fn print_budget_status(total: usize) {
    let goal: usize = 102400;
    if total <= goal {
        println!(
            "  -> UNDER BUDGET by {} bytes ({:.1} KB)",
            goal - total,
            (goal - total) as f64 / 1024.0
        );
    } else {
        println!(
            "  -> OVER BUDGET by {} bytes ({:.1} KB)",
            total - goal,
            (total - goal) as f64 / 1024.0
        );
    }
}
