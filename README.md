# milli-http

[![CI](https://github.com/computer-whisperer/milli-http/actions/workflows/ci.yml/badge.svg)](https://github.com/computer-whisperer/milli-http/actions/workflows/ci.yml)

A `no_std` HTTP/1.1, HTTP/2, and HTTP/3 stack for embedded systems — including
its own QUIC transport and TLS 1.3 implementation. Client and server, no
allocator required, `#![forbid(unsafe_code)]`, stable Rust.

The goal: serve a real browser (or `curl --http3`) from a microcontroller.
A full HTTPS server — one HTTPS/1.1 connection, four concurrent HTTP/3
connections, and two in-flight QUIC handshakes — fits in well under 100 KB of
SRAM.

## What's inside

| Layer | RFC | Notes |
|---|---|---|
| HTTP/1.1 | 9110, 9112 | Keep-alive, chunked transfer, pipelining-safe parsing |
| HTTP/2 | 9113 | Multiplexed streams, flow control, HPACK (RFC 7541) |
| HTTP/3 | 9114 | Request/response over QUIC streams, QPACK (RFC 9204) |
| QUIC v1 | 9000 | Streams, flow control, connection IDs, varint codec |
| Packet protection | 9001 | Header protection, payload AEAD, key schedule |
| Loss recovery | 9002 | PTO, ACK ranges, NewReno congestion control |
| TLS 1.3 | 8446 | Handshake-only for QUIC; full record layer for HTTPS/1.1 and H2 over TCP |
| Alt-Svc discovery | 7838 | Browser-compatible HTTP/1.1 → HTTP/3 upgrade path |

Everything is implemented in this crate — there is no dependency on `quinn`,
`rustls`, `hyper`, or an OS network stack. The only dependencies are
RustCrypto primitive crates (AES-GCM, ChaCha20-Poly1305, SHA-2, HKDF, x25519,
ed25519, P-256) and `heapless`.

## Design

**Sans-IO.** The protocol state machines never touch a socket. You feed bytes
in, poll bytes out, and poll events — the I/O loop, the executor, and the
platform are yours:

```rust
let mut server = Http1Server::<8192, 2048, 4096>::new();

loop {
    // 1. Feed received bytes into the state machine.
    if let Ok(n) = socket.read(&mut recv_buf) {
        server.feed_data(&recv_buf[..n])?;
    }

    // 2. Drain pending output to the wire.
    while let Some(data) = server.poll_output(&mut out_buf) {
        socket.write_all(data)?;
    }

    // 3. React to protocol events.
    while let Some(event) = server.poll_event() {
        match event {
            Http1Event::Headers(stream_id) => {
                server.send_response(stream_id, 200, &headers, false)?;
                server.send_body(stream_id, body, true)?;
            }
            _ => {}
        }
    }
}
```

The same `feed_data` / `poll_output` / `poll_event` pattern runs through every
layer, from raw QUIC connections up to the multi-protocol server manager.
Platform integration is a handful of small traits: `UdpSocket`, `TcpStream`,
`Clock`, `Rng`.

**No allocator required.** The core works on heapless, caller-sized buffers
(`heapless::Vec` under the hood). Enabling the `alloc` feature switches
internal buffers to heap-backed `Vec`, which cuts idle-state RAM dramatically
— buffers only cost memory while they're in use, and handshake state is
released after the handshake completes.

**Pluggable crypto.** AEAD, HKDF, and key exchange are behind a
`CryptoProvider` trait. Default implementations use RustCrypto
(`rustcrypto-chacha` enables ChaCha20-Poly1305 + AES-GCM; `rustcrypto-aes` is
AES-only for smaller flash). Certificates: Ed25519 and ECDSA P-256.

## Memory footprint

Measured for the target configuration of 1 HTTPS/1.1 connection + 4 active
HTTP/3 connections + 2 simultaneous QUIC handshakes, with `alloc` enabled
(struct + peak heap):

| Profile | Per H3 conn | Per handshake | HTTPS/1.1 | Total |
|---|---|---|---|---|
| Compact (512 B stream bufs) | 11.6 KB | +20.5 KB | 21.6 KB | ~106 KB |
| Tight (256 B stream bufs) | 6.2 KB | +17.5 KB | 11.9 KB | **~70 KB** |

Buffer sizes are const generics, so you choose the trade-off per connection.
See [`docs/memory-reduction.md`](docs/memory-reduction.md) for methodology and
`cargo test --all-features memory_budget -- --nocapture` for live numbers.

## Examples

All examples run on `std` sockets and are tested against curl
(`tests/curl_interop.sh`):

```bash
# HTTP/3 server, then: curl -k --http3 https://127.0.0.1:4433/
cargo run --example h3_server --features h3,rustcrypto-chacha

# HTTP/2 over TLS, then: curl -k --http2 https://127.0.0.1:9444/
cargo run --example h2_tls_server --features h2,tcp-tls,rustcrypto-chacha

# Plain HTTP/1.1, then: curl http://127.0.0.1:8080/
cargo run --example http1_server --features http1

# All three protocols behind one event loop (Alt-Svc upgrade path)
cargo run --example multi_server --features h3,h2,rustcrypto-chacha

# Client that discovers and upgrades HTTP/1.1 → H2 → H3
cargo run --example omni_client --features h3,h2,http1,rustcrypto-chacha
```

## Feature flags

| Feature | Pulls in | Purpose |
|---|---|---|
| `quic` | — | QUIC v1 transport (default) |
| `h3` | `quic`, `http` | HTTP/3 + QPACK (default) |
| `h2` | `http` | HTTP/2 + HPACK over TCP |
| `http1` | `http` | HTTP/1.1 over TCP |
| `tcp-tls` | `http` | TLS 1.3 record layer for HTTPS/1.1 and H2 |
| `rustcrypto-chacha` | RustCrypto | ChaCha20-Poly1305 + AES-GCM providers (default) |
| `rustcrypto-aes` | RustCrypto | AES-GCM only (smaller flash) |
| `alloc` | — | Heap-backed internal buffers (lower idle RAM) |
| `std` | — | `std` integration for tests and examples |
| `server` | `alloc`, `tcp-tls` | Multi-protocol connection manager |
| `discovery` | — | Alt-Svc parsing/generation for protocol upgrade |

## Testing

- 800+ unit + integration tests, including RFC 8448 TLS 1.3 test vectors and
  packet-level QUIC handshake exchanges
- End-to-end interop against curl for all five server examples
  (`tests/curl_interop.sh`)
- `cargo-fuzz` targets for the varint, frame, packet-header, TLS-message,
  HPACK/QPACK decoders (`fuzz/`)
- Memory budget regression tests (`tests/memory_budget.rs`,
  `tests/heap_measurement.rs`, `tests/stack_measurement.rs`)
- A living internal audit log: [`docs/audit-findings.md`](docs/audit-findings.md)

## Security status

This crate contains an independent implementation of TLS 1.3 and QUIC packet
protection. It has been reviewed and fuzzed internally (see
[`docs/audit-findings.md`](docs/audit-findings.md)), but it has **not**
received an external security audit. The cryptographic primitives come from
the RustCrypto project; the handshake and protocol logic are this crate's own.
Evaluate accordingly before exposing it to hostile networks in production.

## Status

Active development. The protocol surface above works end-to-end against curl
and Firefox, but APIs are not yet stable and there has been no crates.io
release.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
