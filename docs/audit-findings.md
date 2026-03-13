# Audit Findings — 2026-03-13

Consolidated findings from deep review of all subsystems. Ordered by priority.

## Critical

- [x] **Stack overflow from hardcoded internal buffers** — Transmit and recv paths refactored to use in-place building and caller-provided scratch buffers. Remaining: `handle_crypto_frame` TLS copy buffer and `write_tls_crypto_data` (both handshake-only paths).
  Files: `connection/recv.rs`, `connection/transmit.rs`

- [x] **No secret zeroization** — Added `zeroize` crate. `Drop` impls on `TlsKeySchedule`, `TlsEngine`, `KeyUpdateState`, `DerivedKeys` zeroize all raw secret byte arrays. x25519-dalek `StaticSecret` already self-zeroizes.
  Files: `tls/handshake.rs`, `tls/key_schedule_tls.rs`, `tls/mod.rs`, `connection/keys.rs`

- [x] **No X25519 shared secret validation** — All-zeros check added after `diffie_hellman()` on both client (ServerHello) and server (ClientHello) paths.
  File: `tls/handshake.rs`

- [x] **No duplicate packet number rejection** — Added `RecvPnTracker::contains()` method. Duplicate PNs rejected in `recv_initial`, `recv_handshake` (post-decrypt), and `recv_short` (pre-decrypt, saves AEAD cost).
  Files: `connection/mod.rs`, `connection/recv.rs`

- [x] **No AEAD usage limit tracking** — Added `packets_encrypted`/`packets_decrypted` counters on `KeyUpdateState`, reset on key update. `AEAD_CONFIDENTIALITY_LIMIT = 2^23`. Auto key update in `poll_transmit` when limit reached.
  Files: `connection/keys.rs`, `connection/recv.rs`, `connection/transmit.rs`

- [x] **H2: No received frame size validation** — Added `payload_len > local_settings.max_frame_size` check in frame receive loop, returns `FrameSizeError`.
  File: `h2/connection.rs`

- [x] **H3: Hardcoded per-stream buffers** — `RequestStreamState` parameterized with `const H3_HDR_BUF` and `const H3_DATA_BUF` (defaults: 512, 1024). Threaded through `H3Connection`, `H3Server`, `H3Client`, `ServerManager`.
  Files: `h3/connection.rs`, `h3/server.rs`, `h3/client.rs`, `server/mod.rs`

## High

- [ ] **No congestion window enforcement** — `poll_transmit` never consults `CongestionController.cwnd`. Will flood the network unchecked. RFC 9002.
  Files: `connection/transmit.rs`, `transport/congestion.rs`

- [ ] **Out-of-order stream data dropped** — `store_stream_data` drops data at offsets beyond cursor. Forces retransmission, severely degrades throughput on lossy links.
  File: `connection/mod.rs`

- [ ] **Silent data loss from fixed-capacity collections** — Multiple `let _ = vec.push(...)` silently discard ACK ranges (cap 32), lost packets (cap 64), application events. Excess ACKs cause spurious retransmissions.
  Files: `transport/recovery.rs`, `transport/loss.rs`, `connection/recv.rs`

- [ ] **CONNECTION_CLOSE skips Draining state** — Transitions directly to Closed instead of Draining for 3 PTO. Peer keeps retransmitting. RFC 9000 §10.2.
  File: `connection/recv.rs`

- [ ] **Unknown frame types cause connection error** — RFC 9000 §12.4 says unknown types ≥0x1f must be ignored. Currently any unknown type is fatal, breaking GREASE and extensions.
  File: `connection/recv.rs`

- [ ] **`ack_delay` hardcoded to 0** — Peer can't compensate for processing delay in RTT samples. Overestimates RTT, suboptimal loss detection. RFC 9000 §19.3.
  File: `connection/transmit.rs`

- [ ] **Server accepts handshake with no ALPN match** — When `selected_alpn` is None, server continues silently. RFC 9001 §8.1 requires `NO_APPLICATION_PROTOCOL`.
  File: `tls/handshake.rs`

- [x] **`TlsKeySchedule` fields are `pub`** — Made `early_secret`, `handshake_secret`, `master_secret` private. All access was already internal to the module.
  File: `tls/key_schedule_tls.rs`

- [ ] **H2: `ensure_stream` silently drops at capacity** — New streams discarded instead of `RST_STREAM(REFUSED_STREAM)` or `GOAWAY`. RFC 9113 §5.1.2.
  File: `h2/connection.rs`

- [ ] **H2: CONTINUATION bombing / no header size limit** — Continuation frames append without checking `max_header_list_size`. Buffer fills, truncates HPACK data silently.
  File: `h2/connection.rs`

- [ ] **TLS `send_seq` incremented before encryption** — If `encrypt_into` fails (buffer full), sequence counter desynchronizes. All subsequent records fail to decrypt. Data corruption.
  File: `tcp_tls/connection.rs`

- [ ] **`server` feature forces all protocols** — Requires alloc + tcp-tls + http + h2 + http1 + h3. TCP-only server still pulls entire QUIC stack.
  File: `Cargo.toml`

## Medium

- [ ] O(n²) send queue drain in `build_stream_frames` — `connection/transmit.rs`
- [ ] No TLS record length validation vs `MAX_RECORD_PAYLOAD` — `tcp_tls/connection.rs`
- [ ] Certificate extraction uses fragile OID pattern-matching — `crypto/ed25519.rs`, `crypto/ecdsa_p256.rs`
- [ ] ECDSA signing non-deterministic (no RFC 6979) — `crypto/ecdsa_p256.rs`
- [ ] Hand-rolled `ct_eq` instead of `subtle::ConstantTimeEq` — `tls/handshake.rs`
- [ ] H1 preserves header casing, H2/H3 lowercases — `HttpServerConn` doesn't unify
- [ ] TLS timeout not integrated with H2/H1 timeouts in wrappers — `h2_tls.rs`, `https1.rs`
- [ ] ~1530 lines duplicated across `h2_tls.rs` / `https1.rs`
- [ ] `HttpServerConn` name wrong — clients implement it too
- [ ] 11 const generic parameters on `ServerRunner`
- [ ] `max_ack_delay` hardcoded, never updated from transport params — `transport/loss.rs`
