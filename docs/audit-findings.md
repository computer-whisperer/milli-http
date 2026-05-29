# Audit Findings

Living record of correctness/security review findings across all subsystems.
Two passes so far:

- **2026-03-13** — first deep review (original section, preserved at the bottom).
- **2026-05-29** — independent broad-sweep re-review of all ~40k lines. This
  pass re-derived most of the still-open 2026-03-13 items, fixed every Critical,
  and uncovered new findings. Status below reflects this pass.

Status legend:
- **FIXED** — corrected and verified against the code, with a regression test where practical (commit noted).
- **OPEN (verified)** — confirmed present by reading the cited code in this pass; not yet fixed.
- **OPEN (reported)** — surfaced by the sweep but **not yet independently verified**; treat as a lead, confirm before acting.
- **DESIGN** — intentional-looking trade-off awaiting an explicit decision, not a clear bug.

Branch for the 2026-05-29 fixes: `fix/critical-audit-findings` (unmerged).

---

## Critical

- [x] **FIXED — QUIC congestion window never enforced** (`15ce86c`). `poll_transmit`
  recorded `on_packet_sent` but never consulted `can_send`/`available_window`, so
  cwnd/slow-start/recovery had no effect (network flooding, RFC 9002 §7).
  `build_short_packet` now bounds new STREAM data by the available window; ACK and
  control frames are exempt so a cwnd-limited connection still makes progress.
  Test: `congestion_window_gates_stream_data`. Files: `connection/transmit.rs`.

- [x] **FIXED — connection + per-stream receive flow control never enforced** (`964f64a`).
  `recv.rs` discarded `mark_recv`'s result (dropping per-stream `FlowControlError`/
  `FinalSizeError`) and never called `flow_control.on_recv`; the matching
  `MAX_DATA`/`MAX_STREAM_DATA` replenishment was never emitted. Now enforced and
  replenished (`should_send_max_data`/`max_data_sent`, new `should_send_max_stream_data`/
  `mark_max_stream_data_sent`). Also fixed a latent auto-tune step bug in `mark_recv`.
  Tests: `mark_recv_reports_new_bytes_and_triggers_max_stream_data`,
  `transfer_exceeds_initial_flow_control_windows`. Files: `connection/recv.rs`,
  `connection/transmit.rs`, `transport/stream.rs`.

- [x] **FIXED — H2 CONTINUATION flood / no header-list-size limit** (`44e7912`,
  CVE-2024-27316 class). HEADERS/CONTINUATION fragments were appended with
  `let _ = extend_from_slice(...)`; once `HDRBUF` filled, bytes were silently
  dropped while the loop consumed CONTINUATION frames unboundedly, and the
  truncated block was decoded as complete. Now bounds the field section and
  terminates with `ENHANCE_YOUR_CALM` on overflow. Test:
  `continuation_flood_rejected`. File: `h2/connection.rs`.

- [x] **FIXED — TLS record send-sequence desync** (`e3a87c1`). `send_seq`/`hs_send_seq`
  were incremented before `encrypt_into`; a buffer-full failure consumed a
  sequence number with no record emitted, permanently desyncing the peer's nonce
  (triggerable by ordinary backpressure). Sequence now advances only after a
  record is committed (recv paths made consistent too). File: `tcp_tls/connection.rs`.

- [x] **FIXED — server completes handshake on ALPN mismatch** (`c3e57d9`). When the
  client offered ALPN and no protocol overlapped, `selected_alpn` stayed `None`
  and the handshake completed, then routed to a default handler (a client offering
  only "h3" could be misdirected to HTTP/1.1). Now aborts per RFC 7301 §3.2 /
  RFC 9001 §8.1 (a no-ALPN client is still allowed). Note: this engine has no TLS
  alert pipeline, so it aborts rather than sending `no_application_protocol`. Test:
  `server_rejects_alpn_mismatch`. Files: `tls/handshake.rs`, `server/mod.rs`.

- [x] **FIXED (enabling) — per-stream receive buffer never reclaimed space** (`49e3829`).
  `StreamRecvBuf.len` only grew; once the buffer first filled, `store_stream_data`
  silently dropped all further data, capping single-stream throughput at
  `STREAM_BUF` (1024 B default) regardless of flow control. `stream_recv` now
  compacts read bytes off the front. File: `connection/mod.rs`.

- [x] **FIXED (enabling) — opened-stream send window deadlock** (`49e3829`).
  Locally-opened streams seeded `send.max_data` from a 64 KiB placeholder and never
  applied the peer's advertised `initial_max_stream_data`; the sender blocked at
  64 KiB while the receiver's grant threshold sat at 128 KiB — a permanent deadlock
  on any single-stream transfer over 64 KiB. `open_stream`/`open_uni_stream` now
  seed windows from negotiated params (new `StreamMap::set_stream_windows`).
  Files: `connection/mod.rs`, `transport/stream.rs`.

- **DESIGN — server authentication is certificate-pinning only.** No X.509 chain
  validation and **no hostname/SAN verification**; if `pinned_certs` is empty all
  cert verification is skipped (documented "insecure, for testing") with nothing
  preventing that in production. Defensible for embedded, but the "empty = silently
  insecure" default is a sharp edge. **Needs an explicit threat-model decision.**
  Files: `tls/handshake.rs:516`.

## High

- [ ] **OPEN (verified) — public-key extraction trusts first OID/BIT-STRING match.**
  `extract_*_pubkey_from_cert` pattern-matches the curve OID then scans for the
  first BIT STRING of the expected length, rather than structurally parsing the
  SubjectPublicKeyInfo. A crafted cert can steer extraction. Exploitability is
  gated by the pinning model above. Files: `crypto/ecdsa_p256.rs`, `crypto/ed25519.rs`.

- [ ] **OPEN (reported) — key-update "confirmed" set on any current-phase packet**
  rather than on an ACK of a packet sent in the new phase (RFC 9001 §6.1); can
  desync 1-RTT keys under reordering / a malicious peer. File: `connection/recv.rs:538`.

- [ ] **OPEN (reported) — RecvPnTracker evicts its lowest range when full** (cap 32),
  re-enabling replay of old packet numbers (RFC 9000 §12.3). File: `connection/mod.rs:270`.

- [ ] **OPEN (reported) — ACK ranges parsed into a cap-16 Vec with silent `push` drop**,
  causing spurious retransmits when a peer sends many ranges. File: `connection/recv.rs:688`.

- [ ] **OPEN (reported) — H2 `send_window += delta` unchecked** on SETTINGS_INITIAL_WINDOW_SIZE
  change → debug panic / release wrap (RFC 9113 §6.9.2 FLOW_CONTROL_ERROR). File: `h2/connection.rs:784`.

- [ ] **OPEN (reported) — H2 no MAX_CONCURRENT_STREAMS enforcement**; at-capacity streams
  silently dropped instead of RST_STREAM(REFUSED_STREAM)/GOAWAY. File: `h2/connection.rs`.

- [ ] **OPEN (reported) — H2 no Rapid Reset mitigation** (CVE-2023-44487). File: `h2/connection.rs`.

- [ ] **OPEN (reported) — H2 per-stream receive flow control not enforced** (only
  connection-level). File: `h2/connection.rs:686`.

- [ ] **OPEN (reported) — H2 no inbound stream-ID parity/monotonicity validation**
  (RFC 9113 §5.1.1). File: `h2/connection.rs`.

- [ ] **OPEN (reported) — TLS: QUIC transport-parameters extension not required**
  (RFC 9001 §8.2 mandates TRANSPORT_PARAMETER_ERROR if absent). File: `tls/handshake.rs:474`.

- [ ] **OPEN (reported) — TLS: no ServerHello downgrade-sentinel check** (RFC 8446 §4.1.3);
  legacy_version/compression unvalidated. File: `tls/handshake.rs`, `tls/messages.rs`.

- [ ] **OPEN (reported) — TLS: duplicate extensions silently overwrite** (RFC 8446 §4.2). File: `tls/extensions.rs`.

- [ ] **OPEN (reported) — HTTP/1.1 request smuggling vectors:** whitespace between
  header-name and colon not rejected; bare CR/LF in header values not rejected
  (RFC 9112 §5.1 / RFC 9110 §5.5). File: `http1/connection.rs`, `http1/parse.rs`.

- [ ] **OPEN (reported) — incoming TLS record length not validated vs `MAX_RECORD_PAYLOAD`**
  (defined but unused; RFC 8446 §5.2 record_overflow). File: `tcp_tls/connection.rs`.

- [ ] **OPEN (reported) — server socket leaks:** (a) a dropped `Closed` event on the
  event-ring overflow and (b) an Established-phase `tcp_feed` error that never
  closes/emits leave live sockets stuck. Files: `server/mod.rs`, `server/runner.rs`.

- [ ] **OPEN (reported) — QUIC handshake retransmits create a new connection per packet**
  (client's original DCID never added to `local_cids`) → slot/handshake-pool
  exhaustion. Files: `server/mod.rs`, `connection/recv.rs`.

- [ ] **OPEN (reported) — H3 silent header truncation** sets `headers_received = true`
  after a discarded over-capacity `extend_from_slice`; no request-stream frame
  state machine; control stream doesn't enforce SETTINGS-first/single. File: `h3/connection.rs`.

- [ ] **OPEN (reported) — send-side connection flow control (`on_send`) not enforced,
  and MAX_STREAMS never emitted** — remaining "telemetry-only" gaps in the flow-control
  subsystem (the receive side was fixed in C2 above). Files: `connection/transmit.rs`, `transport/flow_control.rs`.

- [ ] **OPEN (reported) — `max_ack_delay` taken from local, not peer, transport params**
  and never updated (RFC 9002). Files: `connection/mod.rs`, `transport/loss.rs`.

## Medium / Low

- [ ] OPEN (verified) — `parse_initial_header`/`parse_handshake_header` don't validate
  `payload_length` against the buffer (safe only because the coalescer pre-validates;
  the public parsers would panic on a direct malformed call). `packet/long_header.rs`.
- [ ] OPEN (verified) — CID length not validated ≤ 20 on parse (RFC 9000 §17.2). `packet/long_header.rs`, `packet/decode_dcid.rs`.
- [ ] OPEN (reported) — STREAM/CRYPTO `offset+length` and ACK range-vs-largest not
  bounds-checked against 2^62 (masked downstream by saturating arithmetic). `frame/mod.rs`.
- [ ] OPEN (reported) — out-of-order STREAM data dropped and `mark_recv` still advances
  offset (correctness/throughput). `transport/stream.rs`, `connection/mod.rs`.
- [ ] OPEN (reported) — `as usize` varint truncation on 32-bit targets (several sites).
- [ ] OPEN (reported) — Alt-Svc host injection from untrusted config. `discovery/alt_svc.rs`.
- [ ] OPEN (reported) — `next_id` u32 overflow → connection-ID aliasing. `server/mod.rs`.
- [ ] OPEN (reported) — debug `eprintln!` of handshake structure under `std`. `tls/handshake.rs`, `connection/recv.rs`.
- [ ] OPEN (reported, from 2026-03-13) — ECDSA non-deterministic (no RFC 6979); hand-rolled `ct_eq` vs `subtle`.
- [ ] OPEN (reported, from 2026-03-13) — H1 case-preserving vs H2/H3 lowercasing in `HttpServerConn`; ~1530 duplicated lines across `h2_tls.rs`/`https1.rs`; `server` feature forces all protocols.
- **CHECKED, likely NON-ISSUE** — HPACK/QPACK Huffman `acc << 8` accumulator overflow:
  the QPACK reviewer flagged it as theoretically possible but the H2 reviewer fuzzed
  it and could not reach it (the `acc_len >= 30` guard prevents it). Recommend a
  property test against a reference decoder to close it out.

---

## Original review — 2026-03-13 (historical)

Consolidated findings from the first deep review. Items below were the state as of
that pass; several High items have since been fixed in the 2026-05-29 pass above
(congestion window, CONTINUATION bombing, TLS send_seq, ALPN rejection) — see the
current section for authoritative status.

### Critical (all marked done in the 2026-03-13 pass)

- [x] Stack overflow from hardcoded internal buffers — `connection/recv.rs`, `connection/transmit.rs`
- [x] No secret zeroization — `tls/handshake.rs`, `tls/key_schedule_tls.rs`, `tls/mod.rs`, `connection/keys.rs`
- [x] No X25519 shared secret validation — `tls/handshake.rs`
- [x] No duplicate packet number rejection — `connection/mod.rs`, `connection/recv.rs`
- [x] No AEAD usage limit tracking — `connection/keys.rs`, `connection/recv.rs`, `connection/transmit.rs`
- [x] H2: No received frame size validation — `h2/connection.rs`
- [x] H3: Hardcoded per-stream buffers — `h3/connection.rs`, `h3/server.rs`, `h3/client.rs`, `server/mod.rs`

### High (2026-03-13 — see current section for updated status)

- [x] No congestion window enforcement → **FIXED 2026-05-29 (C1)**
- [ ] Out-of-order stream data dropped — `connection/mod.rs`
- [ ] Silent data loss from fixed-capacity collections — `transport/recovery.rs`, `transport/loss.rs`, `connection/recv.rs`
- [ ] CONNECTION_CLOSE skips Draining state — `connection/recv.rs`
- [ ] Unknown frame types cause connection error — `connection/recv.rs` (note: 2026-05-29 review found this is actually RFC-correct for QUIC; verify before changing)
- [ ] `ack_delay` hardcoded to 0 — `connection/transmit.rs`
- [x] Server accepts handshake with no ALPN match → **FIXED 2026-05-29 (C5)**
- [x] `TlsKeySchedule` fields are `pub` — made private
- [ ] H2: `ensure_stream` silently drops at capacity — `h2/connection.rs`
- [x] H2: CONTINUATION bombing / no header size limit → **FIXED 2026-05-29 (C3)**
- [x] TLS `send_seq` incremented before encryption → **FIXED 2026-05-29 (C4)**
- [ ] `server` feature forces all protocols — `Cargo.toml`

### Medium (2026-03-13)

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
