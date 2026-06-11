//! Sustained multi-megabyte HTTP/2-over-TLS upload, end to end, at hardware
//! buffer sizes — the coverage the firmware OTA path was missing.
//!
//! `h2_tls_hw_sized_upload_burst` (in `src/h2_tls.rs`) deliberately drops the
//! server's output to model curl mid-burst, and it is a one-shot ~tens-of-KB
//! burst that never sends a response. That left two real-world behaviours
//! untested:
//!
//!   1. **Sustained streaming.** A multi-MB body only flows if the client keeps
//!      getting flow-control credit, which requires *processing* the server's
//!      consumption-driven `WINDOW_UPDATE`s. This test feeds the server→client
//!      direction so credit recirculates and the transfer sustains over
//!      hundreds of records — exercising the decrypt-in-place hidden-tail
//!      compaction repeatedly across many flow-control round-trips.
//!   2. **The request→response→teardown cycle.** The hardware OOM struck when
//!      the server tried to send its `200` while receive buffers were still
//!      held. This test runs that exact cycle: full body in, response out,
//!      client reads it, stream closes cleanly.

#![cfg(all(
    feature = "h2",
    feature = "tcp-tls",
    any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")
))]

use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::error::Error;
use milli_http::h2::H2Event;
use milli_http::h2_tls::{H2TlsClient, H2TlsServer};
use milli_http::tls::handshake::{ServerTlsConfig, TlsConfig};
use milli_http::tls::transport_params::TransportParams;

const TEST_SEED: [u8; 32] = [0x01u8; 32];

// Hardware-sized server: BUF=18432 (one max TLS record), DATABUF=16384 (the
// per-stream body window the peer is paced to). Same shape as the firmware.
type HwServer = H2TlsServer<Aes128GcmProvider, 18432, 8, 2048, 16384>;
// Client gets a big BUF so it can stage full records without artificial stalls
// — the device under test is the server.
type BigClient = H2TlsClient<Aes128GcmProvider, 65536, 8, 2048, 4096>;

fn test_cert() -> &'static [u8] {
    let pk = ed25519_public_key_from_seed(&TEST_SEED);
    let mut buf = [0u8; 512];
    let n = build_ed25519_cert_der(&pk, &mut buf).unwrap();
    buf[..n].to_vec().leak()
}

fn make_client() -> BigClient {
    let config = TlsConfig {
        server_name: heapless::String::try_from("test.local").unwrap(),
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };
    BigClient::new(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
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

/// Complete the TLS handshake + H2 SETTINGS exchange, delivering output in both
/// directions (unlike the burst test, the client must process the server's
/// SETTINGS so its stream window matches the server's DATABUF).
fn establish(client: &mut BigClient, server: &mut HwServer) {
    for _ in 0..40 {
        let mut progress = false;
        let mut buf = [0u8; 65536];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
            progress = true;
        }
        let mut buf2 = [0u8; 65536];
        while let Some(data) = server.poll_output(&mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }
        if !progress && client.is_established() && server.is_established() {
            break;
        }
    }
    assert!(client.is_established(), "client should be established");
    assert!(server.is_established(), "server should be established");
}

#[test]
fn h2_tls_sustained_multi_mb_upload_then_response() {
    let cert = test_cert();
    let mut client = make_client();
    let mut server = make_server(cert);

    establish(&mut client, &mut server);

    // ~3 MB request body. With a 16384-byte server stream window this forces
    // ~190 flow-control round-trips: the client can only make progress as the
    // server consumes (recv_body) and the resulting WINDOW_UPDATEs reach the
    // client. The pattern is content-addressable (byte i == (i % 251)) so we
    // can verify the server reassembled the stream in order without storing a
    // 3 MB reference copy.
    const BODY_LEN: usize = 3 * 1024 * 1024;
    let byte_at = |i: usize| (i % 251) as u8;

    let stream_id = client
        .send_request("POST", "/system/update", "test.local", &[], false)
        .unwrap();

    // Runner-style server feed: 1500-byte wire chunks (one TCP segment) and
    // recv_body drained in 1024-byte chunks, exactly like UpdateService::feed.
    let mut sent_body = 0usize; // h2 body bytes the client has handed to send_body
    let mut recv_body = 0usize; // body bytes the server has consumed + verified
    let mut wire_to_server: Vec<u8> = Vec::new(); // client→server bytes awaiting feed
    let mut send_done = false;

    let mut cobuf = [0u8; 8192];
    let mut sink = [0u8; 1024];
    let mut sobuf = [0u8; 4096];

    let mut guard = 0usize;
    let mut window_round_trips = 0usize; // cycles where the window had gone dry
    while recv_body < BODY_LEN {
        guard += 1;
        assert!(
            guard < 2_000_000,
            "stalled: recv {recv_body} sent {sent_body} of {BODY_LEN}"
        );

        // 1. Client stages as much body as its windows allow, then flushes the
        //    encrypted wire bytes into the to-server queue.
        if !send_done {
            loop {
                let remaining = BODY_LEN - sent_body;
                if remaining == 0 {
                    break;
                }
                let chunk_len = remaining.min(16384);
                let chunk: Vec<u8> = (sent_body..sent_body + chunk_len).map(byte_at).collect();
                match client.send_body(stream_id, &chunk, false) {
                    Ok(0) => break,
                    Ok(n) => sent_body += n,
                    // Window dry (need a WINDOW_UPDATE) or staging buffer full
                    // (need to flush to wire) — either way, stop staging this
                    // cycle, recirculate, and retry next cycle.
                    Err(Error::WouldBlock) => {
                        window_round_trips += 1;
                        break;
                    }
                    Err(Error::BufferTooSmall { .. }) => break,
                    Err(e) => panic!("client.send_body failed: {e:?}"),
                }
                // Flush as we go so a full send_buf doesn't wedge a large chunk.
                while let Some(data) = client.poll_output(&mut cobuf) {
                    wire_to_server.extend_from_slice(data);
                }
            }
            if sent_body == BODY_LEN {
                client.send_body(stream_id, &[], true).unwrap();
                send_done = true;
            }
        }
        while let Some(data) = client.poll_output(&mut cobuf) {
            wire_to_server.extend_from_slice(data);
        }

        // 2. Feed the server runner-style: up to 4 reads of 1500 bytes / cycle.
        let mut fed_off = 0usize;
        for _ in 0..4 {
            if fed_off >= wire_to_server.len() {
                break;
            }
            let end = (fed_off + 1500).min(wire_to_server.len());
            server.feed_data(&wire_to_server[fed_off..end]).unwrap();
            fed_off = end;
        }
        wire_to_server.drain(..fed_off);

        // 3. Drain server events; on Data, consume the body in 1024-byte chunks
        //    (this is what drives consumption-based WINDOW_UPDATEs).
        while let Some(ev) = server.poll_event() {
            match ev {
                H2Event::Headers(sid) => {
                    let mut method = Vec::new();
                    let mut path = Vec::new();
                    server
                        .recv_headers(sid, |n, v| match n {
                            b":method" => method.extend_from_slice(v),
                            b":path" => path.extend_from_slice(v),
                            _ => {}
                        })
                        .unwrap();
                    assert_eq!(method, b"POST");
                    assert_eq!(path, b"/system/update");
                }
                H2Event::Data(sid) => loop {
                    match server.recv_body(sid, &mut sink) {
                        Ok((0, _)) => break,
                        Ok((n, _fin)) => {
                            for b in &sink[..n] {
                                assert_eq!(
                                    *b,
                                    byte_at(recv_body),
                                    "body byte {recv_body} mismatch"
                                );
                                recv_body += 1;
                            }
                        }
                        Err(_) => break,
                    }
                },
                H2Event::StreamReset(sid, code) => {
                    panic!("unexpected stream reset on {sid}: {code}")
                }
                H2Event::GoAway(_, code) => panic!("unexpected GOAWAY: {code}"),
                _ => {}
            }
        }

        // 4. Recirculate server→client output (WINDOW_UPDATE, SETTINGS ack,
        //    PING, ...) so the client keeps getting flow-control credit. This
        //    is the crucial difference from the burst test, which drops it.
        while let Some(data) = server.poll_output(&mut sobuf) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
        }
    }

    assert_eq!(
        sent_body, BODY_LEN,
        "client should have sent the whole body"
    );
    assert_eq!(recv_body, BODY_LEN, "server should have received it all");
    // Sanity-check that this genuinely streamed under sustained backpressure
    // rather than completing in a couple of big bursts: a 3 MB body through a
    // 16 KB window cannot finish without the client repeatedly running its
    // window dry and waiting for the server's consumption-driven WINDOW_UPDATEs
    // (~190 in the ideal case). This is the steady-state path the burst test
    // never exercised.
    assert!(
        window_round_trips >= 50,
        "expected sustained flow-control round-trips, only saw {window_round_trips}"
    );

    // ---- Response → teardown: this is where the hardware OOM struck. ----
    // The server sends its 200 while its receive buffers are still allocated
    // (decrypt-in-place keeps net_recv around). A regression here would either
    // OOM on hardware or fail to deliver the response.
    server
        .send_response(stream_id, 200, &[(b"content-type", b"text/plain")], false)
        .unwrap();
    server
        .send_body(stream_id, b"update accepted", true)
        .unwrap();

    // Pump both directions to flush request tail + response + teardown frames.
    let mut got_status = false;
    let mut got_finished = false;
    let mut resp_body = Vec::new();
    for _ in 0..200 {
        let mut progress = false;

        while let Some(data) = server.poll_output(&mut sobuf) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            progress = true;
        }
        while let Some(data) = client.poll_output(&mut cobuf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
            progress = true;
        }

        // Server may still emit a tail Data/Finished for the request stream.
        while let Some(_ev) = server.poll_event() {}

        while let Some(ev) = client.poll_event() {
            match ev {
                H2Event::Headers(sid) if sid == stream_id => {
                    let mut status = Vec::new();
                    client
                        .recv_headers(sid, |n, v| {
                            if n == b":status" {
                                status.extend_from_slice(v);
                            }
                        })
                        .unwrap();
                    assert_eq!(status, b"200");
                    got_status = true;
                }
                H2Event::Data(sid) if sid == stream_id => {
                    let mut rb = [0u8; 256];
                    loop {
                        match client.recv_body(sid, &mut rb) {
                            Ok((0, _)) => break,
                            Ok((n, _)) => resp_body.extend_from_slice(&rb[..n]),
                            Err(_) => break,
                        }
                    }
                }
                H2Event::Finished(sid) if sid == stream_id => got_finished = true,
                H2Event::StreamReset(sid, code) => panic!("client stream reset {sid}: {code}"),
                H2Event::GoAway(_, code) => panic!("client GOAWAY: {code}"),
                _ => {}
            }
        }

        if got_status && got_finished {
            // Drain any final response-body bytes that arrived with FIN.
            let mut rb = [0u8; 256];
            while let Ok((n, _)) = client.recv_body(stream_id, &mut rb) {
                if n == 0 {
                    break;
                }
                resp_body.extend_from_slice(&rb[..n]);
            }
            break;
        }
        if !progress {
            // No frames in flight but response not yet complete — pump again;
            // the loop bound guards against a true stall.
        }
    }

    assert!(got_status, "client should have received the 200 response");
    assert!(got_finished, "client should have seen the stream finish");
    assert_eq!(
        resp_body, b"update accepted",
        "client should have received the full response body"
    );
    assert!(
        !server.is_closed(),
        "no error should have closed the server"
    );
}
