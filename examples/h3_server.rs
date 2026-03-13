//! Simple HTTP/3 test server for use with `curl --http3`.
//!
//! Binds a UDP socket on `0.0.0.0:4433`, accepts one QUIC connection,
//! completes the TLS 1.3 handshake, and responds to every HTTP/3 request
//! with an HTML page.
//!
//! Usage (self-signed, for quick testing):
//!   cargo run --example h3_server --features h3,rustcrypto-chacha
//!
//! Usage (with external cert, for Firefox demo):
//!   cargo run --example h3_server --features h3,rustcrypto-chacha -- \
//!       --cert examples/certs/server_cert.der --key examples/certs/server_key.der
//!
//! Then from another terminal:
//!   curl -k --http3 https://127.0.0.1:4433/

use std::io::Write;
use std::net::UdpSocket;
use std::time;

use milli_http::Rng;
use milli_http::connection::{Connection, HandshakePool};
use milli_http::crypto::ecdsa_p256;
use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h3::H3Event;
use milli_http::h3::server::H3Server;
use milli_http::tls::handshake::ServerTlsConfig;
use milli_http::tls::transport_params::TransportParams;

// ---------------------------------------------------------------------------
// RNG wrapper around the `rand` crate
// ---------------------------------------------------------------------------

struct StdRng(rand::rngs::ThreadRng);

impl StdRng {
    fn new() -> Self {
        Self(rand::rng())
    }
}

impl Rng for StdRng {
    fn fill(&mut self, buf: &mut [u8]) {
        use rand::RngCore;
        self.0.fill_bytes(buf);
    }
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Convert a `std::time::Instant` to the library's microsecond-based `Instant`.
fn to_micros(epoch: time::Instant, now: time::Instant) -> u64 {
    now.duration_since(epoch).as_micros() as u64
}

// ---------------------------------------------------------------------------
// Certificate loading from files
// ---------------------------------------------------------------------------

/// Load DER-encoded certificate and PKCS#8 private key from files
/// specified via `--cert` and `--key` command-line arguments.
///
/// Auto-detects the key type by inspecting the certificate:
/// - **Ed25519**: PKCS#8 DER has a 16-byte header, then 32-byte seed (offset 16..48).
/// - **ECDSA-P256**: PKCS#8 DER has the 32-byte scalar at offset 36..68
///   (after the PKCS#8 + EC key headers: 7-byte outer + OCTET STRING wrapper +
///   ECPrivateKey version + OCTET STRING with the scalar).
///
/// Returns `(&'static [u8], &'static [u8])` = (cert_der, private_key_32_bytes) with
/// 'static lifetime via `Box::leak`.
fn load_cert_and_key() -> Option<(&'static [u8], &'static [u8])> {
    let args: Vec<String> = std::env::args().collect();
    let cert_idx = args.iter().position(|a| a == "--cert")?;
    let key_idx = args.iter().position(|a| a == "--key")?;

    let cert_path = args.get(cert_idx + 1)?;
    let key_path = args.get(key_idx + 1)?;

    let cert_der = std::fs::read(cert_path).expect("failed to read cert file");
    let key_der = std::fs::read(key_path).expect("failed to read key file");

    let is_p256 = ecdsa_p256::cert_has_p256_key(&cert_der);

    let key_bytes: Vec<u8> = if is_p256 {
        // PKCS#8 P-256 key: the 32-byte scalar is wrapped in
        //   SEQUENCE { version, AlgorithmIdentifier, OCTET STRING {
        //     ECPrivateKey { version(1byte), OCTET STRING(32 bytes scalar), ... }
        //   }}
        // The scalar is typically at offset 36 (for standard openssl-generated keys),
        // but to be safe we search for the OCTET STRING containing exactly 32 bytes
        // after the EC private key version byte.
        // Common layout: the 32-byte scalar starts at offset 36.
        assert!(
            key_der.len() >= 68,
            "key file too short for P-256 PKCS#8 (got {} bytes)",
            key_der.len()
        );
        // Search for the 32-byte scalar: look for OCTET STRING tag (0x04) with length 0x20
        // in the inner ECPrivateKey structure.
        let scalar_offset =
            find_p256_scalar_in_pkcs8(&key_der).expect("could not find P-256 scalar in PKCS#8 key");
        println!("[init] detected P-256 key (scalar at offset {scalar_offset})");
        key_der[scalar_offset..scalar_offset + 32].to_vec()
    } else {
        // Ed25519 PKCS#8: 16-byte header + 32-byte seed
        assert!(key_der.len() >= 48, "key file too short for Ed25519 PKCS#8");
        println!("[init] detected Ed25519 key");
        key_der[16..48].to_vec()
    };

    // Leak into 'static
    let cert: &'static [u8] = Box::leak(cert_der.into_boxed_slice());
    let key: &'static [u8] = Box::leak(key_bytes.into_boxed_slice());

    Some((cert, key))
}

/// Find the offset of the 32-byte P-256 private scalar inside a PKCS#8 DER key.
///
/// The ECPrivateKey structure (inside PKCS#8's OCTET STRING) contains:
///   SEQUENCE { INTEGER(version=1), OCTET_STRING(32-byte scalar), ... }
///
/// We look for `04 20` (OCTET STRING, length 32) following an `02 01 01`
/// (INTEGER version=1) byte sequence, which is the ECPrivateKey pattern.
fn find_p256_scalar_in_pkcs8(der: &[u8]) -> Option<usize> {
    // Pattern: version INTEGER 02 01 01, then OCTET STRING 04 20, then 32 bytes
    for i in 0..der.len().saturating_sub(37) {
        if der[i] == 0x02
            && der[i + 1] == 0x01
            && der[i + 2] == 0x01
            && der[i + 3] == 0x04
            && der[i + 4] == 0x20
        {
            return Some(i + 5);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("milli-quic HTTP/3 test server");
    println!("=============================");

    // -- Load or generate Ed25519 certificate --
    let (cert_der, private_key_der) = if let Some((c, k)) = load_cert_and_key() {
        println!("[init] loaded certificate from file ({} bytes)", c.len());
        (c, k)
    } else {
        let seed: [u8; 32] = [0x42u8; 32];
        let pk = ed25519_public_key_from_seed(&seed);
        let mut cert_buf = [0u8; 512];
        let cert_len =
            build_ed25519_cert_der(&pk, &mut cert_buf).expect("failed to build certificate DER");
        // Leak into 'static references required by ServerTlsConfig.
        let cert_der: &'static [u8] = Box::leak(cert_buf[..cert_len].to_vec().into_boxed_slice());
        let private_key_der: &'static [u8] = Box::leak(Box::new(seed));
        println!("[init] generated self-signed Ed25519 certificate ({cert_len} bytes)");
        (cert_der, private_key_der)
    };

    // -- Bind UDP socket --
    let socket = UdpSocket::bind("0.0.0.0:4433").expect("failed to bind UDP socket on :4433");
    println!("[init] listening on 0.0.0.0:4433 (UDP)");

    // Use a short read timeout so the main loop stays responsive.
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(5)))
        .expect("set_read_timeout");

    let epoch = time::Instant::now();

    // -- Wait for the first UDP datagram (QUIC Initial from client) --
    let mut recv_buf = [0u8; 65535];
    let (first_len, client_addr) = loop {
        match socket.recv_from(&mut recv_buf) {
            Ok(pair) => break pair,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => panic!("recv_from error: {e}"),
        }
    };

    println!("[conn] received first datagram ({first_len} bytes) from {client_addr}");

    // -- Create the server connection --
    let tp = TransportParams::default_params();
    let tls_config = ServerTlsConfig {
        cert_der,
        private_key_der,
        alpn_protocols: &[b"h3"],
        transport_params: tp.clone(),
    };

    let mut rng = StdRng::new();
    let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();
    let conn = Connection::<Aes128GcmProvider>::server(
        Aes128GcmProvider,
        tls_config,
        tp,
        &mut rng,
        &mut pool,
    )
    .expect("failed to create server Connection");

    let mut h3: H3Server<Aes128GcmProvider> = H3Server::new(conn);
    let mut scratch = [0u8; 2048];

    // Feed the first datagram.
    let now = to_micros(epoch, time::Instant::now());
    if let Err(e) = h3.recv(&recv_buf[..first_len], &mut scratch, now, &mut pool) {
        eprintln!("[conn] error processing first datagram: {e}");
    }

    // -- Main event loop --
    // Open packet log file for debugging
    let mut pkt_log = std::fs::File::create("/tmp/quic_packets.log").expect("create packet log");

    println!("[loop] entering main loop");

    loop {
        let now = to_micros(epoch, time::Instant::now());

        // 1. Send any outgoing datagrams.
        let mut tx_buf = [0u8; 65535];
        loop {
            match h3.poll_transmit(&mut tx_buf, now, &mut pool) {
                Some(tx) => {
                    println!("[send] sending {} bytes to {client_addr}", tx.data.len());
                    let _ = writeln!(
                        pkt_log,
                        "SEND {} {}",
                        tx.data.len(),
                        tx.data
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    let _ = pkt_log.flush();
                    if let Err(e) = socket.send_to(tx.data, client_addr) {
                        eprintln!("[send] error: {e}");
                    }
                }
                None => break,
            }
        }

        // 2. Handle timeouts.
        if let Some(deadline) = h3.next_timeout() {
            let now = to_micros(epoch, time::Instant::now());
            if now >= deadline {
                h3.handle_timeout(now);
            }
        }

        // 3. Receive incoming datagrams.
        match socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                if addr == client_addr {
                    println!(
                        "[recv] received {len} bytes from {addr} (first_byte=0x{:02x})",
                        recv_buf[0]
                    );
                    let _ = writeln!(
                        pkt_log,
                        "RECV {} {}",
                        len,
                        recv_buf[..len]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    let _ = pkt_log.flush();
                    let now = to_micros(epoch, time::Instant::now());
                    match h3.recv(&recv_buf[..len], &mut scratch, now, &mut pool) {
                        Ok(()) => {}
                        Err(e) => eprintln!("[recv] error: {e}"),
                    }
                } else {
                    eprintln!("[recv] ignoring datagram from {addr} (expected {client_addr})");
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("[recv] error: {e}");
            }
        }

        // 4. Process H3 events.
        while let Some(event) = h3.poll_event(&mut scratch) {
            match event {
                H3Event::Connected => {
                    println!("[h3] connection established");
                }

                H3Event::Headers(stream_id) => {
                    println!("[h3] request headers on stream {stream_id}");

                    // Print the request headers.
                    h3.recv_headers(stream_id, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<binary>");
                        let v = core::str::from_utf8(value).unwrap_or("<binary>");
                        println!("[h3]   {n}: {v}");
                    })
                    .ok();

                    // Drain any body (we don't use it).
                    let mut body_buf = [0u8; 4096];
                    loop {
                        match h3.recv_body(stream_id, &mut body_buf) {
                            Ok((_n, true)) => break,
                            Ok((_n, false)) => continue,
                            Err(_) => break,
                        }
                    }

                    // Send a simple response.
                    let body = b"<!DOCTYPE html>\n<html>\n<head><title>milli-quic</title></head>\n<body>\n<h1>Hello from milli-quic!</h1>\n<p>You are connected via HTTP/3 (QUIC).</p>\n</body>\n</html>\n";
                    let content_length = body.len().to_string();
                    let extra_headers: &[(&[u8], &[u8])] = &[
                        (b"content-type", b"text/html"),
                        (b"content-length", content_length.as_bytes()),
                        (b"server", b"milli-quic/0.1"),
                    ];

                    if let Err(e) = h3.send_response(stream_id, 200, extra_headers, false) {
                        eprintln!("[h3] error sending response headers: {e}");
                        continue;
                    }
                    println!("[h3] sent 200 response on stream {stream_id}");

                    match h3.send_body(stream_id, body, true) {
                        Ok(n) => println!("[h3] sent {n} body bytes (fin) on stream {stream_id}"),
                        Err(e) => eprintln!("[h3] error sending body: {e}"),
                    }
                }

                H3Event::Data(stream_id) => {
                    // Drain additional body data if it arrives as a separate event.
                    let mut body_buf = [0u8; 4096];
                    loop {
                        match h3.recv_body(stream_id, &mut body_buf) {
                            Ok((_n, true)) => break,
                            Ok((_n, false)) => continue,
                            Err(_) => break,
                        }
                    }
                }

                H3Event::Finished(stream_id) => {
                    println!("[h3] stream {stream_id} finished");
                }

                H3Event::GoAway(id) => {
                    println!("[h3] received GOAWAY (id={id})");
                    return;
                }
                _ => {}
            }
        }
    }
}
