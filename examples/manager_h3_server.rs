//! HTTP/3 server through `ServerManager`, with firmware-equivalent parameters.
//!
//! The plain `h3_server` example drives `H3Server` directly; this one goes
//! through the `ServerManager` layer (CID routing, per-manager const params,
//! shared handshake pool) exactly the way an embedded `ServerRunner` driver
//! does — small BUF, a single handshake-pool slot — so real-client interop
//! issues in that layer reproduce on host.
//!
//! Usage:
//!   cargo run --example manager_h3_server --features server,http1,h2,h3,rustcrypto-aes,std -- \
//!       [--cert cert.der --key key.p8]
//!   curl -k --http3-only https://127.0.0.1:4433/
//!
//! Without --cert/--key a built-in Ed25519 cert is generated.

use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Duration;

use milli_http::connection::HandshakePool;
use milli_http::crypto::ecdsa_p256;
use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::http::server_conn::HttpEvent;
use milli_http::server::{ServerConfig, ServerEvent, ServerManager};
use milli_http::tls::handshake::ServerTlsConfig;
use milli_http::tls::transport_params::TransportParams;
use milli_http::transport::Rng;

// Firmware-equivalent sizing (crates/main/src/milli_http_server.rs):
// Manager BUF = TLS_BUF = 4096, runner CRYPTO_BUF default = 4096, one
// handshake-pool slot, max_quic_conns = 1.
const BUF: usize = 4096;
const CRYPTO_BUF: usize = 4096;
const HANDSHAKE_SLOTS: usize = 1;

struct CountingRng(u64);
impl Rng for CountingRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            // xorshift — deterministic but spread, fine for debugging
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = self.0 as u8;
        }
    }
}

fn load_cert_and_key() -> Option<(Vec<u8>, Vec<u8>)> {
    let args: Vec<String> = std::env::args().collect();
    let cert_idx = args.iter().position(|a| a == "--cert")?;
    let key_idx = args.iter().position(|a| a == "--key")?;
    let cert_der = std::fs::read(&args[cert_idx + 1]).expect("read cert");
    let key_der = std::fs::read(&args[key_idx + 1]).expect("read key");

    let key = if ecdsa_p256::cert_has_p256_key(&cert_der) {
        // PKCS#8 P-256: find the inner OCTET STRING with the 32-byte scalar.
        let pos = key_der
            .windows(2)
            .position(|w| w == [0x04, 0x20])
            .expect("scalar not found in PKCS#8")
            + 2;
        println!("[init] P-256 key, scalar at offset {pos}");
        key_der[pos..pos + 32].to_vec()
    } else {
        println!("[init] Ed25519 key");
        key_der[16..48].to_vec()
    };
    Some((cert_der, key))
}

fn main() {
    let (cert_der, key): (Vec<u8>, Vec<u8>) = load_cert_and_key().unwrap_or_else(|| {
        const SEED: [u8; 32] = [0x42; 32];
        let pk = ed25519_public_key_from_seed(&SEED);
        let mut buf = [0u8; 512];
        let len = build_ed25519_cert_der(&pk, &mut buf).unwrap();
        println!("[init] generated Ed25519 cert ({len} B)");
        (buf[..len].to_vec(), SEED.to_vec())
    });
    let cert_der: &'static [u8] = cert_der.leak();
    let key: &'static [u8] = key.leak();

    let tls_config = ServerTlsConfig {
        cert_der,
        private_key_der: key,
        alpn_protocols: &[b"h2", b"http/1.1", b"h3"],
        transport_params: TransportParams::default_params(),
    };
    let server_config = ServerConfig {
        max_tcp_conns: 3,
        max_events: 8,
        handshake_timeout_us: 10_000_000,
        max_quic_conns: 1,
    };
    let mut manager: ServerManager<Aes128GcmProvider, SocketAddr, BUF> =
        ServerManager::new(Aes128GcmProvider, tls_config, server_config);
    let mut pool: HandshakePool<Aes128GcmProvider, HANDSHAKE_SLOTS> = HandshakePool::new();
    let mut rng = CountingRng(0x12345678_9abcdef0);

    let sock = UdpSocket::bind("0.0.0.0:4433").expect("bind");
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    println!(
        "[init] manager h3 server on 0.0.0.0:4433 (BUF={BUF}, CRYPTO_BUF={CRYPTO_BUF}, pool={HANDSHAKE_SLOTS})"
    );

    let t0 = std::time::Instant::now();
    let mut rx_buf = [0u8; 1500];
    loop {
        let now = t0.elapsed().as_micros() as u64;

        // step 4 equivalent: feed datagrams
        match sock.recv_from(&mut rx_buf) {
            Ok((n, from)) => {
                println!("[rx] {n} B from {from}");
                if let Err(e) =
                    manager.udp_feed::<CRYPTO_BUF>(&rx_buf[..n], from, now, &mut rng, &mut pool)
                {
                    println!("[feed ERR] {e:?}");
                }
            }
            Err(_) => {} // timeout
        }

        // step 5 equivalent: drain transmits
        let mut tx_buf = [0u8; 1200]; // RFC 9000 §14: max UDP payload until PMTUD
        while let Some((addr, len)) =
            manager.udp_poll_transmit::<CRYPTO_BUF>(&mut tx_buf, now, &mut pool)
        {
            println!("[tx] {len} B to {addr}");
            let _ = sock.send_to(&tx_buf[..len], addr);
        }

        // step 6: timeouts
        manager.handle_timeouts(now);

        // step 7: events
        let mut scratch = [0u8; 2048];
        while let Some(ev) = manager.poll_event(&mut scratch) {
            match ev {
                ServerEvent::Http {
                    conn,
                    event: HttpEvent::Connected,
                } => println!("[event] quic conn {} connected", conn.0),
                ServerEvent::Http {
                    conn,
                    event: HttpEvent::Headers(sid),
                } => {
                    println!("[event] headers on conn {} stream {sid}", conn.0);
                    let body = b"hello from manager_h3_server\n";
                    let mut cl = [0u8; 8];
                    let cl_len = {
                        use std::io::Write;
                        let mut c = &mut cl[..];
                        write!(c, "{}", body.len()).unwrap();
                        8 - c.len()
                    };
                    let headers: [(&[u8], &[u8]); 2] = [
                        (b"content-type", b"text/plain"),
                        (b"content-length", &cl[..cl_len]),
                    ];
                    if let Err(e) = manager.send_response(conn, sid, 200, &headers, false) {
                        println!("[send_response ERR] {e:?}");
                    }
                    if let Err(e) = manager.send_body(conn, sid, body, true) {
                        println!("[send_body ERR] {e:?}");
                    }
                }
                ServerEvent::Closed(conn) => println!("[event] conn {} closed", conn.0),
                ServerEvent::Connected(conn) => println!("[event] tls conn {} connected", conn.0),
                _ => {}
            }
        }
    }
}
