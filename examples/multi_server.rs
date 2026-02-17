//! Multi-protocol HTTP server: HTTP/1.1 + HTTP/2 + HTTP/3 in one event loop.
//!
//! Demonstrates the unified pure-codec architecture of milli-http:
//! - HTTP/3 over QUIC/UDP (port 4433)
//! - HTTP/2 over TCP (port 8443)
//! - HTTP/1.1 over TCP (port 8080) — once implemented
//!
//! All three protocols share the same `feed → poll_output → poll_event` pattern,
//! so a single event loop can drive all of them.
//!
//! Usage (once all features are implemented):
//!   cargo run --example multi_server --features h3,h2,http1,rustcrypto-chacha
//!
//! Currently only H3 and H2 are functional:
//!   cargo run --example multi_server --features h3,h2,rustcrypto-chacha
//!
//! Then test each protocol:
//!   curl --http2-prior-knowledge http://127.0.0.1:8443/
//!   curl -k --http3 https://127.0.0.1:4433/

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};

// -- HTTP/2 --
use milli_http::h2::server::H2Server;
use milli_http::h2::H2Event;

// -- HTTP/3 --
use milli_http::connection::{Connection, HandshakePool};
use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h3::server::H3Server;
use milli_http::h3::H3Event;
use milli_http::tls::handshake::ServerTlsConfig;
use milli_http::tls::transport_params::TransportParams;
use milli_http::Rng;

struct StdRng(rand::rngs::ThreadRng);
impl StdRng {
    fn new() -> Self { Self(rand::rng()) }
}
impl Rng for StdRng {
    fn fill(&mut self, buf: &mut [u8]) {
        use rand::RngCore;
        self.0.fill_bytes(buf);
    }
}

fn to_micros(epoch: std::time::Instant, now: std::time::Instant) -> u64 {
    now.duration_since(epoch).as_micros() as u64
}

/// The same HTML body for all protocols.
const BODY: &[u8] = b"<!DOCTYPE html>\n<html>\n<head><title>milli-http</title></head>\n<body>\n<h1>Hello from milli-http!</h1>\n<p>Multi-protocol server: HTTP/1.1 + HTTP/2 + HTTP/3.</p>\n</body>\n</html>\n";

fn main() {
    println!("milli-http multi-protocol server");
    println!("================================");

    let epoch = std::time::Instant::now();

    // -- Generate self-signed certificate for H3/QUIC --
    let seed: [u8; 32] = [0x42u8; 32];
    let pk = ed25519_public_key_from_seed(&seed);
    let mut cert_buf = [0u8; 512];
    let cert_len = build_ed25519_cert_der(&pk, &mut cert_buf).expect("build cert");
    let cert_der: &'static [u8] = Box::leak(cert_buf[..cert_len].to_vec().into_boxed_slice());
    let private_key_der: &'static [u8] = Box::leak(Box::new(seed));

    // -- Bind sockets --
    let udp_socket = UdpSocket::bind("0.0.0.0:4433").expect("bind UDP :4433");
    udp_socket
        .set_read_timeout(Some(std::time::Duration::from_millis(1)))
        .expect("set_read_timeout");
    println!("[init] HTTP/3 listening on 0.0.0.0:4433 (UDP)");

    let tcp_listener = TcpListener::bind("0.0.0.0:8443").expect("bind TCP :8443");
    tcp_listener.set_nonblocking(true).expect("set_nonblocking");
    println!("[init] HTTP/2 listening on 0.0.0.0:8443 (TCP, h2c)");

    // -- H2 state --
    let mut h2_conns: Vec<(std::net::TcpStream, H2Server<32, 65536>)> = Vec::new();

    // -- H3 state --
    let mut h3_server: Option<H3Server<AesP>> = None;
    let mut h3_client_addr = None;
    let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();

    type AesP = Aes128GcmProvider;

    println!("[loop] entering main event loop");
    println!("  Test H2: curl --http2-prior-knowledge http://127.0.0.1:8443/");
    println!("  Test H3: curl -k --http3 https://127.0.0.1:4433/");
    println!();

    loop {
        let now = to_micros(epoch, std::time::Instant::now());

        // =================================================================
        // HTTP/3 (UDP)
        // =================================================================

        // Send outgoing H3 datagrams.
        if let Some(ref mut h3) = h3_server {
            let mut tx_buf = [0u8; 65535];
            loop {
                match h3.poll_transmit(&mut tx_buf, now, &mut pool) {
                    Some(tx) => {
                        if let Some(addr) = h3_client_addr {
                            let _ = udp_socket.send_to(tx.data, addr);
                        }
                    }
                    None => break,
                }
            }

            // Handle timeouts.
            if let Some(deadline) = h3.next_timeout() {
                if now >= deadline {
                    h3.handle_timeout(now);
                }
            }
        }

        // Receive UDP datagrams.
        let mut recv_buf = [0u8; 65535];
        match udp_socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                if h3_server.is_none() {
                    // Create H3 server on first datagram.
                    let tp = TransportParams::default_params();
                    let tls_config = ServerTlsConfig {
                        cert_der,
                        private_key_der,
                        alpn_protocols: &[b"h3"],
                        transport_params: tp.clone(),
                    };
                    let mut rng = StdRng::new();
                    let conn = Connection::<AesP>::server(
                        Aes128GcmProvider, tls_config, tp, &mut rng, &mut pool,
                    )
                    .expect("create H3 server");
                    h3_server = Some(H3Server::new(conn));
                    h3_client_addr = Some(addr);
                    println!("[h3] new connection from {addr}");
                }
                if let Some(ref mut h3) = h3_server {
                    let _ = h3.recv(&recv_buf[..len], now, &mut pool);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => eprintln!("[udp] recv error: {e}"),
        }

        // Process H3 events.
        if let Some(ref mut h3) = h3_server {
            while let Some(event) = h3.poll_event() {
                match event {
                    H3Event::Connected => println!("[h3] connected"),
                    H3Event::Headers(sid) => {
                        h3.recv_headers(sid, |name, value| {
                            let n = core::str::from_utf8(name).unwrap_or("<bin>");
                            let v = core::str::from_utf8(value).unwrap_or("<bin>");
                            println!("[h3] {n}: {v}");
                        }).ok();

                        let cl = BODY.len().to_string();
                        h3.send_response(sid, 200, &[
                            (b"content-type", b"text/html"),
                            (b"content-length", cl.as_bytes()),
                            (b"server", b"milli-http/0.1"),
                        ], false).ok();
                        h3.send_body(sid, BODY, true).ok();
                        println!("[h3] sent response on stream {sid}");
                    }
                    H3Event::Data(sid) => {
                        let mut d = [0u8; 4096];
                        loop {
                            match h3.recv_body(sid, &mut d) {
                                Ok((_, true)) | Err(_) => break,
                                _ => continue,
                            }
                        }
                    }
                    H3Event::Finished(sid) => println!("[h3] stream {sid} finished"),
                    H3Event::GoAway(_) => {
                        println!("[h3] GOAWAY received");
                        h3_server = None;
                        break;
                    }
                    _ => {}
                }
            }
        }

        // =================================================================
        // HTTP/2 (TCP)
        // =================================================================

        // Accept new TCP connections.
        match tcp_listener.accept() {
            Ok((stream, addr)) => {
                stream.set_nonblocking(true).expect("set_nonblocking");
                println!("[h2] new connection from {addr}");
                h2_conns.push((stream, H2Server::<32, 65536>::new()));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("[tcp] accept error: {e}"),
        }

        // Process each H2 connection.
        let mut closed = Vec::new();
        for (i, (stream, h2)) in h2_conns.iter_mut().enumerate() {
            // Read.
            let mut tcp_buf = [0u8; 65535];
            match stream.read(&mut tcp_buf) {
                Ok(0) => { closed.push(i); continue; }
                Ok(n) => { let _ = h2.feed_data(&tcp_buf[..n]); }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => { closed.push(i); continue; }
            }

            // Write.
            let mut out_buf = [0u8; 65535];
            while let Some(data) = h2.poll_output(&mut out_buf) {
                if stream.write_all(data).is_err() {
                    closed.push(i);
                    break;
                }
            }

            // Events.
            while let Some(event) = h2.poll_event() {
                match event {
                    H2Event::Connected => println!("[h2] connected"),
                    H2Event::Headers(sid) => {
                        h2.recv_headers(sid, |name, value| {
                            let n = core::str::from_utf8(name).unwrap_or("<bin>");
                            let v = core::str::from_utf8(value).unwrap_or("<bin>");
                            println!("[h2] {n}: {v}");
                        }).ok();

                        let cl = BODY.len().to_string();
                        h2.send_response(sid, 200, &[
                            (b"content-type", b"text/html"),
                            (b"content-length", cl.as_bytes()),
                            (b"server", b"milli-http/0.1"),
                        ], false).ok();
                        h2.send_body(sid, BODY, true).ok();
                        println!("[h2] sent response on stream {sid}");
                    }
                    H2Event::Data(sid) => {
                        let mut d = [0u8; 4096];
                        loop {
                            match h2.recv_body(sid, &mut d) {
                                Ok((_, true)) | Err(_) => break,
                                _ => continue,
                            }
                        }
                    }
                    H2Event::Finished(sid) => println!("[h2] stream {sid} finished"),
                    H2Event::GoAway(_, _) => { closed.push(i); break; }
                    H2Event::StreamReset(sid, code) => {
                        println!("[h2] stream {sid} reset ({code})");
                    }
                    _ => {}
                }
            }
        }

        // Remove closed connections (reverse order to preserve indices).
        closed.sort_unstable();
        closed.dedup();
        for &i in closed.iter().rev() {
            println!("[h2] connection {} closed", i);
            h2_conns.remove(i);
        }

        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}
