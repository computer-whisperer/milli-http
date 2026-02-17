//! Minimal HTTP/3 client example.
//!
//! Connects to a QUIC server over UDP, performs the TLS 1.3 handshake, and
//! sends an HTTP/3 GET request.
//!
//! Usage:
//!   cargo run --example h3_client --features h3,rustcrypto-chacha
//!
//! Expects an HTTP/3 server on 127.0.0.1:4433 (see `h3_server` example).

use std::net::UdpSocket;
use std::time;

use milli_http::connection::{Connection, HandshakePool};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h3::client::H3Client;
use milli_http::h3::H3Event;
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

fn to_micros(epoch: time::Instant, now: time::Instant) -> u64 {
    now.duration_since(epoch).as_micros() as u64
}

fn main() {
    println!("milli-http HTTP/3 client");
    println!("========================");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind UDP socket");
    socket.connect("127.0.0.1:4433").expect("failed to connect to server");
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(5)))
        .expect("set_read_timeout");
    println!("[init] targeting 127.0.0.1:4433 (UDP)");

    let epoch = time::Instant::now();
    let mut rng = StdRng::new();
    let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();

    let tp = TransportParams::default_params();
    let conn = Connection::<Aes128GcmProvider>::client(
        Aes128GcmProvider,
        "localhost",
        &[b"h3"],
        tp,
        &mut rng,
        &mut pool,
    )
    .expect("failed to create client Connection");

    let mut h3: H3Client<Aes128GcmProvider> = H3Client::new(conn);
    let mut request_sent = false;
    let mut request_stream: Option<u64> = None;

    for _round in 0..500 {
        let now = to_micros(epoch, time::Instant::now());

        // Send outgoing datagrams.
        let mut tx_buf = [0u8; 65535];
        loop {
            match h3.poll_transmit(&mut tx_buf, now, &mut pool) {
                Some(tx) => {
                    if let Err(e) = socket.send(tx.data) {
                        eprintln!("[send] error: {e}");
                    }
                }
                None => break,
            }
        }

        // Handle timeouts.
        if let Some(deadline) = h3.next_timeout() {
            let now = to_micros(epoch, time::Instant::now());
            if now >= deadline {
                h3.handle_timeout(now);
            }
        }

        // Receive datagrams.
        let mut recv_buf = [0u8; 65535];
        match socket.recv(&mut recv_buf) {
            Ok(n) => {
                let now = to_micros(epoch, time::Instant::now());
                let _ = h3.recv(&recv_buf[..n], now, &mut pool);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("[recv] error: {e}");
                return;
            }
        }

        // Process H3 events.
        while let Some(event) = h3.poll_event() {
            match event {
                H3Event::Connected => {
                    println!("[h3] connection established");
                }
                H3Event::Headers(stream_id) => {
                    println!("[h3] response headers on stream {stream_id}:");
                    h3.recv_headers(stream_id, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        println!("[h3]   {n}: {v}");
                    })
                    .ok();
                }
                H3Event::Data(stream_id) => {
                    let mut body = [0u8; 8192];
                    if let Ok((n, _fin)) = h3.recv_body(stream_id, &mut body) {
                        let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
                        println!("[h3] body ({n} bytes):\n{text}");
                    }
                }
                H3Event::Finished(stream_id) => {
                    println!("[h3] stream {stream_id} finished");
                    if request_stream == Some(stream_id) {
                        println!("[done] request complete");
                        return;
                    }
                }
                H3Event::GoAway(id) => {
                    println!("[h3] GOAWAY (id={id})");
                    return;
                }
                _ => {}
            }
        }

        // Send request once connected (first poll_event after Connected).
        if !request_sent {
            // Try to send — will succeed once handshake and H3 setup are done.
            match h3.send_request("GET", "/", "localhost", &[], false) {
                Ok(stream_id) => {
                    h3.send_body(stream_id, &[], true).ok();
                    println!("[h3] sent GET / on stream {stream_id}");
                    request_stream = Some(stream_id);
                    request_sent = true;
                }
                Err(_) => {} // Not ready yet, retry next round.
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    eprintln!("[timeout] did not complete within iteration limit");
}
