//! Omni-client: HTTP/1.1 + HTTP/2 + HTTP/3 client in one binary.
//!
//! Demonstrates making requests with each protocol variant using the same
//! `feed_data → poll_output → poll_event` calling convention.
//!
//! Usage (once all features are implemented):
//!   cargo run --example omni_client --features h3,h2,http1,rustcrypto-chacha -- [protocol] [url]
//!
//! Usage:
//!   cargo run --example omni_client --features h3,h2,http1,rustcrypto-chacha -- h1 127.0.0.1:8080
//!   cargo run --example omni_client --features h3,h2,http1,rustcrypto-chacha -- h2 127.0.0.1:8443
//!   cargo run --example omni_client --features h3,h2,http1,rustcrypto-chacha -- h3 127.0.0.1:4433
//!
//! The `protocol` argument selects the HTTP version:
//!   h1  — HTTP/1.1 over TCP
//!   h2  — HTTP/2 cleartext (h2c) over TCP
//!   h3  — HTTP/3 over QUIC/UDP

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let protocol = args.get(1).map(|s| s.as_str()).unwrap_or("h2");
    let addr = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or(match protocol {
            "h3" => "127.0.0.1:4433",
            "h2" => "127.0.0.1:8443",
            "h1" => "127.0.0.1:8080",
            _ => "127.0.0.1:8443",
        });

    println!("milli-http omni-client");
    println!("======================");
    println!("Protocol: {protocol}");
    println!("Target:   {addr}");
    println!();

    match protocol {
        "h2" => run_h2(addr),
        "h3" => run_h3(addr),
        "h1" => run_h1(addr),
        other => {
            eprintln!("Unknown protocol: {other}");
            eprintln!("Supported: h1, h2, h3");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 client
// ---------------------------------------------------------------------------

fn run_h1(addr: &str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use milli_http::http1::client::Http1Client;
    use milli_http::http1::Http1Event;

    let mut stream = TcpStream::connect(addr).expect("failed to connect");
    stream.set_nonblocking(true).expect("set_nonblocking");
    println!("[h1] connected to {addr}");

    let mut http1 = Http1Client::<8192, 2048, 4096>::new();

    let stream_id = http1.send_request("GET", "/", addr, &[], true)
        .expect("send_request failed");
    println!("[h1] sent GET / (stream {stream_id})");

    for _round in 0..100 {
        let mut out_buf = [0u8; 8192];
        while let Some(data) = http1.poll_output(&mut out_buf) {
            stream.write_all(data).expect("write failed");
        }

        let mut recv_buf = [0u8; 8192];
        match stream.read(&mut recv_buf) {
            Ok(0) => { println!("[conn] server disconnected"); return; }
            Ok(n) => { http1.feed_data(&recv_buf[..n]).ok(); }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => { eprintln!("[conn] read error: {e}"); return; }
        }

        while let Some(event) = http1.poll_event() {
            match event {
                Http1Event::Connected => {
                    println!("[h1] connected");
                }
                Http1Event::Headers(sid) => {
                    print!("[h1] response headers:");
                    http1.recv_headers(sid, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        print!(" {n}={v}");
                    }).ok();
                    println!();
                }
                Http1Event::Data(sid) => {
                    let mut body = [0u8; 8192];
                    if let Ok((n, _)) = http1.recv_body(sid, &mut body) {
                        let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
                        println!("[h1] body ({n} bytes):\n{text}");
                    }
                }
                Http1Event::Finished(_) => {
                    println!("[done] request complete");
                    return;
                }
                _ => {}
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    eprintln!("[timeout] did not complete");
}

// ---------------------------------------------------------------------------
// HTTP/2 client (h2c)
// ---------------------------------------------------------------------------

fn run_h2(addr: &str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use milli_http::h2::client::H2Client;
    use milli_http::h2::H2Event;

    let mut stream = TcpStream::connect(addr).expect("failed to connect");
    stream.set_nonblocking(true).expect("set_nonblocking");
    println!("[h2] connected to {addr}");

    let mut h2 = H2Client::<16, 65536>::new();
    let mut handshake_done = false;
    let mut request_sent = false;
    let mut request_stream: Option<u64> = None;

    for _round in 0..200 {
        let mut out_buf = [0u8; 65535];
        while let Some(data) = h2.poll_output(&mut out_buf) {
            stream.write_all(data).expect("write failed");
        }

        let mut recv_buf = [0u8; 65535];
        match stream.read(&mut recv_buf) {
            Ok(0) => { println!("[conn] server disconnected"); return; }
            Ok(n) => { h2.feed_data(&recv_buf[..n]).ok(); }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => { eprintln!("[conn] read error: {e}"); return; }
        }

        while let Some(event) = h2.poll_event() {
            match event {
                H2Event::Connected => {
                    println!("[h2] connection established");
                    handshake_done = true;
                }
                H2Event::Headers(sid) => {
                    print!("[h2] response headers:");
                    h2.recv_headers(sid, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        print!(" {n}={v}");
                    }).ok();
                    println!();
                }
                H2Event::Data(sid) => {
                    let mut body = [0u8; 8192];
                    if let Ok((n, _)) = h2.recv_body(sid, &mut body) {
                        let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
                        println!("[h2] body ({n} bytes):\n{text}");
                    }
                }
                H2Event::Finished(sid) => {
                    if request_stream == Some(sid) {
                        println!("[done] request complete");
                        return;
                    }
                }
                _ => {}
            }
        }

        if handshake_done && !request_sent {
            let sid = h2.send_request("GET", "/", addr, &[], true)
                .expect("send_request");
            println!("[h2] sent GET /");
            request_stream = Some(sid);
            request_sent = true;
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    eprintln!("[timeout] did not complete");
}

// ---------------------------------------------------------------------------
// HTTP/3 client
// ---------------------------------------------------------------------------

fn run_h3(addr: &str) {
    use std::net::UdpSocket;

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

    let epoch = std::time::Instant::now();
    let to_micros = |now: std::time::Instant| -> u64 {
        now.duration_since(epoch).as_micros() as u64
    };

    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind UDP");
    socket.connect(addr).expect("connect UDP");
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(5)))
        .expect("set_read_timeout");
    println!("[h3] targeting {addr} (UDP)");

    let mut rng = StdRng::new();
    let mut pool = HandshakePool::<Aes128GcmProvider, 4>::new();
    let tp = TransportParams::default_params();
    let conn = Connection::<Aes128GcmProvider>::client(
        Aes128GcmProvider, "localhost", &[b"h3"], tp, &mut rng, &mut pool,
    ).expect("create client");

    let mut h3: H3Client<Aes128GcmProvider> = H3Client::new(conn);
    let mut request_sent = false;
    let mut request_stream: Option<u64> = None;

    for _round in 0..500 {
        let now = to_micros(std::time::Instant::now());

        let mut tx_buf = [0u8; 65535];
        loop {
            match h3.poll_transmit(&mut tx_buf, now, &mut pool) {
                Some(tx) => { let _ = socket.send(tx.data); }
                None => break,
            }
        }

        if let Some(deadline) = h3.next_timeout() {
            let now = to_micros(std::time::Instant::now());
            if now >= deadline { h3.handle_timeout(now); }
        }

        let mut recv_buf = [0u8; 65535];
        match socket.recv(&mut recv_buf) {
            Ok(n) => {
                let now = to_micros(std::time::Instant::now());
                let _ = h3.recv(&recv_buf[..n], now, &mut pool);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => { eprintln!("[recv] error: {e}"); return; }
        }

        while let Some(event) = h3.poll_event() {
            match event {
                H3Event::Connected => println!("[h3] connected"),
                H3Event::Headers(sid) => {
                    print!("[h3] response headers:");
                    h3.recv_headers(sid, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        print!(" {n}={v}");
                    }).ok();
                    println!();
                }
                H3Event::Data(sid) => {
                    let mut body = [0u8; 8192];
                    if let Ok((n, _)) = h3.recv_body(sid, &mut body) {
                        let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
                        println!("[h3] body ({n} bytes):\n{text}");
                    }
                }
                H3Event::Finished(sid) => {
                    if request_stream == Some(sid) {
                        println!("[done] request complete");
                        return;
                    }
                }
                H3Event::GoAway(_) => { println!("[h3] GOAWAY"); return; }
                _ => {}
            }
        }

        if !request_sent {
            if let Ok(sid) = h3.send_request("GET", "/", "localhost", &[], false) {
                h3.send_body(sid, &[], true).ok();
                println!("[h3] sent GET /");
                request_stream = Some(sid);
                request_sent = true;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    eprintln!("[timeout] did not complete");
}
