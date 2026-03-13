//! HTTPS/1.1 client example — HTTP/1.1 over TLS 1.3.
//!
//! Connects to an HTTPS/1.1 server (e.g. `https1_server`) on 127.0.0.1:9443,
//! performs a TLS 1.3 handshake, then sends an HTTP/1.1 GET request.
//!
//! Usage:
//!   cargo run --example https1_client --features "http1,tcp-tls,rustcrypto-chacha"
//!
//! Expects `https1_server` running on 127.0.0.1:9443.

use std::io::{Read, Write};
use std::net::TcpStream;

use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::http1::Http1Event;
use milli_http::http1::client::Http1Client;
use milli_http::tcp_tls::client::TlsClient;
use milli_http::tcp_tls::connection::TlsEvent;
use milli_http::tls::TransportParams;
use milli_http::tls::handshake::TlsConfig;

fn main() {
    println!("milli-http HTTPS/1.1 client");
    println!("===========================");

    let mut stream =
        TcpStream::connect("127.0.0.1:9443").expect("failed to connect to 127.0.0.1:9443");
    println!("[conn] connected to 127.0.0.1:9443");

    stream.set_nonblocking(true).expect("set_nonblocking");

    // -- Create TLS client --
    let tls_config = TlsConfig {
        server_name: heapless::String::try_from("127.0.0.1").unwrap(),
        alpn_protocols: &[b"http/1.1"],
        transport_params: TransportParams::default_params(),
        pinned_certs: &[],
    };

    let mut rng_bytes = [0u8; 64];
    {
        use rand::RngCore;
        rand::rng().fill_bytes(&mut rng_bytes);
    }
    let mut secret = [0u8; 32];
    let mut random = [0u8; 32];
    secret.copy_from_slice(&rng_bytes[..32]);
    random.copy_from_slice(&rng_bytes[32..]);

    let mut tls: TlsClient<Aes128GcmProvider, 40960> =
        TlsClient::new(Aes128GcmProvider, tls_config, secret, random);

    let mut http1 = Http1Client::<40960, 2048, 4096>::new();
    let mut tls_active = false;
    let mut request_sent = false;

    for _round in 0..200 {
        // 1. TLS output → write to TCP (flushes ClientHello on first iter)
        let mut tls_out = [0u8; 32768];
        while let Some(data) = tls.poll_output(&mut tls_out) {
            if let Err(e) = stream.write_all(data) {
                eprintln!("[conn] write error: {e}");
                return;
            }
        }

        // 2. Read from TCP → feed to TLS
        let mut recv_buf = [0u8; 16384];
        match stream.read(&mut recv_buf) {
            Ok(0) => {
                println!("[conn] server disconnected");
                return;
            }
            Ok(n) => {
                if let Err(e) = tls.feed_data(&recv_buf[..n]) {
                    eprintln!("[tls] feed_data error: {e}");
                    return;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("[conn] read error: {e}");
                return;
            }
        }

        // 3. Process TLS events
        while let Some(event) = tls.poll_event() {
            match event {
                TlsEvent::HandshakeComplete => {
                    println!("[tls] handshake complete");
                    tls_active = true;
                }
                TlsEvent::AppData => {
                    let mut app_buf = [0u8; 16384];
                    loop {
                        match tls.recv_app_data(&mut app_buf) {
                            Ok(n) => {
                                if let Err(e) = http1.feed_data(&app_buf[..n]) {
                                    eprintln!("[http1] feed_data error: {e}");
                                    return;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                TlsEvent::PeerClosed => {
                    println!("[tls] peer closed");
                    return;
                }
            }
        }

        // 4. Send request immediately once TLS handshake completes
        if tls_active && !request_sent {
            let stream_id = http1
                .send_request("GET", "/", "127.0.0.1:9443", &[], true)
                .expect("send_request failed");
            println!("[http1] sent GET / (stream {stream_id})");
            request_sent = true;
        }

        // 5. HTTP/1.1 output → encrypt via TLS
        if tls_active {
            let mut out_buf = [0u8; 32768];
            while let Some(data) = http1.poll_output(&mut out_buf) {
                let copy: Vec<u8> = data.to_vec();
                if let Err(e) = tls.send_app_data(&copy) {
                    eprintln!("[tls] send_app_data error: {e}");
                    return;
                }
            }
        }

        // 6. Process HTTP/1.1 events
        while let Some(event) = http1.poll_event() {
            match event {
                Http1Event::Connected => {
                    println!("[http1] connected");
                }
                Http1Event::Headers(sid) => {
                    println!("[http1] response headers:");
                    http1
                        .recv_headers(sid, |name, value| {
                            let n = core::str::from_utf8(name).unwrap_or("<bin>");
                            let v = core::str::from_utf8(value).unwrap_or("<bin>");
                            println!("[http1]   {n}: {v}");
                        })
                        .ok();
                }
                Http1Event::Data(sid) => {
                    let mut body = [0u8; 8192];
                    if let Ok((n, _fin)) = http1.recv_body(sid, &mut body) {
                        let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
                        println!("[http1] body ({n} bytes):\n{text}");
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
