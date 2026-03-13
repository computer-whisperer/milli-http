//! HTTP/2 over TLS client example.
//!
//! Connects to an H2+TLS server (e.g. `h2_tls_server`) on 127.0.0.1:9444,
//! performs a TLS 1.3 handshake, then sends an HTTP/2 GET request.
//!
//! Usage:
//!   cargo run --example h2_tls_client --features "h2,tcp-tls,rustcrypto-chacha"
//!
//! Expects `h2_tls_server` running on 127.0.0.1:9444.

use std::io::{Read, Write};
use std::net::TcpStream;

use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h2::H2Event;
use milli_http::h2::client::H2Client;
use milli_http::tcp_tls::client::TlsClient;
use milli_http::tcp_tls::connection::TlsEvent;
use milli_http::tls::TransportParams;
use milli_http::tls::handshake::TlsConfig;

fn main() {
    println!("milli-http HTTP/2 (TLS) client");
    println!("==============================");

    let mut stream =
        TcpStream::connect("127.0.0.1:9444").expect("failed to connect to 127.0.0.1:9444");
    println!("[conn] connected to 127.0.0.1:9444");

    stream.set_nonblocking(true).expect("set_nonblocking");

    // -- Create TLS client --
    let tls_config = TlsConfig {
        server_name: heapless::String::try_from("127.0.0.1").unwrap(),
        alpn_protocols: &[b"h2"],
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

    let mut tls: TlsClient<Aes128GcmProvider, 65536> =
        TlsClient::new(Aes128GcmProvider, tls_config, secret, random);

    let mut h2 = H2Client::<16, 65536>::new();
    let mut tls_active = false;
    let mut handshake_done = false;
    let mut request_sent = false;
    let mut request_stream: Option<u64> = None;

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
                                if let Err(e) = h2.feed_data(&app_buf[..n]) {
                                    eprintln!("[h2] feed_data error: {e}");
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

        // 4. Process H2 events
        while let Some(event) = h2.poll_event() {
            match event {
                H2Event::Connected => {
                    println!("[h2] connection established");
                    handshake_done = true;
                }
                H2Event::Headers(stream_id) => {
                    println!("[h2] response headers on stream {stream_id}:");
                    h2.recv_headers(stream_id, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        println!("[h2]   {n}: {v}");
                    })
                    .ok();
                }
                H2Event::Data(stream_id) => {
                    let mut body = [0u8; 8192];
                    match h2.recv_body(stream_id, &mut body) {
                        Ok((n, _fin)) => {
                            let text = core::str::from_utf8(&body[..n]).unwrap_or("<binary>");
                            println!("[h2] body ({n} bytes):\n{text}");
                        }
                        Err(e) => eprintln!("[h2] recv_body error: {e}"),
                    }
                }
                H2Event::Finished(stream_id) => {
                    println!("[h2] stream {stream_id} finished");
                    if request_stream == Some(stream_id) {
                        println!("[done] request complete");
                        return;
                    }
                }
                H2Event::GoAway(last_id, code) => {
                    println!("[h2] GOAWAY (last_stream={last_id}, error={code})");
                    return;
                }
                H2Event::StreamReset(stream_id, code) => {
                    println!("[h2] stream {stream_id} reset (error={code})");
                }
                _ => {}
            }
        }

        // 5. Send GET / once TLS and H2 handshakes are done
        if tls_active && handshake_done && !request_sent {
            let stream_id = h2
                .send_request("GET", "/", "127.0.0.1:9444", &[], true)
                .expect("send_request failed");
            println!("[h2] sent GET / on stream {stream_id}");
            request_stream = Some(stream_id);
            request_sent = true;
        }

        // 6. H2 output → encrypt via TLS
        if tls_active {
            let mut out_buf = [0u8; 65536];
            while let Some(data) = h2.poll_output(&mut out_buf) {
                let copy: Vec<u8> = data.to_vec();
                if let Err(e) = tls.send_app_data(&copy) {
                    eprintln!("[tls] send_app_data error: {e}");
                    return;
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    eprintln!("[timeout] did not complete");
}
