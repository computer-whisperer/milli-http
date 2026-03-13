//! HTTP/2 over TLS server example.
//!
//! Binds a TCP socket on `0.0.0.0:9444`, performs a TLS 1.3 handshake
//! (self-signed Ed25519 cert, ALPN "h2"), then speaks HTTP/2 inside the tunnel.
//!
//! Usage:
//!   cargo run --example h2_tls_server --features "h2,tcp-tls,rustcrypto-chacha"
//!
//! Then from another terminal:
//!   curl -k https://127.0.0.1:9444/

use std::io::{Read, Write};
use std::net::TcpListener;

use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::h2::H2Event;
use milli_http::h2::server::H2Server;
use milli_http::tcp_tls::connection::TlsEvent;
use milli_http::tcp_tls::server::TlsServer;
use milli_http::tls::TransportParams;
use milli_http::tls::handshake::ServerTlsConfig;

fn main() {
    println!("milli-http HTTP/2 (TLS) server");
    println!("==============================");

    // -- Generate self-signed Ed25519 certificate --
    let seed: [u8; 32] = [0x42u8; 32];
    let pk = ed25519_public_key_from_seed(&seed);
    let mut cert_buf = [0u8; 512];
    let cert_len =
        build_ed25519_cert_der(&pk, &mut cert_buf).expect("failed to build certificate DER");
    let cert_der: &'static [u8] = Box::leak(cert_buf[..cert_len].to_vec().into_boxed_slice());
    let private_key_der: &'static [u8] = Box::leak(Box::new(seed));
    println!("[init] generated self-signed Ed25519 certificate ({cert_len} bytes)");

    // -- Bind TCP socket --
    let listener = TcpListener::bind("0.0.0.0:9444").expect("failed to bind TCP on :9444");
    println!("[init] listening on 0.0.0.0:9444 (TCP+TLS, HTTP/2)");

    let (mut stream, client_addr) = listener.accept().expect("accept failed");
    println!("[conn] accepted connection from {client_addr}");

    stream.set_nonblocking(true).expect("set_nonblocking");

    // -- Create TLS server --
    let tls_config = ServerTlsConfig {
        cert_der,
        private_key_der,
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
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

    let mut tls: TlsServer<Aes128GcmProvider, 65536> =
        TlsServer::new(Aes128GcmProvider, tls_config, secret, random);

    let mut h2 = H2Server::<32, 65536>::new();
    let mut tls_active = false;

    loop {
        // 1. Read from TCP → feed to TLS
        let mut recv_buf = [0u8; 16384];
        match stream.read(&mut recv_buf) {
            Ok(0) => {
                println!("[conn] client disconnected");
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

        // 2. Process TLS events
        while let Some(event) = tls.poll_event() {
            match event {
                TlsEvent::HandshakeComplete => {
                    println!("[tls] handshake complete");
                    tls_active = true;
                }
                TlsEvent::AppData => {
                    // Read decrypted data → feed to H2
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

        // 3. Process H2 events
        while let Some(event) = h2.poll_event() {
            match event {
                H2Event::Connected => {
                    println!("[h2] connection established");
                }
                H2Event::Headers(stream_id) => {
                    println!("[h2] request headers on stream {stream_id}");

                    let mut path = [0u8; 256];
                    let mut path_len = 0usize;

                    h2.recv_headers(stream_id, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        println!("[h2]   {n}: {v}");
                        if name == b":path" {
                            let copy = value.len().min(path.len());
                            path[..copy].copy_from_slice(&value[..copy]);
                            path_len = copy;
                        }
                    })
                    .ok();

                    let path_str = core::str::from_utf8(&path[..path_len]).unwrap_or("/");
                    route_h2(&mut h2, stream_id, path_str);
                }
                H2Event::Data(stream_id) => {
                    let mut discard = [0u8; 4096];
                    loop {
                        match h2.recv_body(stream_id, &mut discard) {
                            Ok((_, true)) | Err(_) => break,
                            Ok((_, false)) => continue,
                        }
                    }
                }
                H2Event::Finished(stream_id) => {
                    println!("[h2] stream {stream_id} finished");
                }
                H2Event::GoAway(last_id, code) => {
                    println!("[h2] received GOAWAY (last_stream={last_id}, error={code})");
                    return;
                }
                H2Event::StreamReset(stream_id, code) => {
                    println!("[h2] stream {stream_id} reset (error={code})");
                }
                _ => {}
            }
        }

        // 4. H2 output → encrypt via TLS
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

        // 5. TLS output → write to TCP
        let mut tls_out = [0u8; 32768];
        while let Some(data) = tls.poll_output(&mut tls_out) {
            if let Err(e) = stream.write_all(data) {
                eprintln!("[conn] write error: {e}");
                return;
            }
        }
    }
}

fn route_h2(h2: &mut H2Server<32, 65536>, stream_id: u64, path: &str) {
    match path {
        "/status/404" => {
            let body = b"Not Found";
            let cl = body.len().to_string();
            h2.send_response(
                stream_id,
                404,
                &[
                    (b"content-type", b"text/plain"),
                    (b"content-length", cl.as_bytes()),
                    (b"server", b"milli-http"),
                ],
                false,
            )
            .ok();
            h2.send_body(stream_id, body, true).ok();
        }
        "/large" => {
            let data = [b'X'; 32768];
            let cl = "32768";
            h2.send_response(
                stream_id,
                200,
                &[
                    (b"content-type", b"application/octet-stream"),
                    (b"content-length", cl.as_bytes()),
                    (b"server", b"milli-http"),
                ],
                false,
            )
            .ok();
            // Send in chunks — H2 max frame size is 16384
            let mut offset = 0;
            while offset < data.len() {
                let end_stream = false; // we'll set true on the last chunk
                match h2.send_body(stream_id, &data[offset..], offset + 16384 >= data.len()) {
                    Ok(n) => {
                        println!(
                            "[h2] sent {n} body bytes on stream {stream_id} (offset {offset})"
                        );
                        offset += n;
                    }
                    Err(e) => {
                        eprintln!("[h2] send_body error: {e}");
                        break;
                    }
                }
                let _ = end_stream; // suppress unused warning
            }
        }
        _ => {
            let body = b"<!DOCTYPE html>\n<html>\n<head><title>milli-http</title></head>\n<body>\n<h1>Hello from milli-http!</h1>\n<p>You are connected via HTTP/2 (TLS).</p>\n</body>\n</html>\n";
            let cl = body.len().to_string();
            h2.send_response(
                stream_id,
                200,
                &[
                    (b"content-type", b"text/html"),
                    (b"content-length", cl.as_bytes()),
                    (b"server", b"milli-http"),
                ],
                false,
            )
            .ok();
            h2.send_body(stream_id, body, true).ok();
        }
    }
}
