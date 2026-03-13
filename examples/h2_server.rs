//! Minimal HTTP/2 server example.
//!
//! Binds a TCP socket on `0.0.0.0:8443` and serves HTTP/2 cleartext (h2c).
//! In production, TLS would wrap the TCP stream (see `multi_server` example).
//!
//! Usage:
//!   cargo run --example h2_server --features h2
//!
//! Then from another terminal:
//!   curl --http2-prior-knowledge http://127.0.0.1:8443/
//!
//! NOTE: This example requires the `tcp-tls` feature for real TLS-based h2.
//! Without it, this speaks h2c (HTTP/2 cleartext / prior knowledge).

use std::io::{Read, Write};
use std::net::TcpListener;

use milli_http::h2::H2Event;
use milli_http::h2::server::H2Server;

fn main() {
    println!("milli-http HTTP/2 server (h2c)");
    println!("==============================");

    let listener = TcpListener::bind("0.0.0.0:8443").expect("failed to bind TCP on :8443");
    println!("[init] listening on 0.0.0.0:8443 (TCP, h2c)");

    let (mut stream, client_addr) = listener.accept().expect("accept failed");
    println!("[conn] accepted connection from {client_addr}");

    stream.set_nonblocking(true).expect("set_nonblocking");

    let mut h2 = H2Server::<32, 65536>::new();

    // Response body served to every request.
    let body = b"<!DOCTYPE html>\n<html>\n<head><title>milli-http</title></head>\n<body>\n<h1>Hello from milli-http!</h1>\n<p>You are connected via HTTP/2.</p>\n</body>\n</html>\n";

    loop {
        // 1. Read from TCP socket.
        let mut recv_buf = [0u8; 65535];
        match stream.read(&mut recv_buf) {
            Ok(0) => {
                println!("[conn] client disconnected");
                return;
            }
            Ok(n) => {
                if let Err(e) = h2.feed_data(&recv_buf[..n]) {
                    eprintln!("[h2] feed_data error: {e}");
                    return;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("[conn] read error: {e}");
                return;
            }
        }

        // 2. Write pending output to TCP socket.
        let mut out_buf = [0u8; 65535];
        while let Some(data) = h2.poll_output(&mut out_buf) {
            if let Err(e) = stream.write_all(data) {
                eprintln!("[conn] write error: {e}");
                return;
            }
        }

        // 3. Process H2 events.
        while let Some(event) = h2.poll_event() {
            match event {
                H2Event::Connected => {
                    println!("[h2] connection established");
                }

                H2Event::Headers(stream_id) => {
                    println!("[h2] request headers on stream {stream_id}");

                    h2.recv_headers(stream_id, |name, value| {
                        let n = core::str::from_utf8(name).unwrap_or("<bin>");
                        let v = core::str::from_utf8(value).unwrap_or("<bin>");
                        println!("[h2]   {n}: {v}");
                    })
                    .ok();

                    let content_length = body.len().to_string();
                    let extra: &[(&[u8], &[u8])] = &[
                        (b"content-type", b"text/html"),
                        (b"content-length", content_length.as_bytes()),
                        (b"server", b"milli-http/0.1"),
                    ];

                    if let Err(e) = h2.send_response(stream_id, 200, extra, false) {
                        eprintln!("[h2] error sending response headers: {e}");
                        continue;
                    }
                    match h2.send_body(stream_id, body, true) {
                        Ok(n) => println!("[h2] sent {n} body bytes on stream {stream_id}"),
                        Err(e) => eprintln!("[h2] error sending body: {e}"),
                    }
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
    }
}
