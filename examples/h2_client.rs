//! Minimal HTTP/2 client example.
//!
//! Connects to a server via TCP and performs an HTTP/2 cleartext (h2c)
//! request using prior knowledge.
//!
//! Usage:
//!   cargo run --example h2_client --features h2
//!
//! Expects an h2c server on 127.0.0.1:8443 (see `h2_server` example).
//!
//! NOTE: For TLS-based h2, the `tcp-tls` feature is needed (not yet implemented).

use std::io::{Read, Write};
use std::net::TcpStream;

use milli_http::h2::H2Event;
use milli_http::h2::client::H2Client;

fn main() {
    println!("milli-http HTTP/2 client (h2c)");
    println!("==============================");

    let mut stream =
        TcpStream::connect("127.0.0.1:8443").expect("failed to connect to 127.0.0.1:8443");
    println!("[conn] connected to 127.0.0.1:8443");

    stream.set_nonblocking(true).expect("set_nonblocking");

    let mut h2 = H2Client::<16, 65536>::new();

    // Drive the handshake first.
    let mut handshake_done = false;
    let mut request_sent = false;
    let mut response_stream: Option<u64> = None;

    for _round in 0..100 {
        // Send pending output.
        let mut out_buf = [0u8; 65535];
        while let Some(data) = h2.poll_output(&mut out_buf) {
            if let Err(e) = stream.write_all(data) {
                eprintln!("[conn] write error: {e}");
                return;
            }
        }

        // Read from TCP.
        let mut recv_buf = [0u8; 65535];
        match stream.read(&mut recv_buf) {
            Ok(0) => {
                println!("[conn] server disconnected");
                break;
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

        // Process events.
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
                    if response_stream == Some(stream_id) {
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

        // Send request once handshake is done.
        if handshake_done && !request_sent {
            let stream_id = h2
                .send_request("GET", "/", "127.0.0.1:8443", &[], true)
                .expect("send_request failed");
            println!("[h2] sent GET / on stream {stream_id}");
            response_stream = Some(stream_id);
            request_sent = true;
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
