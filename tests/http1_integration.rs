//! HTTP/1.1 integration tests exercising Http1Server and Http1Client end-to-end.
//!
//! These tests use the public API surface of `milli_http::http1` to verify
//! that the HTTP/1.1 client and server wrappers correctly handle request/response
//! flows, headers, bodies, keep-alive, chunked encoding, and stream lifecycle.

#![cfg(feature = "http1")]

use milli_http::http1::{Http1Client, Http1Event, Http1Server};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type TestHttp1Client = Http1Client<8192, 2048, 4096>;
type TestHttp1Server = Http1Server<8192, 2048, 4096>;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Transfer all pending output from one side to the other.
fn transfer_to_server(client: &mut TestHttp1Client, server: &mut TestHttp1Server) {
    let mut buf = [0u8; 8192];
    while let Some(data) = client.poll_output(&mut buf) {
        let copy = data.to_vec();
        server.feed_data(&copy).unwrap();
    }
}

fn transfer_to_client(server: &mut TestHttp1Server, client: &mut TestHttp1Client) {
    let mut buf = [0u8; 8192];
    while let Some(data) = server.poll_output(&mut buf) {
        let copy = data.to_vec();
        client.feed_data(&copy).unwrap();
    }
}

/// Create a fresh client/server pair. No handshake needed for HTTP/1.1.
fn setup_pair() -> (TestHttp1Client, TestHttp1Server) {
    (TestHttp1Client::new(), TestHttp1Server::new())
}

/// Collect all pending events.
fn drain_events_client(conn: &mut TestHttp1Client) -> Vec<Http1Event> {
    let mut events = Vec::new();
    while let Some(ev) = conn.poll_event() {
        events.push(ev);
    }
    events
}

fn drain_events_server(conn: &mut TestHttp1Server) -> Vec<Http1Event> {
    let mut events = Vec::new();
    while let Some(ev) = conn.poll_event() {
        events.push(ev);
    }
    events
}

/// Format a usize as ASCII decimal into `buf`. Returns the number of bytes written.
fn format_usize(mut n: usize, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}

// ===========================================================================
// Test cases
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. http1_get_request_response
// ---------------------------------------------------------------------------

#[test]
fn http1_get_request_response() {
    let (mut client, mut server) = setup_pair();

    // Client sends GET.
    let stream_id = client
        .send_request("GET", "/index.html", "test.local", &[], true)
        .unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(
        events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))),
        "server should receive Request event"
    );

    // Server reads request headers.
    let mut method = Vec::new();
    let mut path = Vec::new();
    server
        .recv_headers(1, |name, value| match name {
            b":method" => method.extend_from_slice(value),
            b":path" => path.extend_from_slice(value),
            _ => {}
        })
        .unwrap();
    assert_eq!(method, b"GET");
    assert_eq!(path, b"/index.html");

    // Server sends response.
    let body = b"<html>Hello!</html>";
    let mut cl_buf = [0u8; 10];
    let cl_len = format_usize(body.len(), &mut cl_buf);
    server
        .send_response(
            1,
            200,
            &[
                (b"content-type", b"text/html"),
                (b"content-length", &cl_buf[..cl_len]),
            ],
            false,
        )
        .unwrap();
    server.send_body(1, body, true).unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client receives response.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == stream_id)),
        "client should receive Headers event"
    );
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Data(sid) if *sid == stream_id)),
        "client should receive Data event"
    );
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Finished(sid) if *sid == stream_id)),
        "client should receive Finished event"
    );

    // Client reads status.
    let mut status = Vec::new();
    let mut ct = Vec::new();
    client
        .recv_headers(stream_id, |name, value| match name {
            b":status" => status.extend_from_slice(value),
            b"content-type" => ct.extend_from_slice(value),
            _ => {}
        })
        .unwrap();
    assert_eq!(status, b"200");
    assert_eq!(ct, b"text/html");

    // Client reads body.
    let mut recv_buf = [0u8; 256];
    let (n, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..n], body);
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 2. http1_post_with_body
// ---------------------------------------------------------------------------

#[test]
fn http1_post_with_body() {
    let (mut client, mut server) = setup_pair();

    let req_body = b"{\"name\":\"test\"}";
    let mut cl_buf = [0u8; 10];
    let cl_len = format_usize(req_body.len(), &mut cl_buf);

    // Client sends POST with JSON body.
    let stream_id = client
        .send_request(
            "POST",
            "/api/items",
            "test.local",
            &[
                (b"content-type", b"application/json"),
                (b"content-length", &cl_buf[..cl_len]),
            ],
            false,
        )
        .unwrap();
    client.send_body(stream_id, req_body, true).unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));

    // Server reads headers.
    let mut method = Vec::new();
    let mut ct = Vec::new();
    server
        .recv_headers(1, |name, value| match name {
            b":method" => method.extend_from_slice(value),
            b"content-type" => ct.extend_from_slice(value),
            _ => {}
        })
        .unwrap();
    assert_eq!(method, b"POST");
    assert_eq!(ct, b"application/json");

    // Server reads request body.
    let mut body_buf = [0u8; 256];
    let (n, fin) = server.recv_body(1, &mut body_buf).unwrap();
    assert_eq!(&body_buf[..n], req_body);
    assert!(fin);

    // Server sends response.
    let resp_body = b"{\"id\":1}";
    let mut cl_buf2 = [0u8; 10];
    let cl_len2 = format_usize(resp_body.len(), &mut cl_buf2);
    server
        .send_response(
            1,
            200,
            &[
                (b"content-type", b"application/json"),
                (b"content-length", &cl_buf2[..cl_len2]),
            ],
            false,
        )
        .unwrap();
    server.send_body(1, resp_body, true).unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client reads response.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Finished(sid) if *sid == stream_id))
    );

    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    let mut recv_buf = [0u8; 256];
    let (n, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..n], resp_body);
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 3. http1_keep_alive_sequential
// ---------------------------------------------------------------------------

#[test]
fn http1_keep_alive_sequential() {
    let (mut client, mut server) = setup_pair();

    for i in 1..=3u64 {
        let path = match i {
            1 => "/page1",
            2 => "/page2",
            _ => "/page3",
        };

        // Client sends GET.
        let stream_id = client
            .send_request("GET", path, "test.local", &[], true)
            .unwrap();
        assert_eq!(stream_id, i);

        transfer_to_server(&mut client, &mut server);

        // Server receives request.
        let events = drain_events_server(&mut server);
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == i)),
            "server should receive request {i}"
        );

        // Server reads and consumes headers.
        let mut method = Vec::new();
        let mut recv_path = Vec::new();
        server
            .recv_headers(i, |name, value| match name {
                b":method" => method.extend_from_slice(value),
                b":path" => recv_path.extend_from_slice(value),
                _ => {}
            })
            .unwrap();
        assert_eq!(method, b"GET");
        assert_eq!(recv_path, path.as_bytes());

        // Server sends response.
        let body = b"ok";
        server
            .send_response(i, 200, &[(b"content-length", b"2")], false)
            .unwrap();
        server.send_body(i, body, true).unwrap();

        transfer_to_client(&mut server, &mut client);

        // Client receives and consumes response.
        let events = drain_events_client(&mut client);
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == stream_id)),
            "client should receive response headers for request {i}"
        );

        // Consume headers.
        let mut status = Vec::new();
        client
            .recv_headers(stream_id, |name, value| {
                if name == b":status" {
                    status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(status, b"200");

        // Consume body.
        let mut recv_buf = [0u8; 64];
        let (n, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..n], b"ok");
        assert!(fin);
    }
}

// ---------------------------------------------------------------------------
// 4. http1_connection_close
// ---------------------------------------------------------------------------

#[test]
fn http1_connection_close() {
    let (mut client, mut server) = setup_pair();

    // Client sends request with Connection: close.
    let stream_id = client
        .send_request(
            "GET",
            "/goodbye",
            "test.local",
            &[(b"Connection", b"close")],
            true,
        )
        .unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));

    // Server reads headers — should see Connection: close.
    let mut connection_hdr = Vec::new();
    server
        .recv_headers(1, |name, value| {
            if name == b"Connection" {
                connection_hdr.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(connection_hdr, b"close");

    // Server sends response.
    server
        .send_response(1, 200, &[(b"content-length", b"7")], false)
        .unwrap();
    server.send_body(1, b"goodbye", true).unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client receives response.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Finished(sid) if *sid == stream_id))
    );

    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    let mut recv_buf = [0u8; 64];
    let (n, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..n], b"goodbye");
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 5. http1_chunked_response
// ---------------------------------------------------------------------------

#[test]
fn http1_chunked_response() {
    let (mut client, mut server) = setup_pair();

    // Client sends GET.
    let stream_id = client
        .send_request("GET", "/chunked", "test.local", &[], true)
        .unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));
    server.recv_headers(1, |_, _| {}).unwrap();

    // Server sends chunked response by manually encoding chunks.
    server
        .send_response(1, 200, &[(b"transfer-encoding", b"chunked")], false)
        .unwrap();

    // Manually encode chunks: "Hello" (5 bytes) + ", World!" (8 bytes) + terminator.
    server.send_body(1, b"5\r\nHello\r\n", true).unwrap();
    transfer_to_client(&mut server, &mut client);

    // Feed remaining chunks separately to test incremental parsing.
    // We need to go through the server's send_body + transfer path.
    // Since the first transfer already delivered, feed the rest directly to client.
    client.feed_data(b"8\r\n, World!\r\n0\r\n\r\n").unwrap();

    // Client should have decoded the chunked body.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == stream_id)),
        "client should receive Headers event"
    );
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Finished(sid) if *sid == stream_id)),
        "client should receive Finished event"
    );

    // Read headers.
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    // Read decoded body.
    let mut recv_buf = [0u8; 256];
    let (n, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..n], b"Hello, World!");
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 6. http1_large_body
// ---------------------------------------------------------------------------

#[test]
fn http1_large_body() {
    let (mut client, mut server) = setup_pair();

    // Client sends POST with ~4KB body.
    let large_body = [0x58_u8; 4000]; // 'X' repeated 4000 times
    let mut cl_buf = [0u8; 10];
    let cl_len = format_usize(large_body.len(), &mut cl_buf);

    let stream_id = client
        .send_request(
            "POST",
            "/upload",
            "test.local",
            &[(b"content-length", &cl_buf[..cl_len])],
            false,
        )
        .unwrap();
    client.send_body(stream_id, &large_body, true).unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));

    // Server reads headers.
    server.recv_headers(1, |_, _| {}).unwrap();

    // Server reads body (may need multiple reads due to DATABUF=4096).
    let mut all_data = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        match server.recv_body(1, &mut buf) {
            Ok((0, true)) => break,
            Ok((n, fin)) => {
                all_data.extend_from_slice(&buf[..n]);
                if fin {
                    break;
                }
                // Trigger processing for remaining data.
                server.feed_data(b"").unwrap();
                while server.poll_event().is_some() {}
            }
            Err(_) => break,
        }
    }

    assert_eq!(all_data.len(), 4000, "server should receive all 4000 bytes");
    assert!(
        all_data.iter().all(|&b| b == 0x58),
        "all body bytes should be 0x58"
    );
}

// ---------------------------------------------------------------------------
// 7. http1_multiple_headers
// ---------------------------------------------------------------------------

#[test]
fn http1_multiple_headers() {
    let (mut client, mut server) = setup_pair();

    // Client sends request with many custom headers.
    let stream_id = client
        .send_request(
            "GET",
            "/headers",
            "test.local",
            &[
                (b"Accept", b"text/html"),
                (b"Accept-Language", b"en-US"),
                (b"X-Custom-A", b"alpha"),
                (b"X-Custom-B", b"beta"),
                (b"X-Custom-C", b"gamma"),
            ],
            true,
        )
        .unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));

    // Server reads all headers.
    let mut accept = Vec::new();
    let mut accept_lang = Vec::new();
    let mut x_a = Vec::new();
    let mut x_b = Vec::new();
    let mut x_c = Vec::new();
    server
        .recv_headers(1, |name, value| match name {
            b"Accept" => accept.extend_from_slice(value),
            b"Accept-Language" => accept_lang.extend_from_slice(value),
            b"X-Custom-A" => x_a.extend_from_slice(value),
            b"X-Custom-B" => x_b.extend_from_slice(value),
            b"X-Custom-C" => x_c.extend_from_slice(value),
            _ => {}
        })
        .unwrap();

    assert_eq!(accept, b"text/html");
    assert_eq!(accept_lang, b"en-US");
    assert_eq!(x_a, b"alpha");
    assert_eq!(x_b, b"beta");
    assert_eq!(x_c, b"gamma");

    // Server sends response with custom headers back.
    server
        .send_response(
            1,
            200,
            &[
                (b"content-length", b"0"),
                (b"X-Response-A", b"one"),
                (b"X-Response-B", b"two"),
            ],
            false,
        )
        .unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client reads response headers.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == stream_id))
    );

    let mut status = Vec::new();
    let mut resp_a = Vec::new();
    let mut resp_b = Vec::new();
    client
        .recv_headers(stream_id, |name, value| match name {
            b":status" => status.extend_from_slice(value),
            b"X-Response-A" => resp_a.extend_from_slice(value),
            b"X-Response-B" => resp_b.extend_from_slice(value),
            _ => {}
        })
        .unwrap();

    assert_eq!(status, b"200");
    assert_eq!(resp_a, b"one");
    assert_eq!(resp_b, b"two");
}

// ---------------------------------------------------------------------------
// 8. http1_different_status_codes
// ---------------------------------------------------------------------------

#[test]
fn http1_different_status_codes() {
    for &(code, expected_str) in &[
        (200u16, b"200" as &[u8]),
        (301, b"301"),
        (404, b"404"),
        (500, b"500"),
    ] {
        let (mut client, mut server) = setup_pair();

        let stream_id = client
            .send_request("GET", "/", "test.local", &[], true)
            .unwrap();

        transfer_to_server(&mut client, &mut server);

        let events = drain_events_server(&mut server);
        assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));
        server.recv_headers(1, |_, _| {}).unwrap();

        server
            .send_response(1, code, &[(b"content-length", b"0")], false)
            .unwrap();

        transfer_to_client(&mut server, &mut client);

        let events = drain_events_client(&mut client);
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == stream_id))
        );

        let mut status = Vec::new();
        client
            .recv_headers(stream_id, |name, value| {
                if name == b":status" {
                    status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(
            status, expected_str,
            "status code {code} should round-trip correctly"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. http1_head_request
// ---------------------------------------------------------------------------

#[test]
fn http1_head_request() {
    let (mut client, mut server) = setup_pair();

    // Client sends HEAD request.
    let stream_id = client
        .send_request("HEAD", "/info", "test.local", &[], true)
        .unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives request.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(_))));

    let mut method = Vec::new();
    server
        .recv_headers(1, |name, value| {
            if name == b":method" {
                method.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"HEAD");

    // Server responds with Content-Length: 0 (no body for HEAD).
    // Note: A full HTTP/1.1 implementation would allow Content-Length matching
    // the GET response, but the current codec uses CL for body framing, so
    // we use CL: 0 to signal no body.
    server
        .send_response(
            1,
            200,
            &[(b"content-type", b"text/plain"), (b"content-length", b"0")],
            false,
        )
        .unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client receives response with no body.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == stream_id))
    );
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Finished(sid) if *sid == stream_id)),
        "HEAD response with CL:0 should trigger Finished"
    );

    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");
}

// ---------------------------------------------------------------------------
// 10. http1_post_then_get_keep_alive
// ---------------------------------------------------------------------------

#[test]
fn http1_post_then_get_keep_alive() {
    let (mut client, mut server) = setup_pair();

    // --- Request 1: POST with body ---

    let req_body = b"payload";
    let mut cl_buf = [0u8; 10];
    let cl_len = format_usize(req_body.len(), &mut cl_buf);

    let sid1 = client
        .send_request(
            "POST",
            "/submit",
            "test.local",
            &[(b"content-length", &cl_buf[..cl_len])],
            false,
        )
        .unwrap();
    client.send_body(sid1, req_body, true).unwrap();

    transfer_to_server(&mut client, &mut server);

    // Server receives POST.
    let events = drain_events_server(&mut server);
    assert!(events.iter().any(|ev| matches!(ev, Http1Event::Headers(1))));

    // Server consumes request headers + body.
    let mut method = Vec::new();
    server
        .recv_headers(1, |name, value| {
            if name == b":method" {
                method.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"POST");

    let mut body_buf = [0u8; 64];
    let (n, fin) = server.recv_body(1, &mut body_buf).unwrap();
    assert_eq!(&body_buf[..n], req_body);
    assert!(fin);

    // Server sends response 1.
    server
        .send_response(1, 201, &[(b"content-length", b"7")], false)
        .unwrap();
    server.send_body(1, b"created", true).unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client consumes response 1.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == sid1))
    );

    let mut status = Vec::new();
    client
        .recv_headers(sid1, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"201");

    let mut recv_buf = [0u8; 64];
    let (n, fin) = client.recv_body(sid1, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..n], b"created");
    assert!(fin);

    // --- Request 2: GET (no body) ---

    let sid2 = client
        .send_request("GET", "/status", "test.local", &[], true)
        .unwrap();
    assert_eq!(sid2, 2, "second request should use stream_id 2");

    transfer_to_server(&mut client, &mut server);

    // Server receives GET on same connection.
    let events = drain_events_server(&mut server);
    assert!(
        events.iter().any(|ev| matches!(ev, Http1Event::Headers(2))),
        "server should receive second request with stream_id 2"
    );

    // Server reads headers.
    let mut method2 = Vec::new();
    let mut path2 = Vec::new();
    server
        .recv_headers(2, |name, value| match name {
            b":method" => method2.extend_from_slice(value),
            b":path" => path2.extend_from_slice(value),
            _ => {}
        })
        .unwrap();
    assert_eq!(method2, b"GET");
    assert_eq!(path2, b"/status");

    // Server sends response 2.
    server
        .send_response(2, 200, &[(b"content-length", b"2")], false)
        .unwrap();
    server.send_body(2, b"ok", true).unwrap();

    transfer_to_client(&mut server, &mut client);

    // Client receives response 2.
    let events = drain_events_client(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Http1Event::Headers(sid) if *sid == sid2))
    );

    let mut status2 = Vec::new();
    client
        .recv_headers(sid2, |name, value| {
            if name == b":status" {
                status2.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status2, b"200");

    let mut recv_buf2 = [0u8; 64];
    let (n2, fin2) = client.recv_body(sid2, &mut recv_buf2).unwrap();
    assert_eq!(&recv_buf2[..n2], b"ok");
    assert!(fin2);
}
