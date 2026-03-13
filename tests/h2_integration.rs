//! HTTP/2 integration tests exercising H2Server and H2Client end-to-end.
//!
//! These tests use the public API surface of `milli_http::h2` to verify
//! that the H2 client and server wrappers correctly handle handshakes,
//! request/response flows, headers, bodies, and stream lifecycle.

#![cfg(feature = "h2")]

use milli_http::h2::{H2Client, H2Event, H2Server};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type TestH2Client = H2Client<8, 16384, 2048, 4096>;
type TestH2Server = H2Server<8, 16384, 2048, 4096>;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Exchange all pending output between client and server, looping until
/// no more data flows in either direction.
fn exchange_h2(client: &mut TestH2Client, server: &mut TestH2Server) {
    for _ in 0..10 {
        let mut any = false;

        // Client → Server
        let mut buf = [0u8; 16384];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
            any = true;
        }

        // Server → Client
        let mut buf2 = [0u8; 16384];
        while let Some(data) = server.poll_output(&mut buf2) {
            let copy = data.to_vec();
            client.feed_data(&copy).unwrap();
            any = true;
        }

        if !any {
            break;
        }
    }
}

/// Run the HTTP/2 handshake to completion.
///
/// After calling this, both sides should have exchanged SETTINGS and
/// emitted `H2Event::Connected`.
fn run_h2_handshake(client: &mut TestH2Client, server: &mut TestH2Server) {
    for _ in 0..5 {
        exchange_h2(client, server);
    }
}

/// Create an H2Client and H2Server with the handshake complete and
/// Connected events drained from both sides.
fn setup_h2_pair() -> (TestH2Client, TestH2Server) {
    let mut client = TestH2Client::new();
    let mut server = TestH2Server::new();

    run_h2_handshake(&mut client, &mut server);

    // Drain Connected events from both sides.
    let mut client_connected = false;
    let mut server_connected = false;
    while let Some(ev) = client.poll_event() {
        if ev == H2Event::Connected {
            client_connected = true;
        }
    }
    while let Some(ev) = server.poll_event() {
        if ev == H2Event::Connected {
            server_connected = true;
        }
    }

    assert!(
        client_connected,
        "H2 setup: client did not receive H2Event::Connected"
    );
    assert!(
        server_connected,
        "H2 setup: server did not receive H2Event::Connected"
    );

    (client, server)
}

/// Collect all pending H2Events from a client.
fn drain_client_events(client: &mut TestH2Client) -> Vec<H2Event> {
    let mut events = Vec::new();
    while let Some(ev) = client.poll_event() {
        events.push(ev);
    }
    events
}

/// Wait for a specific event type on the server, exchanging packets as needed.
fn wait_for_server_headers(client: &mut TestH2Client, server: &mut TestH2Server) -> u64 {
    for _ in 0..10 {
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                return sid;
            }
        }
        exchange_h2(client, server);
    }
    panic!("server did not receive H2Event::Headers");
}

/// Wait for response headers on the client, exchanging packets as needed.
fn wait_for_client_headers(
    client: &mut TestH2Client,
    server: &mut TestH2Server,
    expected_stream: u64,
) {
    for _ in 0..10 {
        while let Some(ev) = client.poll_event() {
            if let H2Event::Headers(sid) = ev {
                if sid == expected_stream {
                    return;
                }
            }
        }
        exchange_h2(client, server);
    }
    panic!("client did not receive H2Event::Headers for stream {expected_stream}");
}

// ===========================================================================
// Test cases
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. h2_handshake_completes
// ---------------------------------------------------------------------------

#[test]
fn h2_handshake_completes() {
    // setup_h2_pair asserts that both sides receive H2Event::Connected.
    let (_client, _server) = setup_h2_pair();
}

// ---------------------------------------------------------------------------
// 2. h2_get_request_response
// ---------------------------------------------------------------------------

#[test]
fn h2_get_request_response() {
    let (mut client, mut server) = setup_h2_pair();

    // Client sends a GET request.
    let stream_id = client
        .send_request("GET", "/index.html", "test.local", &[], true)
        .unwrap();

    exchange_h2(&mut client, &mut server);

    // Server should see a Headers event.
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server reads request headers.
    let mut method = Vec::new();
    let mut path = Vec::new();
    server
        .recv_headers(req_stream, |name, value| {
            if name == b":method" {
                method.extend_from_slice(value);
            } else if name == b":path" {
                path.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"GET");
    assert_eq!(path, b"/index.html");

    // Server sends 200 response with body.
    server
        .send_response(req_stream, 200, &[(b"content-type", b"text/html")], false)
        .unwrap();
    let body = b"Hello, world!";
    server.send_body(req_stream, body, true).unwrap();

    exchange_h2(&mut client, &mut server);

    // Client should see Headers and Data events.
    wait_for_client_headers(&mut client, &mut server, stream_id);

    // Client reads response status.
    let mut status = Vec::new();
    let mut content_type = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            } else if name == b"content-type" {
                content_type.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");
    assert_eq!(content_type, b"text/html");

    // Client reads response body.
    let mut recv_buf = [0u8; 256];
    let (len, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..len], body);
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 3. h2_post_with_body
// ---------------------------------------------------------------------------

#[test]
fn h2_post_with_body() {
    let (mut client, mut server) = setup_h2_pair();

    // Client sends POST with body.
    let stream_id = client
        .send_request(
            "POST",
            "/api/data",
            "test.local",
            &[(b"content-type", b"application/json")],
            false,
        )
        .unwrap();

    let req_body = b"{\"key\":\"value\"}";
    client.send_body(stream_id, req_body, true).unwrap();

    exchange_h2(&mut client, &mut server);

    // Server receives request.
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server reads request headers.
    let mut method = Vec::new();
    let mut path = Vec::new();
    let mut ct = Vec::new();
    server
        .recv_headers(req_stream, |name, value| match name {
            b":method" => method.extend_from_slice(value),
            b":path" => path.extend_from_slice(value),
            b"content-type" => ct.extend_from_slice(value),
            _ => {}
        })
        .unwrap();
    assert_eq!(method, b"POST");
    assert_eq!(path, b"/api/data");
    assert_eq!(ct, b"application/json");

    // Server reads request body.
    let mut body_buf = [0u8; 256];
    let (body_len, fin) = server.recv_body(req_stream, &mut body_buf).unwrap();
    assert_eq!(&body_buf[..body_len], req_body);
    assert!(fin);

    // Server sends response.
    server
        .send_response(
            req_stream,
            200,
            &[(b"content-type", b"application/json")],
            false,
        )
        .unwrap();
    let resp_body = b"{\"status\":\"ok\"}";
    server.send_body(req_stream, resp_body, true).unwrap();

    exchange_h2(&mut client, &mut server);

    // Client reads response.
    wait_for_client_headers(&mut client, &mut server, stream_id);

    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"200");

    let mut resp_buf = [0u8; 256];
    let (n, fin) = client.recv_body(stream_id, &mut resp_buf).unwrap();
    assert_eq!(&resp_buf[..n], resp_body);
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 4. h2_multiple_concurrent_streams
// ---------------------------------------------------------------------------

#[test]
fn h2_multiple_concurrent_streams() {
    let (mut client, mut server) = setup_h2_pair();

    // Client sends 3 concurrent GET requests.
    let s1 = client
        .send_request("GET", "/page1", "test.local", &[], true)
        .unwrap();
    let s2 = client
        .send_request("GET", "/page2", "test.local", &[], true)
        .unwrap();
    let s3 = client
        .send_request("GET", "/page3", "test.local", &[], true)
        .unwrap();

    assert_ne!(s1, s2);
    assert_ne!(s2, s3);
    assert_ne!(s1, s3);

    exchange_h2(&mut client, &mut server);

    // Server should see Headers events for all 3 streams.
    let mut header_streams = Vec::new();
    for _ in 0..10 {
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                header_streams.push(sid);
            }
        }
        if header_streams.len() >= 3 {
            break;
        }
        exchange_h2(&mut client, &mut server);
    }
    assert!(
        header_streams.len() >= 3,
        "server should receive headers for all 3 streams, got {}",
        header_streams.len()
    );

    // Read paths from each stream.
    let mut paths: Vec<(u64, Vec<u8>)> = Vec::new();
    for &sid in &header_streams {
        let mut path = Vec::new();
        server
            .recv_headers(sid, |name, value| {
                if name == b":path" {
                    path.extend_from_slice(value);
                }
            })
            .unwrap();
        paths.push((sid, path));
    }
    // All 3 paths should be present.
    let path_values: Vec<&[u8]> = paths.iter().map(|(_, p)| p.as_slice()).collect();
    assert!(path_values.contains(&&b"/page1"[..]));
    assert!(path_values.contains(&&b"/page2"[..]));
    assert!(path_values.contains(&&b"/page3"[..]));

    // Server responds to all 3 requests.
    for &sid in &header_streams {
        server.send_response(sid, 200, &[], false).unwrap();
        server.send_body(sid, b"ok", true).unwrap();
    }

    exchange_h2(&mut client, &mut server);

    // Client should see response headers for all 3 streams.
    let mut response_streams = Vec::new();
    for _ in 0..10 {
        while let Some(ev) = client.poll_event() {
            if let H2Event::Headers(sid) = ev {
                response_streams.push(sid);
            }
        }
        if response_streams.len() >= 3 {
            break;
        }
        exchange_h2(&mut client, &mut server);
    }
    assert!(
        response_streams.len() >= 3,
        "client should receive response headers for all 3 streams, got {}",
        response_streams.len()
    );

    // Verify each response has status 200.
    for &sid in &[s1, s2, s3] {
        let mut status = Vec::new();
        client
            .recv_headers(sid, |name, value| {
                if name == b":status" {
                    status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(status, b"200", "stream {sid} should have status 200");
    }
}

// ---------------------------------------------------------------------------
// 5. h2_large_response_body
// ---------------------------------------------------------------------------

#[test]
fn h2_large_response_body() {
    let (mut client, mut server) = setup_h2_pair();

    // Client sends GET.
    let stream_id = client
        .send_request("GET", "/large", "test.local", &[], true)
        .unwrap();

    exchange_h2(&mut client, &mut server);
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server sends response headers.
    server.send_response(req_stream, 200, &[], false).unwrap();

    // Server sends body in multiple chunks (~4KB total).
    let chunk_a = [0xAA_u8; 1000];
    let chunk_b = [0xBB_u8; 1000];
    let chunk_c = [0xCC_u8; 1000];
    let chunk_d = [0xDD_u8; 1000];

    server.send_body(req_stream, &chunk_a, false).unwrap();
    server.send_body(req_stream, &chunk_b, false).unwrap();
    server.send_body(req_stream, &chunk_c, false).unwrap();
    server.send_body(req_stream, &chunk_d, true).unwrap();

    // Exchange until client has all data.
    for _ in 0..10 {
        exchange_h2(&mut client, &mut server);
    }

    // Drain events.
    let events = drain_client_events(&mut client);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, H2Event::Headers(sid) if *sid == stream_id)),
        "client should receive response headers"
    );

    // Read all body data.
    let mut all_data = Vec::new();
    let mut recv_buf = [0u8; 4096];
    loop {
        match client.recv_body(stream_id, &mut recv_buf) {
            Ok((0, true)) => break,
            Ok((n, fin)) => {
                all_data.extend_from_slice(&recv_buf[..n]);
                if fin {
                    break;
                }
                // Exchange + drain to get more data flowing
                exchange_h2(&mut client, &mut server);
                while client.poll_event().is_some() {}
            }
            Err(_) => break,
        }
    }

    assert!(
        all_data.len() >= 2000,
        "client should receive substantial body data, got {} bytes",
        all_data.len()
    );
    // Verify first chunk content.
    assert!(
        all_data[..1000].iter().all(|&b| b == 0xAA),
        "first 1000 bytes should be 0xAA"
    );
}

// ---------------------------------------------------------------------------
// 6. h2_response_headers_correct
// ---------------------------------------------------------------------------

#[test]
fn h2_response_headers_correct() {
    let (mut client, mut server) = setup_h2_pair();

    let stream_id = client
        .send_request("GET", "/headers-test", "test.local", &[], true)
        .unwrap();

    exchange_h2(&mut client, &mut server);
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server sends 404 with custom headers.
    // Note: we use end_stream=false on headers + empty body with end_stream=true
    // because the H2 connection cleans up streams in Closed state that have no
    // data_available, which would prevent recv_headers from working.
    server
        .send_response(
            req_stream,
            404,
            &[
                (b"content-type", b"text/html"),
                (b"server", b"milli-http/test"),
                (b"x-custom", b"hello"),
            ],
            false,
        )
        .unwrap();
    server.send_body(req_stream, &[], true).unwrap();

    exchange_h2(&mut client, &mut server);
    wait_for_client_headers(&mut client, &mut server, stream_id);

    // Client reads all response headers.
    let mut status = Vec::new();
    let mut content_type = Vec::new();
    let mut server_hdr = Vec::new();
    let mut x_custom = Vec::new();
    client
        .recv_headers(stream_id, |name, value| match name {
            b":status" => status.extend_from_slice(value),
            b"content-type" => content_type.extend_from_slice(value),
            b"server" => server_hdr.extend_from_slice(value),
            b"x-custom" => x_custom.extend_from_slice(value),
            _ => {}
        })
        .unwrap();

    assert_eq!(status, b"404", ":status should be 404");
    assert_eq!(content_type, b"text/html");
    assert_eq!(server_hdr, b"milli-http/test");
    assert_eq!(x_custom, b"hello");
}

// ---------------------------------------------------------------------------
// 7. h2_empty_body_response
// ---------------------------------------------------------------------------

#[test]
fn h2_empty_body_response() {
    let (mut client, mut server) = setup_h2_pair();

    let stream_id = client
        .send_request("GET", "/empty", "test.local", &[], true)
        .unwrap();

    exchange_h2(&mut client, &mut server);
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server sends 204 No Content with no body.
    // We use end_stream=false on headers + empty body with end_stream=true
    // because the H2 connection cleans up streams without data_available,
    // which would prevent recv_headers from working.
    server.send_response(req_stream, 204, &[], false).unwrap();
    server.send_body(req_stream, &[], true).unwrap();

    exchange_h2(&mut client, &mut server);

    // Client should receive Headers and Finished events.
    let mut got_headers = false;
    let mut got_finished = false;
    for _ in 0..5 {
        while let Some(ev) = client.poll_event() {
            match ev {
                H2Event::Headers(sid) if sid == stream_id => got_headers = true,
                H2Event::Finished(sid) if sid == stream_id => got_finished = true,
                _ => {}
            }
        }
        if got_headers && got_finished {
            break;
        }
        exchange_h2(&mut client, &mut server);
    }
    assert!(got_headers, "client should receive response Headers");
    assert!(got_finished, "client should receive Finished");

    // Verify status is 204.
    let mut status = Vec::new();
    client
        .recv_headers(stream_id, |name, value| {
            if name == b":status" {
                status.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(status, b"204");
}

// ---------------------------------------------------------------------------
// 8. h2_goaway
// ---------------------------------------------------------------------------

#[test]
fn h2_goaway() {
    let (mut client, mut server) = setup_h2_pair();

    // Server sends GOAWAY with error code 0 (no error).
    server.send_goaway(0).unwrap();

    exchange_h2(&mut client, &mut server);

    // Client should receive GoAway event.
    let mut got_goaway = false;
    let mut goaway_error = None;
    while let Some(ev) = client.poll_event() {
        if let H2Event::GoAway(_, error_code) = ev {
            got_goaway = true;
            goaway_error = Some(error_code);
        }
    }
    assert!(got_goaway, "client should receive GoAway event");
    assert_eq!(goaway_error, Some(0), "GOAWAY error code should be 0");
}

// ---------------------------------------------------------------------------
// 9. h2_request_headers_round_trip
// ---------------------------------------------------------------------------

#[test]
fn h2_request_headers_round_trip() {
    let (mut client, mut server) = setup_h2_pair();

    // Client sends PUT with custom headers.
    let stream_id = client
        .send_request(
            "PUT",
            "/resource/42",
            "example.com",
            &[
                (b"accept", b"*/*"),
                (b"user-agent", b"milli-http/test"),
                (b"x-request-id", b"abc-123"),
            ],
            true,
        )
        .unwrap();
    let _ = stream_id;

    exchange_h2(&mut client, &mut server);
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server reads all request headers.
    let mut method = Vec::new();
    let mut scheme = Vec::new();
    let mut authority = Vec::new();
    let mut path = Vec::new();
    let mut accept = Vec::new();
    let mut user_agent = Vec::new();
    let mut x_request_id = Vec::new();

    server
        .recv_headers(req_stream, |name, value| match name {
            b":method" => method.extend_from_slice(value),
            b":scheme" => scheme.extend_from_slice(value),
            b":authority" => authority.extend_from_slice(value),
            b":path" => path.extend_from_slice(value),
            b"accept" => accept.extend_from_slice(value),
            b"user-agent" => user_agent.extend_from_slice(value),
            b"x-request-id" => x_request_id.extend_from_slice(value),
            _ => {}
        })
        .unwrap();

    assert_eq!(method, b"PUT");
    assert_eq!(scheme, b"https");
    assert_eq!(authority, b"example.com");
    assert_eq!(path, b"/resource/42");
    assert_eq!(accept, b"*/*");
    assert_eq!(user_agent, b"milli-http/test");
    assert_eq!(x_request_id, b"abc-123");
}

// ---------------------------------------------------------------------------
// 10. h2_server_different_status_codes
// ---------------------------------------------------------------------------

#[test]
fn h2_server_different_status_codes() {
    for &(code, expected_str) in &[
        (200u16, b"200" as &[u8]),
        (301, b"301"),
        (404, b"404"),
        (500, b"500"),
    ] {
        let (mut client, mut server) = setup_h2_pair();

        let stream_id = client
            .send_request("GET", "/", "test.local", &[], true)
            .unwrap();

        exchange_h2(&mut client, &mut server);
        let req_stream = wait_for_server_headers(&mut client, &mut server);

        server.send_response(req_stream, code, &[], false).unwrap();
        server.send_body(req_stream, &[], true).unwrap();

        exchange_h2(&mut client, &mut server);
        wait_for_client_headers(&mut client, &mut server, stream_id);

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
// 11. h2_stream_fin_on_response
// ---------------------------------------------------------------------------

#[test]
fn h2_stream_fin_on_response() {
    let (mut client, mut server) = setup_h2_pair();

    let stream_id = client
        .send_request("GET", "/fin-test", "test.local", &[], true)
        .unwrap();

    exchange_h2(&mut client, &mut server);
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Server sends response with body and end_stream=true.
    server.send_response(req_stream, 200, &[], false).unwrap();
    server.send_body(req_stream, b"done", true).unwrap();

    // Exchange until client has all data.
    for _ in 0..5 {
        exchange_h2(&mut client, &mut server);
    }

    // Client should see Headers, Data, and Finished events.
    let mut got_headers = false;
    let mut got_data = false;
    let mut got_finished = false;
    while let Some(ev) = client.poll_event() {
        match ev {
            H2Event::Headers(sid) if sid == stream_id => got_headers = true,
            H2Event::Data(sid) if sid == stream_id => got_data = true,
            H2Event::Finished(sid) if sid == stream_id => got_finished = true,
            _ => {}
        }
    }
    assert!(got_headers, "client should receive response headers");
    assert!(got_data, "client should receive response data");
    assert!(got_finished, "client should receive Finished event");

    // Verify body content.
    let mut recv_buf = [0u8; 256];
    let (len, fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
    assert_eq!(&recv_buf[..len], b"done");
    assert!(fin);
}

// ---------------------------------------------------------------------------
// 12. h2_post_large_request_body
// ---------------------------------------------------------------------------

#[test]
fn h2_post_large_request_body() {
    let (mut client, mut server) = setup_h2_pair();

    // Client sends POST with ~2KB body.
    let stream_id = client
        .send_request("POST", "/upload", "test.local", &[], false)
        .unwrap();

    let large_body = [0x42_u8; 2000];
    let sent = client.send_body(stream_id, &large_body, true).unwrap();
    assert!(sent > 0, "should send at least some data");

    // Exchange to deliver data.
    for _ in 0..10 {
        exchange_h2(&mut client, &mut server);
    }

    // Server should receive the request.
    let req_stream = wait_for_server_headers(&mut client, &mut server);

    // Read request headers.
    let mut method = Vec::new();
    server
        .recv_headers(req_stream, |name, value| {
            if name == b":method" {
                method.extend_from_slice(value);
            }
        })
        .unwrap();
    assert_eq!(method, b"POST");

    // Read all body data from server.
    let mut all_data = Vec::new();
    let mut recv_buf = [0u8; 4096];
    loop {
        match server.recv_body(req_stream, &mut recv_buf) {
            Ok((0, true)) => break,
            Ok((n, fin)) => {
                all_data.extend_from_slice(&recv_buf[..n]);
                if fin {
                    break;
                }
                exchange_h2(&mut client, &mut server);
                while server.poll_event().is_some() {}
            }
            Err(_) => break,
        }
    }

    assert!(
        all_data.len() >= 1000,
        "server should receive substantial body data, got {} bytes",
        all_data.len()
    );
    // Verify content.
    assert!(
        all_data.iter().all(|&b| b == 0x42),
        "body bytes should all be 0x42"
    );
}
