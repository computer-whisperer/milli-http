//! Interop bench: a mainstream HTTP/2 client (hyper + rustls) against
//! [`ServerRunner`] over real TCP sockets.
//!
//! The in-crate integration tests pair this library's client with its own
//! server, which cannot catch asymmetric spec assumptions — both ends share
//! them. This bench drives the server with hyper's h2 stack over a rustls
//! TLS 1.3 session, the same client family as browsers and mobile apps, and
//! it found two real bugs the symmetric tests could not:
//!
//! - stream-table capacity: SETTINGS advertised more concurrency than the
//!   table held, and a refused stream still emitted Headers events
//!   (`stream_capacity_request_burst_then_put`);
//! - HPACK: hyper legally indexes against the RFC-initial 4096-byte dynamic
//!   table whenever its first requests race the SETTINGS exchange
//!   (`fresh_connections_settings_race`).
//!
//! Server reads are clamped to seeded-random sizes to sweep TCP segmentation
//! patterns (embedded targets feed the stack in small, varying chunks).

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use milli_http::crypto::ed25519::{build_ed25519_cert_der, ed25519_public_key_from_seed};
use milli_http::crypto::rustcrypto::Aes128GcmProvider;
use milli_http::http::server_conn::HttpEvent;
use milli_http::server::runner::ServerRunner;
use milli_http::server::{ConnId, ServerConfig, ServerEvent, ServerManager};
use milli_http::tls::TransportParams;
use milli_http::tls::handshake::ServerTlsConfig;
use milli_http::transport::{NoUdp, Rng as MilliRng, TcpAccept, TcpStream as MilliTcpStream};
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng};

const TLS_BUF: usize = 18432;

// ---------------------------------------------------------------------------
// std transports for ServerRunner
// ---------------------------------------------------------------------------

struct StdListener {
    inner: std::net::TcpListener,
    seed: u64,
    next_conn: u64,
}

struct StdStream {
    inner: std::net::TcpStream,
    /// Seeded RNG clamping read sizes (segmentation sweep).
    rng: StdRng,
}

impl MilliTcpStream for StdStream {
    type Error = std::io::Error;

    fn poll_read(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        // Most reads are clamped to a random size; some pass through
        // unclamped (coalesced delivery).
        let max = if self.rng.random_bool(0.3) {
            buf.len()
        } else {
            self.rng.random_range(1..=buf.len().min(1500))
        };
        match self.inner.read(&mut buf[..max]) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        match self.inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl TcpAccept for StdListener {
    type Stream = StdStream;
    type Error = std::io::Error;

    fn poll_accept(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Self::Stream, Self::Error>> {
        match self.inner.accept() {
            Ok((s, _addr)) => {
                s.set_nonblocking(true).unwrap();
                s.set_nodelay(true).unwrap();
                self.next_conn += 1;
                Poll::Ready(Ok(StdStream {
                    inner: s,
                    rng: StdRng::seed_from_u64(self.seed ^ self.next_conn),
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

struct StdMilliRng(StdRng);
impl MilliRng for StdMilliRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

// ---------------------------------------------------------------------------
// Server: an event loop in the shape embedded consumers use — recv_headers at
// Headers, drain body, route, respond; one pending slot for parked bodies.
// ---------------------------------------------------------------------------

type Mgr = ServerManager<Aes128GcmProvider, SocketAddr, TLS_BUF, 16, 16, 2, 256, 16>;
type Runner<'a> = ServerRunner<
    'a,
    Aes128GcmProvider,
    StdListener,
    NoUdp<SocketAddr>,
    StdMilliRng,
    SocketAddr,
    TLS_BUF,
    4096,
    16,
    16,
    2,
    256,
    16,
>;

struct PendingRequest {
    conn: ConnId,
    stream_id: u64,
    method: Vec<u8>,
    path: Vec<u8>,
    body: Vec<u8>,
}

/// Routes: any GET under /res/ → 200 with a small body; PUT /res/value with
/// the 5-byte test body → 204. Everything unexpected → 400/404/405, which the
/// client side asserts against.
fn route(method: &[u8], path: &[u8], body: &[u8]) -> (u16, Vec<u8>) {
    match method {
        b"GET" if path.starts_with(b"/res/") => (200, b"ok".to_vec()),
        b"PUT" if path == b"/res/value" => {
            if body == b"hello" {
                (204, Vec::new())
            } else {
                (400, b"bad body".to_vec())
            }
        }
        b"GET" | b"PUT" | b"POST" => (404, b"not found".to_vec()),
        _ => (405, b"method not allowed".to_vec()),
    }
}

fn drain_body(manager: &mut Mgr, conn: ConnId, stream_id: u64, body: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 1024];
    loop {
        match manager.recv_body(conn, stream_id, &mut buf) {
            Ok((0, fin)) => return fin,
            Ok((n, fin)) => {
                body.extend_from_slice(&buf[..n]);
                if fin {
                    return true;
                }
            }
            Err(milli_http::error::Error::WouldBlock) => return false,
            Err(_) => return true,
        }
    }
}

fn send_response(manager: &mut Mgr, conn: ConnId, stream_id: u64, status: u16, body: &[u8]) {
    let cl = body.len().to_string();
    let headers: [(&[u8], &[u8]); 2] = [
        (b"content-type", b"text/plain"),
        (b"content-length", cl.as_bytes()),
    ];
    manager
        .send_response(conn, stream_id, status, &headers, body.is_empty())
        .expect("send_response failed");
    if !body.is_empty() {
        let sent = manager
            .send_body(conn, stream_id, body, true)
            .expect("send_body failed");
        assert_eq!(sent, body.len(), "partial response body send");
    }
}

fn server_thread(listener: std::net::TcpListener, seed: u64, stop: Arc<AtomicBool>) {
    let cert_seed: [u8; 32] = [0x42u8; 32];
    let pk = ed25519_public_key_from_seed(&cert_seed);
    let mut cert_buf = [0u8; 512];
    let cert_len = build_ed25519_cert_der(&pk, &mut cert_buf).expect("cert");
    let cert_der: &'static [u8] = Box::leak(cert_buf[..cert_len].to_vec().into_boxed_slice());
    let private_key_der: &'static [u8] = Box::leak(Box::new(cert_seed));

    let tls_config = ServerTlsConfig {
        cert_der,
        private_key_der,
        alpn_protocols: &[b"h2"],
        transport_params: TransportParams::default_params(),
    };
    let server_config = ServerConfig {
        max_tcp_conns: 3,
        max_events: 8,
        handshake_timeout_us: 10_000_000,
        ..ServerConfig::default()
    };
    let manager: Mgr = ServerManager::new(Aes128GcmProvider, tls_config, server_config);

    listener.set_nonblocking(true).unwrap();
    let mut tls_listener = StdListener {
        inner: listener,
        seed,
        next_conn: 0,
    };
    let mut rng = StdMilliRng(StdRng::seed_from_u64(seed));
    // The h3 feature changes ServerRunner::new's shape (UDP socket + QUIC
    // handshake pool); this bench is TCP-only either way.
    #[cfg(feature = "h3")]
    let mut udp = NoUdp::<SocketAddr>::new();
    #[cfg(feature = "h3")]
    let mut pool: milli_http::connection::HandshakePool<Aes128GcmProvider, 1, 4096> =
        milli_http::connection::HandshakePool::new();
    #[cfg(feature = "h3")]
    let mut runner: Runner<'_> = ServerRunner::new(
        manager,
        Some(&mut tls_listener),
        None,
        &mut udp,
        &mut rng,
        &mut pool,
    );
    #[cfg(not(feature = "h3"))]
    let mut runner: Runner<'_> =
        ServerRunner::new(manager, Some(&mut tls_listener), None, &mut rng);

    let mut pending: Option<PendingRequest> = None;
    let start = Instant::now();
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(&waker);

    while !stop.load(Ordering::Relaxed) {
        let now = start.elapsed().as_micros() as u64;
        let event = match runner.poll_event(&mut cx, now) {
            Poll::Ready(ev) => ev,
            Poll::Pending => {
                std::thread::sleep(std::time::Duration::from_micros(200));
                continue;
            }
        };
        let manager = &mut runner.manager;

        match event {
            ServerEvent::Http {
                conn,
                event: HttpEvent::Headers(stream_id),
            } => {
                let mut method = Vec::new();
                let mut path = Vec::new();
                manager
                    .recv_headers(conn, stream_id, &mut |name, value| match name {
                        b":method" => method = value.to_vec(),
                        b":path" => path = value.to_vec(),
                        _ => {}
                    })
                    .unwrap_or_else(|e| panic!("recv_headers failed on stream {stream_id}: {e:?}"));
                assert!(
                    !method.is_empty(),
                    "stream {stream_id}: headers decoded but :method missing"
                );

                if method == b"GET" {
                    let (status, body) = route(&method, &path, &[]);
                    send_response(manager, conn, stream_id, status, &body);
                } else {
                    let mut body = Vec::new();
                    let fin = drain_body(manager, conn, stream_id, &mut body);
                    if fin {
                        let (status, resp) = route(&method, &path, &body);
                        send_response(manager, conn, stream_id, status, &resp);
                    } else {
                        assert!(pending.is_none(), "second concurrent bodied request");
                        pending = Some(PendingRequest {
                            conn,
                            stream_id,
                            method,
                            path,
                            body,
                        });
                    }
                }
            }
            ServerEvent::Http {
                conn,
                event: HttpEvent::Data(stream_id),
            } => {
                if let Some(req) = pending
                    .as_mut()
                    .filter(|r| r.conn == conn && r.stream_id == stream_id)
                {
                    let fin = {
                        let mut body = std::mem::take(&mut req.body);
                        let fin = drain_body(manager, conn, stream_id, &mut body);
                        req.body = body;
                        fin
                    };
                    if fin {
                        let req = pending.take().unwrap();
                        let (status, resp) = route(&req.method, &req.path, &req.body);
                        send_response(manager, conn, stream_id, status, &resp);
                    }
                }
            }
            ServerEvent::Http {
                conn,
                event: HttpEvent::Finished(stream_id),
            } => {
                if pending
                    .as_ref()
                    .is_some_and(|r| r.conn == conn && r.stream_id == stream_id)
                {
                    let mut req = pending.take().unwrap();
                    drain_body(manager, conn, stream_id, &mut req.body);
                    let (status, resp) = route(&req.method, &req.path, &req.body);
                    send_response(manager, conn, stream_id, status, &resp);
                }
            }
            ServerEvent::Closed(conn) => {
                if pending.as_ref().is_some_and(|r| r.conn == conn) {
                    pending = None;
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Client: hyper h2 over rustls, accept-any-cert
// ---------------------------------------------------------------------------

mod client {
    use std::sync::Arc;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::Request;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_rustls::TlsConnector;

    #[derive(Debug)]
    struct AcceptAnyServerCert {
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    pub fn tls_connector() -> TlsConnector {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        TlsConnector::from(Arc::new(cfg))
    }

    pub type SendReq =
        http2::SendRequest<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>>;

    pub async fn connect(tls: &TlsConnector, port: u16) -> SendReq {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        tcp.set_nodelay(true).unwrap();
        let name = rustls::pki_types::ServerName::from(std::net::IpAddr::from([127, 0, 0, 1]));
        let tls_stream = tls.connect(name, tcp).await.expect("tls connect");
        let (send, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send
    }

    pub async fn request(
        send: &mut SendReq,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        port: u16,
    ) -> Result<u16, String> {
        let builder = Request::builder()
            .method(method)
            .uri(format!("https://127.0.0.1:{port}{path}"));
        let body = match body {
            Some(b) => BodyExt::boxed(Full::new(Bytes::from(b))),
            None => BodyExt::boxed(Empty::new()),
        };
        let req = builder.body(body).map_err(|e| e.to_string())?;
        send.ready().await.map_err(|e| format!("ready: {e}"))?;
        let resp = send
            .send_request(req)
            .await
            .map_err(|e| format!("send: {e}"))?;
        let status = resp.status().as_u16();
        resp.into_body()
            .collect()
            .await
            .map_err(|e| format!("body: {e}"))?;
        Ok(status)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const GET_PATHS: [&str; 8] = [
    "/res/a", "/res/b", "/res/c", "/res/d", "/res/e", "/res/f", "/res/g", "/res/h",
];

struct TestServer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(seed: u64) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = stop.clone();
            std::thread::spawn(move || server_thread(listener, seed, stop))
        };
        Self {
            port,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // A panic on the server thread is a test failure, not a teardown
        // footnote — propagate it unless the test is already panicking.
        if let Err(e) = self.handle.take().unwrap().join() {
            if !std::thread::panicking() {
                std::panic::resume_unwind(e);
            }
        }
    }
}

/// The failure shape from the field: a burst of concurrent GETs (filling the
/// stream table), then a PUT on the same connection — the (MAX_STREAMS+1)-th
/// stream overall. Repeated so closed-but-unswept streams from earlier
/// batches stress capacity accounting across batches.
#[test]
fn stream_capacity_request_burst_then_put() {
    for seed in [1u64, 7, 42] {
        let server = TestServer::start(seed);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let tls = client::tls_connector();
            for iter in 0..5 {
                let mut send = client::connect(&tls, server.port).await;
                let gets = futures::future::join_all(GET_PATHS.iter().map(|p| {
                    let mut s = send.clone();
                    let port = server.port;
                    async move { client::request(&mut s, "GET", p, None, port).await }
                }))
                .await;
                for (p, r) in GET_PATHS.iter().zip(&gets) {
                    assert_eq!(*r, Ok(200), "seed {seed} iter {iter}: GET {p}");
                }
                let put = client::request(
                    &mut send,
                    "PUT",
                    "/res/value",
                    Some(b"hello".to_vec()),
                    server.port,
                )
                .await;
                assert_eq!(put, Ok(204), "seed {seed} iter {iter}: PUT");
                let gets = futures::future::join_all(GET_PATHS.iter().map(|p| {
                    let mut s = send.clone();
                    let port = server.port;
                    async move { client::request(&mut s, "GET", p, None, port).await }
                }))
                .await;
                for (p, r) in GET_PATHS.iter().zip(&gets) {
                    assert_eq!(*r, Ok(200), "seed {seed} iter {iter}: GET(after) {p}");
                }
            }
        });
    }
}

/// Fresh connection per request: hyper's first header blocks may be encoded
/// before it has processed the server's SETTINGS, legally indexing against
/// the RFC-initial 4096-byte HPACK dynamic table (RFC 7541 §4.2). The server
/// must decode those blocks.
#[test]
fn fresh_connections_settings_race() {
    let server = TestServer::start(3);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let tls = client::tls_connector();
        for iter in 0..20 {
            let mut send = client::connect(&tls, server.port).await;
            let put = client::request(
                &mut send,
                "PUT",
                "/res/value",
                Some(b"hello".to_vec()),
                server.port,
            )
            .await;
            assert_eq!(put, Ok(204), "iter {iter}: fresh-conn PUT");
        }
    });
}
