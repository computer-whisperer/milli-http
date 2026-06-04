//! A `no_std` HTTP/1.1, HTTP/2, and HTTP/3 stack for embedded systems,
//! including an integrated QUIC transport and TLS 1.3 implementation.
//!
//! Every protocol layer is a sans-IO state machine driven by the same three
//! calls — `feed_data` (bytes in), `poll_output` (bytes out), and
//! `poll_event` (protocol events) — so the I/O loop, executor, and platform
//! are entirely yours. Platform integration is a handful of small traits:
//! [`UdpSocket`], [`TcpStream`], [`Clock`], and [`Rng`].
//!
//! The core requires no allocator; the `alloc` feature switches internal
//! buffers to heap-backed storage for a much lower idle-memory footprint.
//! Cryptography is pluggable via [`crypto::CryptoProvider`], with default
//! implementations built on RustCrypto.
//!
//! Protocol layers are selected by feature flags: `http1`, `h2`, `h3`,
//! `quic`, `tcp-tls` (TLS 1.3 record layer for HTTPS/1.1 and HTTP/2), and
//! `server` (multi-protocol connection manager). See the README for the full
//! matrix.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod buf;

pub mod error;
pub mod frame;
pub mod varint;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "http")]
pub use http::server_conn::{HttpEvent, HttpServerConn};

#[cfg(any(feature = "h3", feature = "h2"))]
pub mod hpack;

#[cfg(feature = "h2")]
pub mod h2;

#[cfg(feature = "http1")]
pub mod http1;

#[cfg(feature = "tcp-tls")]
pub mod tcp_tls;

#[cfg(all(feature = "tcp-tls", feature = "http1"))]
pub mod https1;

#[cfg(all(feature = "tcp-tls", feature = "h2"))]
pub mod h2_tls;

#[cfg(feature = "h3")]
pub mod h3;

#[cfg(feature = "discovery")]
pub mod discovery;

#[cfg(feature = "server")]
pub mod server;

pub mod transport;
pub use transport::{Address, Clock, Instant, Rng, TcpAccept, TcpStream, UdpSocket};

pub mod crypto;
pub mod packet;
pub mod tls;

pub mod connection;
pub use connection::{
    Connection, ConnectionConfig, ConnectionId, ConnectionState, DefaultConfig, Event,
    HandshakeContext, HandshakePool, HandshakePoolAccess, Transmit,
    io::{QuicStreamIo, QuicStreamIoBufs},
};
pub use tls::handshake::Role;
