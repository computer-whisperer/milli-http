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
