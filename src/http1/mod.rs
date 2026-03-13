//! HTTP/1.1 protocol implementation.
//!
//! A pure-codec HTTP/1.1 stack following the same calling convention as
//! HTTP/2 and QUIC: `feed_data()` → `poll_output()` → `poll_event()`.

pub mod client;
pub mod connection;
pub mod io;
pub mod parse;
pub mod server;

pub use client::Http1Client;
pub use connection::{Http1Connection, Http1Event};
pub use io::{Http1Io, Http1IoBufs};
pub use server::Http1Server;
