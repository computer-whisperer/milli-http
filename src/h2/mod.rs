//! HTTP/2 protocol implementation (RFC 9113).
//!
//! A pure-codec HTTP/2 stack following the same calling convention as the
//! existing QUIC Connection: `feed_data()` → `poll_output()` → `poll_event()`.

pub mod client;
pub mod connection;
pub mod flow_control;
pub mod frame;
pub mod io;
pub mod server;
pub mod stream;

pub use client::H2Client;
pub use connection::{H2Connection, H2Event, H2Settings};
pub use frame::{H2Frame, H2FrameHeader, H2Priority};
pub use io::{H2Io, H2IoBufs};
pub use server::H2Server;
