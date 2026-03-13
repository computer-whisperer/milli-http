//! Shared HTTP types used across HTTP/1.1, HTTP/2, and HTTP/3.

pub mod header;
pub mod method;
pub mod server_conn;
pub mod status;

pub use header::Header;
pub use method::Method;
pub use status::StatusCode;

/// Timeout configuration for HTTP connections.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    /// Close if no data received for N microseconds.
    pub idle_timeout_us: Option<u64>,
    /// Close if headers not received within N microseconds of connection/request start.
    pub header_timeout_us: Option<u64>,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            idle_timeout_us: None,
            header_timeout_us: None,
        }
    }
}
