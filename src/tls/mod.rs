//! TLS 1.3 handshake engine for QUIC.
//!
//! QUIC uses TLS 1.3 differently from TCP:
//! - No TLS record layer — QUIC carries raw handshake messages in CRYPTO frames
//! - No TLS content encryption — QUIC does its own packet protection
//! - QUIC transport parameters are exchanged as a TLS extension
//!
//! The TLS engine produces/consumes handshake message bytes and derives
//! traffic secrets for QUIC packet protection.

pub mod alert;
pub mod extensions;
pub mod handshake;
pub mod key_schedule_tls;
pub mod messages;
pub mod transcript;
pub mod transport_params;

pub use alert::AlertDescription;
pub use handshake::{ServerTlsConfig, TlsEngine};
pub use messages::CipherSuite;
pub use transport_params::TransportParams;

use crate::crypto::Level;
use zeroize::Zeroize;

/// Keys derived during the TLS handshake, to be consumed by QUIC.
pub struct DerivedKeys {
    /// The encryption level these keys apply to.
    pub level: Level,
    /// Send traffic secret — up to 48 bytes (32 for SHA-256, 48 for SHA-384).
    pub send_secret: [u8; 48],
    /// Receive traffic secret — up to 48 bytes (32 for SHA-256, 48 for SHA-384).
    pub recv_secret: [u8; 48],
    /// Actual length of the secrets in bytes (32 for SHA-256, 48 for SHA-384).
    pub secret_len: usize,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.send_secret.zeroize();
        self.recv_secret.zeroize();
    }
}

/// The TLS session interface used by QUIC.
pub trait TlsSession {
    type Error;

    /// Process incoming TLS handshake bytes from a CRYPTO frame.
    fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), Self::Error>;

    /// Write outgoing TLS handshake bytes into `buf`.
    /// Returns `(bytes_written, target_level)`.
    /// Returns `(0, _)` if nothing to send.
    fn write_handshake(&mut self, buf: &mut [u8]) -> Result<(usize, Level), Self::Error>;

    /// Check if new keys are available after processing.
    fn derived_keys(&mut self) -> Option<DerivedKeys>;

    /// Is the handshake complete?
    fn is_complete(&self) -> bool;

    /// Get negotiated ALPN (e.g., b"h3").
    fn alpn(&self) -> Option<&[u8]>;

    /// Get peer's QUIC transport parameters.
    fn peer_transport_params(&self) -> Option<&TransportParams>;

    /// Set our QUIC transport parameters.
    fn set_transport_params(&mut self, params: &TransportParams);
}
