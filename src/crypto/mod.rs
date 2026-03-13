//! Cryptographic traits and implementations for QUIC packet protection.
//!
//! QUIC needs several crypto primitives: AEAD for packet encryption,
//! HKDF for key derivation, and header protection. The [`CryptoProvider`]
//! trait bundles these together, allowing pluggable implementations
//! (software via RustCrypto, or hardware-accelerated).

mod aead;
pub mod ecdsa_p256;
pub mod ed25519;
mod header_protection;
mod hkdf;

#[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
pub mod rustcrypto;

pub mod key_schedule;

pub use aead::Aead;
pub use header_protection::HeaderProtection;
pub use hkdf::Hkdf;

use crate::error::Error;
use zeroize::Zeroize;

/// Encryption level — determines which keys to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Initial,
    Handshake,
    /// 1-RTT application data.
    Application,
}

/// Bundle of cryptographic primitives needed by QUIC.
///
/// Implementations provide AEAD, HKDF, and header protection
/// for a specific cipher suite.
pub trait CryptoProvider {
    type Aead: Aead;
    type Hkdf: Hkdf;
    type HeaderProtection: HeaderProtection;

    /// Create an AEAD instance from a key.
    fn aead(&self, key: &[u8]) -> Result<Self::Aead, Error>;

    /// Get an HKDF instance for key derivation.
    fn hkdf(&self) -> Self::Hkdf;

    /// Create a header protection cipher from a key.
    fn header_protection(&self, key: &[u8]) -> Result<Self::HeaderProtection, Error>;
}

/// Keys for one direction (send or recv) at one encryption level.
pub struct DirectionalKeys<A: Aead, H: HeaderProtection> {
    pub aead: A,
    pub header_protection: H,
    /// Nonce base — XORed with packet number to form the per-packet nonce.
    pub iv: [u8; 12],
}

impl<A: Aead, H: HeaderProtection> Drop for DirectionalKeys<A, H> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl<A: Aead, H: HeaderProtection> DirectionalKeys<A, H> {
    /// Compute the AEAD nonce for a given packet number.
    ///
    /// The nonce is formed by XORing the IV with the packet number
    /// (left-padded to 12 bytes).
    pub fn nonce(&self, packet_number: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let pn_bytes = packet_number.to_be_bytes();
        // XOR packet number into the last 8 bytes of the IV
        for i in 0..8 {
            nonce[12 - 8 + i] ^= pn_bytes[i];
        }
        nonce
    }
}
