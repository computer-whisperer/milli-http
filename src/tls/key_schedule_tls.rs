//! TLS 1.3 key schedule (RFC 8446 section 7.1).
//!
//! The key schedule derives handshake and application traffic secrets
//! from the ECDHE shared secret and transcript hashes.
//!
//! ```text
//!             0
//!             |
//!             v
//!   PSK ->  HKDF-Extract = Early Secret
//!             |
//!             v
//!   ECDHE -> HKDF-Extract = Handshake Secret
//!             |
//!             +-> Derive-Secret(., "c hs traffic", CH..SH)
//!             +-> Derive-Secret(., "s hs traffic", CH..SH)
//!             |
//!             v
//!     0  ->  HKDF-Extract = Master Secret
//!             |
//!             +-> Derive-Secret(., "c ap traffic", CH..SF)
//!             +-> Derive-Secret(., "s ap traffic", CH..SF)
//! ```

use crate::crypto::Hkdf;
use crate::crypto::key_schedule::hkdf_expand_label;
use crate::error::Error;
use zeroize::Zeroize;

/// TLS 1.3 key schedule state.
pub struct TlsKeySchedule {
    early_secret: [u8; 32],
    handshake_secret: [u8; 32],
    master_secret: [u8; 32],
}

impl Drop for TlsKeySchedule {
    fn drop(&mut self) {
        self.early_secret.zeroize();
        self.handshake_secret.zeroize();
        self.master_secret.zeroize();
    }
}

impl TlsKeySchedule {
    /// Initialize the key schedule with no PSK (0-RTT not supported).
    ///
    /// Computes: Early Secret = HKDF-Extract(salt=0, ikm=0)
    pub fn new<H: Hkdf>(hkdf: &H) -> Self {
        let zero_ikm = [0u8; 32];
        let zero_salt = [0u8; 32];
        let mut early_secret = [0u8; 32];
        hkdf.extract(&zero_salt, &zero_ikm, &mut early_secret);

        Self {
            early_secret,
            handshake_secret: [0u8; 32],
            master_secret: [0u8; 32],
        }
    }

    /// Derive the handshake secret from the ECDHE shared secret.
    ///
    /// 1. Derive-Secret(Early Secret, "derived", "") -> salt
    /// 2. HKDF-Extract(salt, shared_secret) -> Handshake Secret
    pub fn derive_handshake_secret<H: Hkdf>(
        &mut self,
        hkdf: &H,
        shared_secret: &[u8; 32],
    ) -> Result<(), Error> {
        // Derive-Secret(Early Secret, "derived", "")
        // = HKDF-Expand-Label(Early Secret, "derived", Hash(""), 32)
        let empty_hash = empty_transcript_hash();
        let mut salt = [0u8; 32];
        hkdf_expand_label(hkdf, &self.early_secret, b"derived", &empty_hash, &mut salt)?;

        hkdf.extract(&salt, shared_secret, &mut self.handshake_secret);
        Ok(())
    }

    /// Derive client and server handshake traffic secrets.
    ///
    /// - client_secret = Derive-Secret(Handshake Secret, "c hs traffic", transcript_hash)
    /// - server_secret = Derive-Secret(Handshake Secret, "s hs traffic", transcript_hash)
    ///
    /// `transcript_hash` is the hash of ClientHello..ServerHello.
    pub fn derive_handshake_traffic_secrets<H: Hkdf>(
        &self,
        hkdf: &H,
        transcript_hash: &[u8; 32],
        client_secret: &mut [u8; 32],
        server_secret: &mut [u8; 32],
    ) -> Result<(), Error> {
        hkdf_expand_label(
            hkdf,
            &self.handshake_secret,
            b"c hs traffic",
            transcript_hash,
            client_secret,
        )?;
        hkdf_expand_label(
            hkdf,
            &self.handshake_secret,
            b"s hs traffic",
            transcript_hash,
            server_secret,
        )?;
        Ok(())
    }

    /// Compute the master secret.
    ///
    /// 1. Derive-Secret(Handshake Secret, "derived", "") -> salt
    /// 2. HKDF-Extract(salt, 0) -> Master Secret
    pub fn derive_master_secret<H: Hkdf>(&mut self, hkdf: &H) -> Result<(), Error> {
        let empty_hash = empty_transcript_hash();
        let mut salt = [0u8; 32];
        hkdf_expand_label(
            hkdf,
            &self.handshake_secret,
            b"derived",
            &empty_hash,
            &mut salt,
        )?;

        let zero_ikm = [0u8; 32];
        hkdf.extract(&salt, &zero_ikm, &mut self.master_secret);
        Ok(())
    }

    /// Derive client and server application traffic secrets.
    ///
    /// - client_secret = Derive-Secret(Master Secret, "c ap traffic", transcript_hash)
    /// - server_secret = Derive-Secret(Master Secret, "s ap traffic", transcript_hash)
    ///
    /// `transcript_hash` is the hash of ClientHello..server Finished.
    pub fn derive_app_traffic_secrets<H: Hkdf>(
        &self,
        hkdf: &H,
        transcript_hash: &[u8; 32],
        client_secret: &mut [u8; 32],
        server_secret: &mut [u8; 32],
    ) -> Result<(), Error> {
        hkdf_expand_label(
            hkdf,
            &self.master_secret,
            b"c ap traffic",
            transcript_hash,
            client_secret,
        )?;
        hkdf_expand_label(
            hkdf,
            &self.master_secret,
            b"s ap traffic",
            transcript_hash,
            server_secret,
        )?;
        Ok(())
    }

    /// Derive the Finished key from a handshake traffic secret.
    ///
    /// finished_key = HKDF-Expand-Label(handshake_secret, "finished", "", Hash.length)
    pub fn derive_finished_key<H: Hkdf>(
        hkdf: &H,
        base_key: &[u8; 32],
        finished_key: &mut [u8; 32],
    ) -> Result<(), Error> {
        hkdf_expand_label(hkdf, base_key, b"finished", &[], finished_key)
    }
}

/// Compute SHA-256("") — the hash of an empty transcript.
///
/// This is used in Derive-Secret(secret, "derived", "").
fn empty_transcript_hash() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let h = Sha256::new();
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute HMAC-SHA256(key, message) for Finished verification.
///
/// The Finished verify_data = HMAC(finished_key, transcript_hash).
pub fn compute_finished_verify_data<H: Hkdf>(
    hkdf: &H,
    finished_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32], Error> {
    // HMAC(key, msg) can be computed using HKDF-Extract(key=msg, salt=key)
    // since HKDF-Extract is just HMAC.
    // Actually: HKDF-Extract(salt, ikm) = HMAC(salt, ikm)
    // We want HMAC(finished_key, transcript_hash)
    // So: HKDF-Extract(salt=finished_key, ikm=transcript_hash)
    let mut verify_data = [0u8; 32];
    hkdf.extract(finished_key, transcript_hash, &mut verify_data);
    Ok(verify_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use the real HKDF implementation for tests
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    use crate::crypto::rustcrypto::HkdfSha256;

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn early_secret_no_psk() {
        let hkdf = HkdfSha256;
        let ks = TlsKeySchedule::new(&hkdf);
        // The early secret should be deterministic (same every time)
        let ks2 = TlsKeySchedule::new(&hkdf);
        assert_eq!(ks.early_secret, ks2.early_secret);
        // It should not be all zeros (HKDF-Extract should produce something)
        assert_ne!(ks.early_secret, [0u8; 32]);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn handshake_and_traffic_secrets() {
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);

        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();
        assert_ne!(ks.handshake_secret, [0u8; 32]);

        let transcript_hash = [0xAA; 32];
        let mut client_hs = [0u8; 32];
        let mut server_hs = [0u8; 32];
        ks.derive_handshake_traffic_secrets(&hkdf, &transcript_hash, &mut client_hs, &mut server_hs)
            .unwrap();

        // Client and server secrets should be different
        assert_ne!(client_hs, server_hs);
        assert_ne!(client_hs, [0u8; 32]);
        assert_ne!(server_hs, [0u8; 32]);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn master_and_app_secrets() {
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);

        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();
        ks.derive_master_secret(&hkdf).unwrap();
        assert_ne!(ks.master_secret, [0u8; 32]);

        let transcript_hash = [0xBB; 32];
        let mut client_app = [0u8; 32];
        let mut server_app = [0u8; 32];
        ks.derive_app_traffic_secrets(&hkdf, &transcript_hash, &mut client_app, &mut server_app)
            .unwrap();

        assert_ne!(client_app, server_app);
        assert_ne!(client_app, [0u8; 32]);
        assert_ne!(server_app, [0u8; 32]);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn finished_key_and_verify_data() {
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);

        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();

        let transcript_hash = [0xAA; 32];
        let mut client_hs = [0u8; 32];
        let mut server_hs = [0u8; 32];
        ks.derive_handshake_traffic_secrets(&hkdf, &transcript_hash, &mut client_hs, &mut server_hs)
            .unwrap();

        // Derive finished key
        let mut finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(&hkdf, &client_hs, &mut finished_key).unwrap();
        assert_ne!(finished_key, [0u8; 32]);

        // Compute verify data
        let verify = compute_finished_verify_data(&hkdf, &finished_key, &transcript_hash).unwrap();
        assert_ne!(verify, [0u8; 32]);

        // Same inputs should produce same output
        let verify2 = compute_finished_verify_data(&hkdf, &finished_key, &transcript_hash).unwrap();
        assert_eq!(verify, verify2);

        // Different transcript should produce different verify data
        let other_hash = [0xCC; 32];
        let verify3 = compute_finished_verify_data(&hkdf, &finished_key, &other_hash).unwrap();
        assert_ne!(verify, verify3);
    }

    #[test]
    fn empty_transcript_hash_is_sha256_empty() {
        use sha2::{Digest, Sha256};
        let expected: [u8; 32] = {
            let h = Sha256::new();
            let r = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        };
        assert_eq!(empty_transcript_hash(), expected);
    }

    /// RFC 8448 test vector: TLS 1.3 key schedule with known inputs.
    /// We test the early secret derivation against the RFC 8448 "Simple 1-RTT Handshake" trace.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_early_secret() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;
        let ks = TlsKeySchedule::new(&hkdf);
        // RFC 8448 section 3: Early Secret when PSK = 0
        // HKDF-Extract(salt=0x00*32, ikm=0x00*32)
        assert_eq!(
            ks.early_secret,
            hex!("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        );
    }

    /// Test that Derive-Secret(early_secret, "derived", "") matches RFC 8448.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_derived_from_early() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;
        let ks = TlsKeySchedule::new(&hkdf);

        let empty_hash = empty_transcript_hash();
        let mut salt = [0u8; 32];
        hkdf_expand_label(&hkdf, &ks.early_secret, b"derived", &empty_hash, &mut salt).unwrap();

        assert_eq!(
            salt,
            hex!("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        );
    }

    /// RFC 8448 §3: Handshake Secret from ECDHE shared secret.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_handshake_secret() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);
        let shared_secret =
            hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();
        assert_eq!(
            ks.handshake_secret,
            hex!("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        );
    }

    /// RFC 8448 §3: Client and server handshake traffic secrets.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_handshake_traffic_secrets() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);
        let shared_secret =
            hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();

        let transcript_hash =
            hex!("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        ks.derive_handshake_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut client_secret,
            &mut server_secret,
        )
        .unwrap();

        assert_eq!(
            client_secret,
            hex!("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            server_secret,
            hex!("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
    }

    /// RFC 8448 §3: Master Secret derivation.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_master_secret() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);
        let shared_secret =
            hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();
        ks.derive_master_secret(&hkdf).unwrap();
        assert_eq!(
            ks.master_secret,
            hex!("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );
    }

    /// RFC 8448 §3: Client and server application traffic secrets.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_app_traffic_secrets() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;
        let mut ks = TlsKeySchedule::new(&hkdf);
        let shared_secret =
            hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        ks.derive_handshake_secret(&hkdf, &shared_secret).unwrap();
        ks.derive_master_secret(&hkdf).unwrap();

        // Transcript-Hash(CH..server Finished) from RFC 8448 §3
        let transcript_hash =
            hex!("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        ks.derive_app_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut client_secret,
            &mut server_secret,
        )
        .unwrap();

        assert_eq!(
            client_secret,
            hex!("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );
        assert_eq!(
            server_secret,
            hex!("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        );
    }

    /// RFC 8448 §3: Server finished key derivation.
    /// Validates HKDF-Expand-Label(server_hs_traffic, "finished", "", 32).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_server_finished() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;

        let server_hs_traffic =
            hex!("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        let mut finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(&hkdf, &server_hs_traffic, &mut finished_key)
            .unwrap();
        assert_eq!(
            finished_key,
            hex!("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")
        );
    }

    /// RFC 8448 §3: Client finished key and verify_data.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn rfc8448_client_finished() {
        use hex_literal::hex;
        let hkdf = HkdfSha256;

        let client_hs_traffic =
            hex!("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        let mut finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(&hkdf, &client_hs_traffic, &mut finished_key)
            .unwrap();
        assert_eq!(
            finished_key,
            hex!("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")
        );

        // Transcript-Hash(CH..server Finished) from RFC 8448 §3
        let transcript_hash =
            hex!("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
        let verify_data =
            compute_finished_verify_data(&hkdf, &finished_key, &transcript_hash).unwrap();
        assert_eq!(
            verify_data,
            hex!("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
        );
    }
}
