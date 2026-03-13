//! QUIC key derivation (RFC 9001).
//!
//! Provides HKDF-Expand-Label, initial secret derivation, and packet
//! key derivation for QUIC v1.

use crate::crypto::{Aead, CryptoProvider, DirectionalKeys, Hkdf};
use crate::error::Error;
use zeroize::Zeroize;

/// QUIC v1 Initial salt (RFC 9001 section 5.2).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// HKDF-Expand-Label as defined in RFC 9001 section 5.1.
///
/// Constructs the HkdfLabel structure:
///   uint16 length = out.len()
///   opaque label<7..255> = "tls13 " + label
///   opaque context<0..255> = context
///
/// Then calls HKDF-Expand(secret, HkdfLabel, out.len()).
pub fn hkdf_expand_label<H: Hkdf>(
    hkdf: &H,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // Build the HkdfLabel info structure on the stack.
    // Max label: "tls13 " (6) + label (reasonable max ~20) = ~26 bytes
    // Max info: 2 + 1 + 6 + label.len() + 1 + context.len()
    let tls13_prefix = b"tls13 ";
    let full_label_len = tls13_prefix.len() + label.len();
    let info_len = 2 + 1 + full_label_len + 1 + context.len();

    // We use a stack buffer. 80 bytes is ample for any QUIC label.
    if info_len > 80 {
        return Err(Error::Crypto);
    }

    let mut info = [0u8; 80];
    let out_len = out.len() as u16;
    info[0] = (out_len >> 8) as u8;
    info[1] = out_len as u8;
    info[2] = full_label_len as u8;
    info[3..3 + tls13_prefix.len()].copy_from_slice(tls13_prefix);
    info[3 + tls13_prefix.len()..3 + full_label_len].copy_from_slice(label);
    info[3 + full_label_len] = context.len() as u8;
    if !context.is_empty() {
        info[4 + full_label_len..4 + full_label_len + context.len()].copy_from_slice(context);
    }

    hkdf.expand(secret, &info[..info_len], out)
}

/// Derive the QUIC v1 initial secrets from a client Destination Connection ID.
///
/// Produces `client_secret` and `server_secret`, each of length `H::HASH_LEN`.
pub fn derive_initial_secrets<H: Hkdf>(
    hkdf: &H,
    dcid: &[u8],
    client_secret: &mut [u8],
    server_secret: &mut [u8],
) -> Result<(), Error> {
    let mut initial_secret = [0u8; 32];
    hkdf.extract(&INITIAL_SALT_V1, dcid, &mut initial_secret);

    let result = (|| {
        hkdf_expand_label(hkdf, &initial_secret, b"client in", &[], client_secret)?;
        hkdf_expand_label(hkdf, &initial_secret, b"server in", &[], server_secret)?;
        Ok(())
    })();
    initial_secret.zeroize();
    result
}

/// Derive packet protection keys from a traffic secret.
///
/// `key` length should be the AEAD key size (16 for AES-128-GCM, 32 for ChaCha20).
/// `iv` length should be 12.
/// `hp_key` length should be 16 (AES) or 32 (ChaCha20).
pub fn derive_packet_keys<H: Hkdf>(
    hkdf: &H,
    secret: &[u8],
    key: &mut [u8],
    iv: &mut [u8],
    hp_key: &mut [u8],
) -> Result<(), Error> {
    hkdf_expand_label(hkdf, secret, b"quic key", &[], key)?;
    hkdf_expand_label(hkdf, secret, b"quic iv", &[], iv)?;
    hkdf_expand_label(hkdf, secret, b"quic hp", &[], hp_key)?;
    Ok(())
}

/// Derive TLS record protection keys from a traffic secret.
///
/// Uses labels `"key"` and `"iv"` (RFC 8446 §7.3) instead of `"quic key"` / `"quic iv"`.
/// No header protection key is needed for TLS records.
pub fn derive_tls_record_keys<H: Hkdf>(
    hkdf: &H,
    secret: &[u8],
    key: &mut [u8],
    iv: &mut [u8; 12],
) -> Result<(), Error> {
    hkdf_expand_label(hkdf, secret, b"key", &[], key)?;
    hkdf_expand_label(hkdf, secret, b"iv", &[], iv)?;
    Ok(())
}

/// Derive the next-generation application traffic secret for QUIC Key Update.
///
/// Per RFC 9001 section 6.1, the updated secret is derived as:
///   new_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
///
/// The caller should then derive new packet protection keys from `new_secret`
/// using [`derive_packet_keys`] or [`derive_directional_keys`].
pub fn derive_next_application_secret<H: Hkdf>(
    hkdf: &H,
    current_secret: &[u8],
    new_secret: &mut [u8],
) -> Result<(), Error> {
    hkdf_expand_label(hkdf, current_secret, b"quic ku", &[], new_secret)
}

/// Derive complete `DirectionalKeys` from a traffic secret using a `CryptoProvider`.
pub fn derive_directional_keys<C: CryptoProvider>(
    provider: &C,
    hkdf: &C::Hkdf,
    secret: &[u8],
) -> Result<DirectionalKeys<C::Aead, C::HeaderProtection>, Error> {
    let mut key_buf = [0u8; 32];
    let mut iv = [0u8; 12];
    let mut hp_buf = [0u8; 32];

    let key_len = C::Aead::KEY_LEN;
    let hp_key_len = core::cmp::max(key_len, 16); // AES HP is always 16, ChaCha HP is 32

    let result = (|| {
        derive_packet_keys(
            hkdf,
            secret,
            &mut key_buf[..key_len],
            &mut iv,
            &mut hp_buf[..hp_key_len],
        )?;

        let aead = provider.aead(&key_buf[..key_len])?;
        let header_protection = provider.header_protection(&hp_buf[..hp_key_len])?;

        Ok(DirectionalKeys {
            aead,
            header_protection,
            iv,
        })
    })();
    key_buf.zeroize();
    hp_buf.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Use the real HkdfSha256 impl for tests.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    use crate::crypto::rustcrypto::HkdfSha256;

    // ---- RFC 9001 Appendix A.1 test vectors ----

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn initial_secrets_rfc9001_a1() {
        let hkdf = HkdfSha256;
        let dcid = hex!("8394c8f03e515708");

        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        derive_initial_secrets(&hkdf, &dcid, &mut client_secret, &mut server_secret).unwrap();

        assert_eq!(
            client_secret,
            hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            server_secret,
            hex!("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn initial_client_keys_rfc9001_a1() {
        let hkdf = HkdfSha256;
        let client_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");

        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut hp = [0u8; 16];
        derive_packet_keys(&hkdf, &client_secret, &mut key, &mut iv, &mut hp).unwrap();

        assert_eq!(key, hex!("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv, hex!("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp, hex!("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn initial_server_keys_rfc9001_a1() {
        let hkdf = HkdfSha256;
        let server_secret =
            hex!("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");

        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut hp = [0u8; 16];
        derive_packet_keys(&hkdf, &server_secret, &mut key, &mut iv, &mut hp).unwrap();

        assert_eq!(key, hex!("cf3a5331653c364c88f0f379b6067e37"));
        assert_eq!(iv, hex!("0ac1493ca1905853b0bba03e"));
        assert_eq!(hp, hex!("c206b8d9b9f0f37644430b490eeaa314"));
    }

    // ---- HKDF-Expand-Label basic test ----

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn hkdf_expand_label_client_in() {
        let hkdf = HkdfSha256;
        // initial_secret derived from INITIAL_SALT_V1 + dcid
        let dcid = hex!("8394c8f03e515708");
        let mut initial_secret = [0u8; 32];
        hkdf.extract(&INITIAL_SALT_V1, &dcid, &mut initial_secret);

        let mut client_secret = [0u8; 32];
        hkdf_expand_label(&hkdf, &initial_secret, b"client in", &[], &mut client_secret).unwrap();

        assert_eq!(
            client_secret,
            hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
    }

    // ---- DirectionalKeys nonce computation ----

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn directional_keys_nonce() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let hkdf = HkdfSha256;
        let client_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");

        let provider = Aes128GcmProvider;
        let dk = derive_directional_keys(&provider, &hkdf, &client_secret).unwrap();

        // iv = fa044b2f42a3fd3b46fb255c
        assert_eq!(dk.iv, hex!("fa044b2f42a3fd3b46fb255c"));

        // Nonce for packet number 0 should equal the IV
        let nonce0 = dk.nonce(0);
        assert_eq!(nonce0, dk.iv);

        // Nonce for pn=1: XOR last byte with 1
        let nonce1 = dk.nonce(1);
        let mut expected = dk.iv;
        expected[11] ^= 1;
        assert_eq!(nonce1, expected);
    }

    // ---- derive_directional_keys end-to-end ----

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_directional_keys_aes() {
        use crate::crypto::Aead as _;
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let hkdf = HkdfSha256;
        let dcid = hex!("8394c8f03e515708");

        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        derive_initial_secrets(&hkdf, &dcid, &mut client_secret, &mut server_secret).unwrap();

        let provider = Aes128GcmProvider;
        let client_keys = derive_directional_keys(&provider, &hkdf, &client_secret).unwrap();
        let server_keys = derive_directional_keys(&provider, &hkdf, &server_secret).unwrap();

        // Verify IVs match the RFC vectors
        assert_eq!(client_keys.iv, hex!("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(server_keys.iv, hex!("0ac1493ca1905853b0bba03e"));

        // Verify we can encrypt and decrypt with the derived keys
        let mut buf = [0u8; 64];
        let plaintext = b"test payload";
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let nonce = client_keys.nonce(0);
        let aad = b"header";

        let ct_len = client_keys
            .aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();
        let pt_len = client_keys
            .aead
            .open_in_place(&nonce, aad, &mut buf, ct_len)
            .unwrap();
        assert_eq!(&buf[..pt_len], plaintext);
    }

    // ---- Key Update derivation (RFC 9001 section 6.1) ----

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_next_application_secret_produces_different_secret() {
        let hkdf = HkdfSha256;
        let current_secret = hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");

        let mut new_secret = [0u8; 32];
        derive_next_application_secret(&hkdf, &current_secret, &mut new_secret).unwrap();

        // Must be different from the original
        assert_ne!(new_secret, current_secret);
        // Must not be all zeros
        assert_ne!(new_secret, [0u8; 32]);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_next_application_secret_is_deterministic() {
        let hkdf = HkdfSha256;
        let current_secret = [0x42u8; 32];

        let mut new_secret1 = [0u8; 32];
        let mut new_secret2 = [0u8; 32];
        derive_next_application_secret(&hkdf, &current_secret, &mut new_secret1).unwrap();
        derive_next_application_secret(&hkdf, &current_secret, &mut new_secret2).unwrap();

        assert_eq!(new_secret1, new_secret2);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_next_application_secret_chain() {
        // Verify that chaining key updates produces distinct secrets at each generation
        let hkdf = HkdfSha256;
        let gen0 = [0xAA; 32];
        let mut gen1 = [0u8; 32];
        let mut gen2 = [0u8; 32];
        let mut gen3 = [0u8; 32];

        derive_next_application_secret(&hkdf, &gen0, &mut gen1).unwrap();
        derive_next_application_secret(&hkdf, &gen1, &mut gen2).unwrap();
        derive_next_application_secret(&hkdf, &gen2, &mut gen3).unwrap();

        // All four generations must be distinct
        assert_ne!(gen0, gen1);
        assert_ne!(gen1, gen2);
        assert_ne!(gen2, gen3);
        assert_ne!(gen0, gen2);
        assert_ne!(gen0, gen3);
        assert_ne!(gen1, gen3);
    }
}
