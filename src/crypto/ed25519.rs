//! Ed25519 signing and verification for TLS 1.3 CertificateVerify.
//!
//! Provides helpers to:
//! - Build the TLS 1.3 CertificateVerify signed content (RFC 8446 section 4.4.3)
//! - Sign with an Ed25519 private key
//! - Verify an Ed25519 signature using a public key extracted from a DER certificate
//! - Extract an Ed25519 public key from a minimal DER-encoded certificate

use crate::error::Error;

/// TLS 1.3 signature algorithm code for Ed25519.
pub const ED25519_ALGORITHM: u16 = 0x0807;

/// Context string for server CertificateVerify (RFC 8446 section 4.4.3).
const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// Context string for client CertificateVerify (RFC 8446 section 4.4.3).
#[allow(dead_code)]
const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// Build the content to be signed for CertificateVerify (RFC 8446 section 4.4.3).
///
/// The signed content is:
///   64 bytes of 0x20 (space) + context_string + 0x00 + transcript_hash
///
/// Returns the content in a fixed-size buffer and the length used.
pub fn build_certificate_verify_content(
    context: &[u8],
    transcript_hash: &[u8; 32],
) -> ([u8; 130], usize) {
    // 64 spaces + context (up to 33 bytes) + 0x00 + 32 bytes hash
    // Max = 64 + 33 + 1 + 32 = 130
    let mut content = [0u8; 130];
    let mut off = 0;

    // 64 bytes of 0x20
    for item in content.iter_mut().take(64) {
        *item = 0x20;
    }
    off += 64;

    // Context string
    content[off..off + context.len()].copy_from_slice(context);
    off += context.len();

    // Separator byte 0x00
    content[off] = 0x00;
    off += 1;

    // Transcript hash
    content[off..off + 32].copy_from_slice(transcript_hash);
    off += 32;

    (content, off)
}

/// Build the server CertificateVerify signed content.
pub fn build_server_cv_content(transcript_hash: &[u8; 32]) -> ([u8; 130], usize) {
    build_certificate_verify_content(SERVER_CONTEXT, transcript_hash)
}

/// Sign the CertificateVerify content using an Ed25519 private key.
///
/// `signing_key_bytes` must be the 32-byte Ed25519 seed (private key).
/// `transcript_hash` is the hash of the transcript up to and including the Certificate message.
///
/// Returns the 64-byte Ed25519 signature.
pub fn sign_certificate_verify(
    signing_key_bytes: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 64], Error> {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let (content, content_len) = build_server_cv_content(transcript_hash);

    let signature = signing_key.sign(&content[..content_len]);
    Ok(signature.to_bytes())
}

/// Verify a CertificateVerify signature using an Ed25519 public key.
///
/// `public_key_bytes` must be the 32-byte Ed25519 public key.
/// `signature_bytes` must be the 64-byte Ed25519 signature.
/// `transcript_hash` is the hash of the transcript up to and including the Certificate message.
pub fn verify_certificate_verify(
    public_key_bytes: &[u8; 32],
    signature_bytes: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<(), Error> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(public_key_bytes).map_err(|_| Error::Tls)?;

    if signature_bytes.len() != 64 {
        return Err(Error::Tls);
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_array);

    let (content, content_len) = build_server_cv_content(transcript_hash);

    verifying_key
        .verify(&content[..content_len], &signature)
        .map_err(|_| Error::Tls)
}

/// Extract an Ed25519 public key from a DER-encoded certificate.
///
/// This does minimal ASN.1 parsing to find the SubjectPublicKeyInfo
/// containing an Ed25519 key (OID 1.3.101.112 = 06 03 2b 65 70).
///
/// Returns the 32-byte Ed25519 public key if found.
pub fn extract_ed25519_pubkey_from_cert(cert_der: &[u8]) -> Result<[u8; 32], Error> {
    // The Ed25519 OID in DER encoding: 06 03 2b 65 70
    let ed25519_oid: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    // Search for the OID in the certificate
    if let Some(oid_pos) = find_subsequence(cert_der, ed25519_oid) {
        // After the OID, we expect the public key in a BIT STRING.
        // The SubjectPublicKeyInfo structure is:
        //   SEQUENCE {
        //     SEQUENCE {
        //       OID (ed25519)
        //     }
        //     BIT STRING (0x00 padding byte + 32-byte key)
        //   }
        //
        // After the OID (5 bytes), the inner SEQUENCE might end,
        // then we get a BIT STRING tag (0x03).
        let after_oid = oid_pos + ed25519_oid.len();

        // Search for the BIT STRING tag after the OID
        for i in after_oid..cert_der.len().saturating_sub(34) {
            if cert_der[i] == 0x03 {
                // BIT STRING tag found
                let len_byte = cert_der.get(i + 1).ok_or(Error::Tls)?;
                let bit_string_len = *len_byte as usize;

                // Ed25519 public key BIT STRING: length should be 33
                // (1 byte unused-bits count + 32 bytes key)
                if bit_string_len == 33 {
                    let padding = cert_der.get(i + 2).ok_or(Error::Tls)?;
                    if *padding != 0x00 {
                        return Err(Error::Tls);
                    }

                    let key_start = i + 3;
                    let key_end = key_start + 32;
                    if key_end > cert_der.len() {
                        return Err(Error::Tls);
                    }

                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&cert_der[key_start..key_end]);
                    return Ok(pubkey);
                }
            }
        }
    }

    Err(Error::Tls)
}

/// Derive the Ed25519 public key from a 32-byte private key seed.
pub fn ed25519_public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    verifying_key.to_bytes()
}

/// Build a minimal self-signed DER certificate containing an Ed25519 public key.
///
/// This creates a minimal X.509v3-like structure sufficient for TLS 1.3
/// CertificateVerify purposes. It contains the SubjectPublicKeyInfo with
/// the Ed25519 OID and the 32-byte public key.
///
/// Returns the DER-encoded certificate bytes and the length used.
pub fn build_ed25519_cert_der(public_key: &[u8; 32], out: &mut [u8]) -> Result<usize, Error> {
    // Build a minimal X.509 Certificate structure:
    // SEQUENCE (Certificate) {
    //   SEQUENCE (TBSCertificate) {
    //     [0] EXPLICIT INTEGER (version = v3 = 2)
    //     INTEGER (serialNumber = 1)
    //     SEQUENCE (signature algorithm = Ed25519) {
    //       OID 1.3.101.112
    //     }
    //     SEQUENCE (issuer = CN=milli-quic) {
    //       SET { SEQUENCE { OID 2.5.4.3, UTF8String "milli-quic" } }
    //     }
    //     SEQUENCE (validity) {
    //       UTCTime "250101000000Z"
    //       UTCTime "350101000000Z"
    //     }
    //     SEQUENCE (subject = CN=milli-quic) {
    //       SET { SEQUENCE { OID 2.5.4.3, UTF8String "milli-quic" } }
    //     }
    //     SEQUENCE (SubjectPublicKeyInfo) {
    //       SEQUENCE { OID 1.3.101.112 }
    //       BIT STRING (0x00 + public_key)
    //     }
    //   }
    //   SEQUENCE (signatureAlgorithm = Ed25519) {
    //     OID 1.3.101.112
    //   }
    //   BIT STRING (signature - placeholder)
    // }

    // Pre-built DER template for a minimal Ed25519 certificate.
    // The public key bytes are at a known offset.
    #[rustfmt::skip]
    let template: &[u8] = &[
        // SEQUENCE (Certificate)
        0x30, 0x81, 0xd6,
          // SEQUENCE (TBSCertificate)
          0x30, 0x81, 0x89,
            // [0] EXPLICIT INTEGER v3 (2)
            0xa0, 0x03, 0x02, 0x01, 0x02,
            // INTEGER serialNumber = 1
            0x02, 0x01, 0x01,
            // SEQUENCE (signature algorithm OID = Ed25519)
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            // SEQUENCE (issuer: CN=milli-quic)
            0x30, 0x15,
              0x31, 0x13, 0x30, 0x11,
                0x06, 0x03, 0x55, 0x04, 0x03,  // OID 2.5.4.3 (CN)
                0x0c, 0x0a,                      // UTF8String length 10
                b'm', b'i', b'l', b'l', b'i', b'-', b'q', b'u', b'i', b'c',
            // SEQUENCE (validity)
            0x30, 0x1e,
              // UTCTime "250101000000Z"
              0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
              // UTCTime "350101000000Z"
              0x17, 0x0d, b'3', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
            // SEQUENCE (subject: CN=milli-quic) - same as issuer
            0x30, 0x15,
              0x31, 0x13, 0x30, 0x11,
                0x06, 0x03, 0x55, 0x04, 0x03,
                0x0c, 0x0a,
                b'm', b'i', b'l', b'l', b'i', b'-', b'q', b'u', b'i', b'c',
            // SEQUENCE (SubjectPublicKeyInfo)
            0x30, 0x2a,
              // SEQUENCE { OID 1.3.101.112 }
              0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
              // BIT STRING: 0x00 padding + 32 bytes public key
              0x03, 0x21, 0x00,
              // 32 bytes of public key placeholder (will be replaced)
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          // SEQUENCE (signatureAlgorithm = Ed25519)
          0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
          // BIT STRING (signature - 64 bytes + 1 padding byte)
          0x03, 0x41, 0x00,
          // 64 bytes of placeholder signature
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let total = template.len();
    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    out[..total].copy_from_slice(template);

    // Find the public key location: after BIT STRING tag 0x03 0x21 0x00
    // in the SubjectPublicKeyInfo section. We search for the OID first.
    let pubkey_offset = find_subsequence(&out[..total], &[0x03, 0x21, 0x00]).ok_or(Error::Tls)? + 3;
    out[pubkey_offset..pubkey_offset + 32].copy_from_slice(public_key);

    Ok(total)
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=(haystack.len() - needle.len())).find(|&i| haystack[i..i + needle.len()] == *needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let transcript_hash = [0xABu8; 32];

        let signature = sign_certificate_verify(&seed, &transcript_hash).unwrap();

        let pubkey = ed25519_public_key_from_seed(&seed);
        verify_certificate_verify(&pubkey, &signature, &transcript_hash).unwrap();
    }

    #[test]
    fn verify_wrong_key_fails() {
        let seed = [0x42u8; 32];
        let wrong_seed = [0x43u8; 32];
        let transcript_hash = [0xABu8; 32];

        let signature = sign_certificate_verify(&seed, &transcript_hash).unwrap();

        let wrong_pubkey = ed25519_public_key_from_seed(&wrong_seed);
        let result = verify_certificate_verify(&wrong_pubkey, &signature, &transcript_hash);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_transcript_fails() {
        let seed = [0x42u8; 32];
        let transcript_hash = [0xABu8; 32];
        let wrong_hash = [0xACu8; 32];

        let signature = sign_certificate_verify(&seed, &transcript_hash).unwrap();

        let pubkey = ed25519_public_key_from_seed(&seed);
        let result = verify_certificate_verify(&pubkey, &signature, &wrong_hash);
        assert!(result.is_err());
    }

    #[test]
    fn build_cert_and_extract_pubkey() {
        let seed = [0x42u8; 32];
        let pubkey = ed25519_public_key_from_seed(&seed);

        let mut cert_buf = [0u8; 512];
        let cert_len = build_ed25519_cert_der(&pubkey, &mut cert_buf).unwrap();
        let cert_der = &cert_buf[..cert_len];

        let extracted = extract_ed25519_pubkey_from_cert(cert_der).unwrap();
        assert_eq!(extracted, pubkey);
    }

    #[test]
    fn extract_pubkey_from_non_ed25519_cert_fails() {
        // Random bytes that don't contain the Ed25519 OID
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let result = extract_ed25519_pubkey_from_cert(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_verify_content_format() {
        let transcript_hash = [0xABu8; 32];
        let (content, len) = build_server_cv_content(&transcript_hash);

        // Should start with 64 spaces
        for i in 0..64 {
            assert_eq!(content[i], 0x20, "byte {i} should be 0x20");
        }

        // Then the context string
        let context_str = b"TLS 1.3, server CertificateVerify";
        assert_eq!(&content[64..64 + context_str.len()], context_str);

        // Then 0x00
        let sep_pos = 64 + context_str.len();
        assert_eq!(content[sep_pos], 0x00);

        // Then the transcript hash
        let hash_start = sep_pos + 1;
        assert_eq!(&content[hash_start..hash_start + 32], &transcript_hash);

        // Total length
        assert_eq!(len, 64 + context_str.len() + 1 + 32);
    }

    #[test]
    fn full_sign_verify_with_cert() {
        // Generate key pair
        let seed = [0x55u8; 32];
        let pubkey = ed25519_public_key_from_seed(&seed);

        // Build a certificate with this public key
        let mut cert_buf = [0u8; 512];
        let cert_len = build_ed25519_cert_der(&pubkey, &mut cert_buf).unwrap();
        let cert_der = &cert_buf[..cert_len];

        // Sign with the private key
        let transcript_hash = [0xCDu8; 32];
        let signature = sign_certificate_verify(&seed, &transcript_hash).unwrap();

        // Extract public key from cert and verify
        let extracted_pubkey = extract_ed25519_pubkey_from_cert(cert_der).unwrap();
        verify_certificate_verify(&extracted_pubkey, &signature, &transcript_hash).unwrap();
    }
}
