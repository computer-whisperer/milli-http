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
/// Build a minimal self-signed Ed25519 X.509 certificate (CN=milli-quic).
///
/// Equivalent to [`build_ed25519_cert_der_with_san`] with no SAN entries.
pub fn build_ed25519_cert_der(public_key: &[u8; 32], out: &mut [u8]) -> Result<usize, Error> {
    build_ed25519_cert_der_with_san(public_key, &[], &[], out)
}

/// Build a minimal self-signed Ed25519 X.509 certificate (CN=milli-quic) with
/// an optional `subjectAltName` extension.
///
/// `dns_names` and `ip_addrs` populate the SAN so TLS clients can validate the
/// hostname or IP they connected to (modern clients ignore the CN). Both are
/// optional — pass empty slices to omit the extension entirely, which yields a
/// certificate byte-identical to [`build_ed25519_cert_der`]. The signature is a
/// fixed placeholder: this certificate is meant to be pinned/trusted directly,
/// not chain-verified.
pub fn build_ed25519_cert_der_with_san(
    public_key: &[u8; 32],
    dns_names: &[&str],
    ip_addrs: &[core::net::IpAddr],
    out: &mut [u8],
) -> Result<usize, Error> {
    use crate::crypto::x509::{asn1_len_size, encode_san_extensions, write_asn1_len};

    // Fixed TBSCertificate fragments. The DER structure is:
    //   TBSCertificate ::= SEQUENCE {
    //     [0] version v3, serialNumber 1, signature Ed25519,
    //     issuer/subject CN=milli-quic, validity 2025-2035, SPKI, [3] extensions
    //   }
    const VERSION: [u8; 5] = [0xa0, 0x03, 0x02, 0x01, 0x02];
    const SERIAL: [u8; 3] = [0x02, 0x01, 0x01];
    // signatureAlgorithm: SEQUENCE { OID 1.3.101.112 (Ed25519) }
    const SIG_ALGO: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    // issuer == subject: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (CN), UTF8String "milli-quic" } } }
    const NAME: [u8; 23] = [
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, b'm', b'i',
        b'l', b'l', b'i', b'-', b'q', b'u', b'i', b'c',
    ];
    // validity: SEQUENCE { UTCTime "250101000000Z", UTCTime "350101000000Z" }
    const VALIDITY: [u8; 32] = [
        0x30, 0x1e, 0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'3', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ];
    // SubjectPublicKeyInfo header: SEQUENCE { SEQUENCE { Ed25519 OID }, BIT STRING (0x00 + key) }
    const SPKI_HEADER: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    // Encode the SAN extensions block first (0 bytes if both lists are empty).
    let mut ext = [0u8; 320];
    let ext_len = encode_san_extensions(dns_names, ip_addrs, &mut ext)?;

    // ---- assemble TBSCertificate content ----
    let mut tbs = [0u8; 512];
    let mut t = 0usize;
    for frag in [
        &VERSION[..],
        &SERIAL[..],
        &SIG_ALGO[..],
        &NAME[..],
        &VALIDITY[..],
        &NAME[..],
        &SPKI_HEADER[..],
    ] {
        tbs[t..t + frag.len()].copy_from_slice(frag);
        t += frag.len();
    }
    tbs[t..t + 32].copy_from_slice(public_key);
    t += 32;
    tbs[t..t + ext_len].copy_from_slice(&ext[..ext_len]);
    t += ext_len;
    let tbs_len = t;

    // ---- outer Certificate: TBS + signatureAlgorithm + signature ----
    // signature BIT STRING: 03 41 00 + 64-byte placeholder.
    const SIG_LEN: usize = 3 + 64;
    let tbs_wrapped = 1 + asn1_len_size(tbs_len) + tbs_len;
    let outer_content = tbs_wrapped + SIG_ALGO.len() + SIG_LEN;
    let total = 1 + asn1_len_size(outer_content) + outer_content;
    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    let mut o = 0usize;
    out[o] = 0x30;
    o += 1;
    o += write_asn1_len(outer_content, &mut out[o..])?;
    // TBSCertificate
    out[o] = 0x30;
    o += 1;
    o += write_asn1_len(tbs_len, &mut out[o..])?;
    out[o..o + tbs_len].copy_from_slice(&tbs[..tbs_len]);
    o += tbs_len;
    // signatureAlgorithm
    out[o..o + SIG_ALGO.len()].copy_from_slice(&SIG_ALGO);
    o += SIG_ALGO.len();
    // signature BIT STRING (placeholder zeros)
    out[o] = 0x03;
    out[o + 1] = 0x41;
    out[o + 2] = 0x00;
    for b in out[o + 3..o + SIG_LEN].iter_mut() {
        *b = 0x00;
    }
    o += SIG_LEN;

    Ok(o)
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
    fn build_cert_with_san_embeds_names_and_ip() {
        use core::net::{IpAddr, Ipv6Addr};

        let seed = [0x42u8; 32];
        let pubkey = ed25519_public_key_from_seed(&seed);
        let v6 = Ipv6Addr::new(0xfd54, 0xa4ae, 0x56de, 1, 0, 0, 0, 1);

        let mut cert_buf = [0u8; 512];
        let cert_len = build_ed25519_cert_der_with_san(
            &pubkey,
            &["raven.local"],
            &[IpAddr::V6(v6)],
            &mut cert_buf,
        )
        .unwrap();
        let cert_der = &cert_buf[..cert_len];

        // subjectAltName OID (2.5.29.17), the dNSName, and the iPAddress octets
        // are all present.
        assert!(find_subsequence(cert_der, &[0x06, 0x03, 0x55, 0x1d, 0x11]).is_some());
        assert!(find_subsequence(cert_der, b"raven.local").is_some());
        assert!(find_subsequence(cert_der, &v6.octets()).is_some());

        // The public key is still extractable past the SAN block.
        assert_eq!(extract_ed25519_pubkey_from_cert(cert_der).unwrap(), pubkey);

        // And the SAN cert is larger than the equivalent no-SAN cert.
        let mut plain = [0u8; 512];
        let plain_len = build_ed25519_cert_der(&pubkey, &mut plain).unwrap();
        assert!(cert_len > plain_len);
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
