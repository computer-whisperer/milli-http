//! ECDSA-P256 (secp256r1 with SHA-256) signing and verification for TLS 1.3 CertificateVerify.
//!
//! Provides helpers to:
//! - Build the TLS 1.3 CertificateVerify signed content (RFC 8446 section 4.4.3)
//! - Sign with an ECDSA-P256 private key (32-byte scalar)
//! - Verify an ECDSA-P256 signature using a public key extracted from a DER certificate
//! - Extract a P-256 public key from a DER-encoded X.509 certificate

use crate::error::Error;

/// TLS 1.3 signature algorithm code for ECDSA with secp256r1 and SHA-256.
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// Sign the CertificateVerify content using an ECDSA-P256 private key.
///
/// `signing_key_bytes` must be the 32-byte P-256 private scalar.
/// `transcript_hash` is the hash of the transcript up to and including the Certificate message.
///
/// Returns the DER-encoded ECDSA signature (variable length, typically 70-72 bytes).
pub fn sign_certificate_verify(
    signing_key_bytes: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<heapless::Vec<u8, 128>, Error> {
    use p256::ecdsa::{SigningKey, signature::Signer};

    if signing_key_bytes.len() != 32 {
        return Err(Error::Tls);
    }

    let signing_key = SigningKey::from_bytes(signing_key_bytes.into()).map_err(|_| Error::Tls)?;

    // Build the TLS 1.3 CertificateVerify signed content
    let (content, content_len) = crate::crypto::ed25519::build_server_cv_content(transcript_hash);

    // Sign the content directly -- the p256 crate's Signer impl for SigningKey
    // hashes with SHA-256 internally, but for TLS 1.3 CertificateVerify with
    // ecdsa_secp256r1_sha256, the content to sign IS the raw content
    // (64 spaces + context + 0x00 + transcript_hash), and it gets SHA-256'd
    // by the signing operation.
    let signature: p256::ecdsa::DerSignature = signing_key.sign(&content[..content_len]);

    let sig_bytes = signature.as_bytes();
    let mut result = heapless::Vec::new();
    result
        .extend_from_slice(sig_bytes)
        .map_err(|_| Error::Tls)?;
    Ok(result)
}

/// Verify a CertificateVerify signature using an ECDSA-P256 public key.
///
/// `public_key_bytes` must be the uncompressed P-256 public key point
/// (65 bytes: 0x04 || x || y), or the SEC1-encoded point.
/// `signature` must be the DER-encoded ECDSA signature.
/// `transcript_hash` is the hash of the transcript up to and including the Certificate message.
pub fn verify_certificate_verify(
    public_key_bytes: &[u8],
    signature: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<(), Error> {
    use p256::ecdsa::{VerifyingKey, signature::Verifier};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|_| Error::Tls)?;

    let sig = p256::ecdsa::DerSignature::try_from(signature).map_err(|_| Error::Tls)?;

    let (content, content_len) = crate::crypto::ed25519::build_server_cv_content(transcript_hash);

    verifying_key
        .verify(&content[..content_len], &sig)
        .map_err(|_| Error::Tls)
}

/// Extract a P-256 (secp256r1) public key from a DER-encoded X.509 certificate.
///
/// Searches for the secp256r1 OID (1.2.840.10045.3.1.7) in the certificate,
/// then extracts the uncompressed public key point from the SubjectPublicKeyInfo
/// BIT STRING.
///
/// Returns the raw public key bytes (65 bytes for uncompressed point: 0x04 || x || y).
pub fn extract_p256_pubkey_from_cert(cert_der: &[u8]) -> Result<heapless::Vec<u8, 128>, Error> {
    // The secp256r1 OID in DER encoding: 06 08 2a 86 48 ce 3d 03 01 07
    // OID 1.2.840.10045.3.1.7
    let secp256r1_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    if let Some(oid_pos) = find_subsequence(cert_der, secp256r1_oid) {
        // After the secp256r1 OID, the SubjectPublicKeyInfo structure has:
        //   SEQUENCE {
        //     SEQUENCE {
        //       OID (ecPublicKey = 1.2.840.10045.2.1)
        //       OID (secp256r1 = 1.2.840.10045.3.1.7)  <-- we found this
        //     }
        //     BIT STRING (0x00 padding byte + 65-byte uncompressed point)
        //   }
        let after_oid = oid_pos + secp256r1_oid.len();

        // Search for the BIT STRING tag (0x03) after the OID
        for i in after_oid..cert_der.len().saturating_sub(66) {
            if cert_der[i] == 0x03 {
                // BIT STRING tag found -- parse the length
                let (bit_string_len, hdr_len) = parse_asn1_length(&cert_der[i + 1..])?;

                // P-256 uncompressed public key BIT STRING: length should be 66
                // (1 byte unused-bits count + 65 bytes = 0x04 || x(32) || y(32))
                if bit_string_len == 66 {
                    let content_start = i + 1 + hdr_len;
                    let padding = cert_der.get(content_start).ok_or(Error::Tls)?;
                    if *padding != 0x00 {
                        return Err(Error::Tls);
                    }

                    let key_start = content_start + 1;
                    let key_end = key_start + 65;
                    if key_end > cert_der.len() {
                        return Err(Error::Tls);
                    }

                    let mut pubkey = heapless::Vec::new();
                    pubkey
                        .extend_from_slice(&cert_der[key_start..key_end])
                        .map_err(|_| Error::Tls)?;
                    return Ok(pubkey);
                }
            }
        }
    }

    Err(Error::Tls)
}

/// Detect whether a DER-encoded certificate contains a P-256 key.
///
/// Returns `true` if the secp256r1 OID (1.2.840.10045.3.1.7) is found.
pub fn cert_has_p256_key(cert_der: &[u8]) -> bool {
    let secp256r1_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    find_subsequence(cert_der, secp256r1_oid).is_some()
}

/// Derive the P-256 public key (SEC1 uncompressed) from a 32-byte private scalar.
pub fn p256_public_key_from_scalar(scalar: &[u8; 32]) -> Result<heapless::Vec<u8, 128>, Error> {
    use p256::ecdsa::SigningKey;

    let signing_key = SigningKey::from_bytes(scalar.into()).map_err(|_| Error::Tls)?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false); // uncompressed

    let mut result = heapless::Vec::new();
    result
        .extend_from_slice(encoded.as_bytes())
        .map_err(|_| Error::Tls)?;
    Ok(result)
}

/// Build a minimal self-signed ECDSA P-256 X.509 certificate (CN=milli-quic).
///
/// Equivalent to [`build_p256_cert_der_with_san`] with no SAN entries.
pub fn build_p256_cert_der(public_key: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    build_p256_cert_der_with_san(public_key, &[], &[], out)
}

/// Build a minimal self-signed ECDSA P-256 X.509 certificate (CN=milli-quic)
/// with an optional `subjectAltName` extension. `dns_names` and `ip_addrs`
/// populate the SAN so TLS clients can validate the hostname/IP they connected
/// to; both are optional (pass empty slices to omit the extension).
pub fn build_p256_cert_der_with_san(
    public_key: &[u8],
    dns_names: &[&str],
    ip_addrs: &[core::net::IpAddr],
    out: &mut [u8],
) -> Result<usize, Error> {
    // We need the uncompressed public key (65 bytes: 0x04 || x || y)
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(Error::Tls);
    }

    // Build a minimal X.509 Certificate structure.
    // We construct this manually, piece by piece.
    //
    // SubjectPublicKeyInfo for ECDSA P-256:
    //   SEQUENCE {
    //     SEQUENCE {
    //       OID 1.2.840.10045.2.1 (ecPublicKey)
    //       OID 1.2.840.10045.3.1.7 (secp256r1)
    //     }
    //     BIT STRING (0x00 + 65-byte uncompressed point)
    //   }

    // ecPublicKey OID: 06 07 2a 86 48 ce 3d 02 01
    // secp256r1 OID:   06 08 2a 86 48 ce 3d 03 01 07

    // Build the SPKI
    let algo_seq_inner: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // secp256r1 OID
    ];
    // algo SEQUENCE: 30 + len + inner
    let algo_seq_len = algo_seq_inner.len(); // 19

    // BIT STRING: 03 + len(66) + 0x00 + pubkey(65)
    let bit_string_len = 1 + 65; // 66

    // SPKI SEQUENCE length: (1 + 1 + algo_seq_len) + (1 + 1 + bit_string_len)
    let spki_inner_len = (2 + algo_seq_len) + (2 + bit_string_len);

    // CN = "milli-quic" in RDN format:
    // SET { SEQUENCE { OID 2.5.4.3, UTF8String "milli-quic" } }
    let cn_rdn: &[u8] = &[
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, b'm', b'i', b'l', b'l',
        b'i', b'-', b'q', b'u', b'i', b'c',
    ];

    // Validity: UTCTime "250101000000Z" to "350101000000Z"
    let validity: &[u8] = &[
        0x30, 0x1e, 0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'3', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ];

    // Signature algorithm for the outer cert: ecdsaWithSHA256
    // OID 1.2.840.10045.4.3.2
    let ecdsa_sha256_algo: &[u8] = &[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];

    // TBSCertificate contents:
    //   [0] EXPLICIT INTEGER v3 (2)       = a0 03 02 01 02  (5 bytes)
    //   INTEGER serialNumber = 1          = 02 01 01        (3 bytes)
    //   SEQUENCE sigAlgo (ecdsa-sha256)   = ecdsa_sha256_algo  (12 bytes)
    //   SEQUENCE issuer (CN=milli-quic)   = 30 15 + cn_rdn  (23 bytes total)
    //   SEQUENCE validity                 = validity         (32 bytes)
    //   SEQUENCE subject (CN=milli-quic)  = 30 15 + cn_rdn  (23 bytes total)
    //   SEQUENCE SPKI                     = computed

    let version_bytes: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
    let serial_bytes: &[u8] = &[0x02, 0x01, 0x01];
    let issuer_header: &[u8] = &[0x30, 0x15];
    let subject_header: &[u8] = &[0x30, 0x15];

    // Placeholder signature: 8 bytes of zeros (minimal valid-looking DER sig)
    // Actually let's use a fake 64-byte-ish signature to look realistic.
    // BIT STRING: 03 + len + 0x00 + signature_bytes
    let fake_sig_len = 8;
    let fake_sig_bitstring_len = 1 + fake_sig_len; // 9

    // Build the entire certificate
    let mut buf_off = 0;

    // Helper closure is not ergonomic in no_std, so we'll build manually.

    // ---- TBSCertificate ----
    let mut tbs = [0u8; 512];
    let mut tbs_off = 0;

    // Copy version, serial
    tbs[tbs_off..tbs_off + version_bytes.len()].copy_from_slice(version_bytes);
    tbs_off += version_bytes.len();
    tbs[tbs_off..tbs_off + serial_bytes.len()].copy_from_slice(serial_bytes);
    tbs_off += serial_bytes.len();

    // sigAlgo
    tbs[tbs_off..tbs_off + ecdsa_sha256_algo.len()].copy_from_slice(ecdsa_sha256_algo);
    tbs_off += ecdsa_sha256_algo.len();

    // issuer
    tbs[tbs_off..tbs_off + issuer_header.len()].copy_from_slice(issuer_header);
    tbs_off += issuer_header.len();
    tbs[tbs_off..tbs_off + cn_rdn.len()].copy_from_slice(cn_rdn);
    tbs_off += cn_rdn.len();

    // validity
    tbs[tbs_off..tbs_off + validity.len()].copy_from_slice(validity);
    tbs_off += validity.len();

    // subject
    tbs[tbs_off..tbs_off + subject_header.len()].copy_from_slice(subject_header);
    tbs_off += subject_header.len();
    tbs[tbs_off..tbs_off + cn_rdn.len()].copy_from_slice(cn_rdn);
    tbs_off += cn_rdn.len();

    // SPKI SEQUENCE
    tbs[tbs_off] = 0x30;
    tbs_off += 1;
    tbs_off += write_asn1_length(spki_inner_len, &mut tbs[tbs_off..])?;

    // Algorithm SEQUENCE
    tbs[tbs_off] = 0x30;
    tbs_off += 1;
    tbs[tbs_off] = algo_seq_len as u8;
    tbs_off += 1;
    tbs[tbs_off..tbs_off + algo_seq_inner.len()].copy_from_slice(algo_seq_inner);
    tbs_off += algo_seq_inner.len();

    // BIT STRING (public key)
    tbs[tbs_off] = 0x03;
    tbs_off += 1;
    tbs[tbs_off] = bit_string_len as u8;
    tbs_off += 1;
    tbs[tbs_off] = 0x00; // unused bits
    tbs_off += 1;
    tbs[tbs_off..tbs_off + 65].copy_from_slice(public_key);
    tbs_off += 65;

    // Extensions: [3] EXPLICIT subjectAltName (nothing written if both empty).
    tbs_off +=
        crate::crypto::x509::encode_san_extensions(dns_names, ip_addrs, &mut tbs[tbs_off..])?;

    let tbs_len = tbs_off;

    // ---- Outer Certificate SEQUENCE ----
    // Content: TBS-SEQUENCE + sigAlgo-SEQUENCE + sig-BIT-STRING
    let tbs_seq_encoded_len = 1 + asn1_length_size(tbs_len) + tbs_len;
    let outer_content_len = tbs_seq_encoded_len
        + ecdsa_sha256_algo.len()
        + 1
        + asn1_length_size(fake_sig_bitstring_len)
        + fake_sig_bitstring_len;

    if out.len() < 1 + asn1_length_size(outer_content_len) + outer_content_len {
        return Err(Error::BufferTooSmall {
            needed: 1 + asn1_length_size(outer_content_len) + outer_content_len,
        });
    }

    // Outer SEQUENCE tag + length
    out[buf_off] = 0x30;
    buf_off += 1;
    buf_off += write_asn1_length(outer_content_len, &mut out[buf_off..])?;

    // TBSCertificate SEQUENCE
    out[buf_off] = 0x30;
    buf_off += 1;
    buf_off += write_asn1_length(tbs_len, &mut out[buf_off..])?;
    out[buf_off..buf_off + tbs_len].copy_from_slice(&tbs[..tbs_len]);
    buf_off += tbs_len;

    // signatureAlgorithm
    out[buf_off..buf_off + ecdsa_sha256_algo.len()].copy_from_slice(ecdsa_sha256_algo);
    buf_off += ecdsa_sha256_algo.len();

    // signature BIT STRING (placeholder)
    out[buf_off] = 0x03;
    buf_off += 1;
    buf_off += write_asn1_length(fake_sig_bitstring_len, &mut out[buf_off..])?;
    out[buf_off] = 0x00; // unused bits
    buf_off += 1;
    // fake_sig_len bytes of zeros (already zero from caller or we set them)
    for b in out[buf_off..buf_off + fake_sig_len].iter_mut() {
        *b = 0xAA; // placeholder signature
    }
    buf_off += fake_sig_len;

    Ok(buf_off)
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=(haystack.len() - needle.len())).find(|&i| haystack[i..i + needle.len()] == *needle)
}

/// Parse a DER/ASN.1 length field. Returns (length_value, bytes_consumed).
fn parse_asn1_length(data: &[u8]) -> Result<(usize, usize), Error> {
    if data.is_empty() {
        return Err(Error::Tls);
    }
    if data[0] < 0x80 {
        // Short form
        Ok((data[0] as usize, 1))
    } else if data[0] == 0x81 {
        // Long form, 1 byte
        if data.len() < 2 {
            return Err(Error::Tls);
        }
        Ok((data[1] as usize, 2))
    } else if data[0] == 0x82 {
        // Long form, 2 bytes
        if data.len() < 3 {
            return Err(Error::Tls);
        }
        Ok((((data[1] as usize) << 8) | (data[2] as usize), 3))
    } else {
        Err(Error::Tls)
    }
}

/// Compute the number of bytes needed to encode an ASN.1 length.
fn asn1_length_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else {
        3
    }
}

/// Write an ASN.1 length field. Returns bytes written.
fn write_asn1_length(len: usize, out: &mut [u8]) -> Result<usize, Error> {
    if len < 0x80 {
        if out.is_empty() {
            return Err(Error::BufferTooSmall { needed: 1 });
        }
        out[0] = len as u8;
        Ok(1)
    } else if len < 0x100 {
        if out.len() < 2 {
            return Err(Error::BufferTooSmall { needed: 2 });
        }
        out[0] = 0x81;
        out[1] = len as u8;
        Ok(2)
    } else {
        if out.len() < 3 {
            return Err(Error::BufferTooSmall { needed: 3 });
        }
        out[0] = 0x82;
        out[1] = (len >> 8) as u8;
        out[2] = (len & 0xFF) as u8;
        Ok(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let scalar = [0x42u8; 32];
        let transcript_hash = [0xABu8; 32];

        let signature = sign_certificate_verify(&scalar, &transcript_hash).unwrap();
        assert!(!signature.is_empty());
        // DER-encoded ECDSA signatures are typically 70-72 bytes
        assert!(
            signature.len() >= 68 && signature.len() <= 74,
            "unexpected signature length: {}",
            signature.len()
        );

        let pubkey = p256_public_key_from_scalar(&scalar).unwrap();
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04); // uncompressed point marker

        verify_certificate_verify(&pubkey, &signature, &transcript_hash).unwrap();
    }

    #[test]
    fn verify_wrong_key_fails() {
        let scalar = [0x42u8; 32];
        let wrong_scalar = [0x43u8; 32];
        let transcript_hash = [0xABu8; 32];

        let signature = sign_certificate_verify(&scalar, &transcript_hash).unwrap();

        let wrong_pubkey = p256_public_key_from_scalar(&wrong_scalar).unwrap();
        let result = verify_certificate_verify(&wrong_pubkey, &signature, &transcript_hash);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_transcript_fails() {
        let scalar = [0x42u8; 32];
        let transcript_hash = [0xABu8; 32];
        let wrong_hash = [0xACu8; 32];

        let signature = sign_certificate_verify(&scalar, &transcript_hash).unwrap();

        let pubkey = p256_public_key_from_scalar(&scalar).unwrap();
        let result = verify_certificate_verify(&pubkey, &signature, &wrong_hash);
        assert!(result.is_err());
    }

    #[test]
    fn build_cert_and_extract_pubkey() {
        let scalar = [0x42u8; 32];
        let pubkey = p256_public_key_from_scalar(&scalar).unwrap();

        let mut cert_buf = [0u8; 512];
        let cert_len = build_p256_cert_der(&pubkey, &mut cert_buf).unwrap();
        let cert_der = &cert_buf[..cert_len];

        let extracted = extract_p256_pubkey_from_cert(cert_der).unwrap();
        assert_eq!(extracted.as_slice(), pubkey.as_slice());
    }

    #[test]
    fn build_cert_with_san_embeds_names_and_ip() {
        use core::net::{IpAddr, Ipv4Addr};

        let scalar = [0x42u8; 32];
        let pubkey = p256_public_key_from_scalar(&scalar).unwrap();
        let v4 = Ipv4Addr::new(192, 168, 1, 50);

        let mut cert_buf = [0u8; 512];
        let cert_len = build_p256_cert_der_with_san(
            &pubkey,
            &["raven.local"],
            &[IpAddr::V4(v4)],
            &mut cert_buf,
        )
        .unwrap();
        let cert_der = &cert_buf[..cert_len];

        assert!(find_subsequence(cert_der, &[0x06, 0x03, 0x55, 0x1d, 0x11]).is_some());
        assert!(find_subsequence(cert_der, b"raven.local").is_some());
        assert!(find_subsequence(cert_der, &v4.octets()).is_some());
        assert_eq!(
            extract_p256_pubkey_from_cert(cert_der).unwrap().as_slice(),
            pubkey.as_slice()
        );

        let mut plain = [0u8; 512];
        let plain_len = build_p256_cert_der(&pubkey, &mut plain).unwrap();
        assert!(cert_len > plain_len);
    }

    #[test]
    fn extract_pubkey_from_non_p256_cert_fails() {
        // Random bytes that don't contain the secp256r1 OID
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let result = extract_p256_pubkey_from_cert(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn cert_has_p256_key_detects_correctly() {
        let scalar = [0x42u8; 32];
        let pubkey = p256_public_key_from_scalar(&scalar).unwrap();

        let mut cert_buf = [0u8; 512];
        let cert_len = build_p256_cert_der(&pubkey, &mut cert_buf).unwrap();

        assert!(cert_has_p256_key(&cert_buf[..cert_len]));
        assert!(!cert_has_p256_key(&[0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn full_sign_verify_with_cert() {
        // Generate key pair
        let scalar = [0x55u8; 32];
        let pubkey = p256_public_key_from_scalar(&scalar).unwrap();

        // Build a certificate with this public key
        let mut cert_buf = [0u8; 512];
        let cert_len = build_p256_cert_der(&pubkey, &mut cert_buf).unwrap();
        let cert_der = &cert_buf[..cert_len];

        // Sign with the private key
        let transcript_hash = [0xCDu8; 32];
        let signature = sign_certificate_verify(&scalar, &transcript_hash).unwrap();

        // Extract public key from cert and verify
        let extracted_pubkey = extract_p256_pubkey_from_cert(cert_der).unwrap();
        verify_certificate_verify(&extracted_pubkey, &signature, &transcript_hash).unwrap();
    }

    #[test]
    fn sign_with_wrong_key_length_fails() {
        let short_key = [0x42u8; 16];
        let transcript_hash = [0xABu8; 32];
        assert!(sign_certificate_verify(&short_key, &transcript_hash).is_err());
    }
}
