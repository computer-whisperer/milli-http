//! Minimal ASN.1/DER helpers for on-device X.509 certificate generation.
//!
//! Shared by the Ed25519 and ECDSA P-256 self-signed certificate builders.
//! Only the small subset needed to emit a `subjectAltName` extension is
//! implemented; nothing here parses untrusted input.

use core::net::IpAddr;

use crate::error::Error;

/// Number of bytes needed to encode `len` as a DER definite-length field.
pub(crate) fn asn1_len_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else {
        3
    }
}

/// Write a DER definite-length field for `len`. Returns bytes written.
///
/// Supports lengths up to 0xFFFF, which is far beyond any certificate field we
/// emit on-device.
pub(crate) fn write_asn1_len(len: usize, out: &mut [u8]) -> Result<usize, Error> {
    let n = asn1_len_size(len);
    if out.len() < n {
        return Err(Error::BufferTooSmall { needed: n });
    }
    match n {
        1 => out[0] = len as u8,
        2 => {
            out[0] = 0x81;
            out[1] = len as u8;
        }
        _ => {
            out[0] = 0x82;
            out[1] = (len >> 8) as u8;
            out[2] = len as u8;
        }
    }
    Ok(n)
}

/// Append one `GeneralName` (`tag` + length + `bytes`) to `names` at `*n`.
fn put_general_name(names: &mut [u8], n: &mut usize, tag: u8, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > 0xff {
        return Err(Error::Tls);
    }
    if *n + 2 + bytes.len() > names.len() {
        return Err(Error::BufferTooSmall {
            needed: *n + 2 + bytes.len(),
        });
    }
    names[*n] = tag;
    names[*n + 1] = bytes.len() as u8;
    names[*n + 2..*n + 2 + bytes.len()].copy_from_slice(bytes);
    *n += 2 + bytes.len();
    Ok(())
}

/// Encode the TBSCertificate `extensions` field carrying a single
/// `subjectAltName` extension:
///
/// ```text
/// [3] EXPLICIT SEQUENCE OF Extension {
///     SEQUENCE {                       -- the subjectAltName extension
///         OID 2.5.29.17
///         OCTET STRING {
///             SEQUENCE OF GeneralName {
///                 [2] dNSName   (one per entry in `dns_names`)
///                 [7] iPAddress (one per entry in `ip_addrs`; 4 or 16 bytes)
///             }
///         }
///     }
/// }
/// ```
///
/// Both lists are optional: if `dns_names` and `ip_addrs` are both empty,
/// nothing is written and `Ok(0)` is returned — the caller should then omit the
/// extensions field entirely (a v3 certificate with no extensions is valid).
pub(crate) fn encode_san_extensions(
    dns_names: &[&str],
    ip_addrs: &[IpAddr],
    out: &mut [u8],
) -> Result<usize, Error> {
    if dns_names.is_empty() && ip_addrs.is_empty() {
        return Ok(0);
    }

    // subjectAltName OID (2.5.29.17), pre-encoded.
    const SAN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];

    // 1. GeneralName entries (innermost), built into scratch to learn the length.
    let mut names = [0u8; 256];
    let mut n = 0usize;

    for dns in dns_names {
        // [2] IMPLICIT IA5String
        put_general_name(&mut names, &mut n, 0x82, dns.as_bytes())?;
    }
    for ip in ip_addrs {
        // [7] IMPLICIT OCTET STRING (4 bytes for IPv4, 16 for IPv6)
        match ip {
            IpAddr::V4(v4) => put_general_name(&mut names, &mut n, 0x87, &v4.octets())?,
            IpAddr::V6(v6) => put_general_name(&mut names, &mut n, 0x87, &v6.octets())?,
        }
    }
    let names_len = n;

    // 2. Wrap outward, computing each length from the inside out.
    let gn_seq_len = 1 + asn1_len_size(names_len) + names_len; // 30 <names>
    let octet_len = 1 + asn1_len_size(gn_seq_len) + gn_seq_len; // 04 <gn_seq>
    let ext_content_len = SAN_OID.len() + octet_len;
    let ext_seq_len = 1 + asn1_len_size(ext_content_len) + ext_content_len; // 30 <oid+octet>
    let exts_seq_len = 1 + asn1_len_size(ext_seq_len) + ext_seq_len; // 30 <ext>
    let total = 1 + asn1_len_size(exts_seq_len) + exts_seq_len; // a3 <exts_seq>

    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    let mut o = 0usize;
    // [3] EXPLICIT
    out[o] = 0xa3;
    o += 1;
    o += write_asn1_len(exts_seq_len, &mut out[o..])?;
    // SEQUENCE OF Extension
    out[o] = 0x30;
    o += 1;
    o += write_asn1_len(ext_seq_len, &mut out[o..])?;
    // Extension SEQUENCE
    out[o] = 0x30;
    o += 1;
    o += write_asn1_len(ext_content_len, &mut out[o..])?;
    // extnID
    out[o..o + SAN_OID.len()].copy_from_slice(&SAN_OID);
    o += SAN_OID.len();
    // extnValue OCTET STRING
    out[o] = 0x04;
    o += 1;
    o += write_asn1_len(gn_seq_len, &mut out[o..])?;
    // GeneralNames SEQUENCE
    out[o] = 0x30;
    o += 1;
    o += write_asn1_len(names_len, &mut out[o..])?;
    out[o..o + names_len].copy_from_slice(&names[..names_len]);
    o += names_len;

    Ok(o)
}
