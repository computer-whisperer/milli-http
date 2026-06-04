//! TLS 1.3 handshake message encoding and decoding.
//!
//! Handshake message format:
//!   HandshakeType (1 byte)
//!   Length (3 bytes, big-endian)
//!   Body (Length bytes)

use crate::error::Error;

/// TLS handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

impl HandshakeType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            8 => Some(Self::EncryptedExtensions),
            11 => Some(Self::Certificate),
            15 => Some(Self::CertificateVerify),
            20 => Some(Self::Finished),
            _ => None,
        }
    }
}

/// TLS cipher suites we support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsChacha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn to_u16(self) -> u16 {
        match self {
            Self::TlsAes128GcmSha256 => 0x1301,
            Self::TlsChacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x1301 => Some(Self::TlsAes128GcmSha256),
            0x1303 => Some(Self::TlsChacha20Poly1305Sha256),
            _ => None,
        }
    }
}

/// Parsed ClientHello message.
pub struct ClientHello<'a> {
    pub random: &'a [u8; 32],
    pub session_id: &'a [u8],
    pub cipher_suites: &'a [u8],
    pub extensions: &'a [u8],
}

/// Parsed ServerHello message.
pub struct ServerHello<'a> {
    pub random: &'a [u8; 32],
    pub session_id: &'a [u8],
    pub cipher_suite: CipherSuite,
    pub extensions: &'a [u8],
}

/// Parsed Certificate message.
pub struct CertificatePayload<'a> {
    /// The certificate request context (usually empty for server certs).
    pub context: &'a [u8],
    /// Raw certificate entries data (list of CertificateEntry).
    pub entries: &'a [u8],
}

/// A single certificate entry from the Certificate message.
pub struct CertificateEntry<'a> {
    /// DER-encoded certificate data.
    pub cert_data: &'a [u8],
    /// Extensions (usually empty).
    pub extensions: &'a [u8],
}

/// Parsed CertificateVerify message.
pub struct CertificateVerify<'a> {
    pub algorithm: u16,
    pub signature: &'a [u8],
}

/// Write the 4-byte handshake header (type + 3-byte length).
fn write_handshake_header(
    msg_type: HandshakeType,
    body_len: usize,
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() < 4 {
        return Err(Error::BufferTooSmall { needed: 4 });
    }
    out[0] = msg_type as u8;
    let len = body_len as u32;
    out[1] = ((len >> 16) & 0xFF) as u8;
    out[2] = ((len >> 8) & 0xFF) as u8;
    out[3] = (len & 0xFF) as u8;
    Ok(())
}

/// Read the handshake header: returns (type_byte, body_length, header_consumed=4).
pub fn read_handshake_header(data: &[u8]) -> Result<(u8, usize), Error> {
    if data.len() < 4 {
        return Err(Error::Tls);
    }
    let msg_type = data[0];
    let length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    Ok((msg_type, length))
}

/// Encode a ClientHello message.
///
/// Format:
///   - ProtocolVersion: 0x0303 (TLS 1.2 for compatibility)
///   - Random: 32 bytes
///   - SessionID: length-prefixed (1 byte length)
///   - CipherSuites: length-prefixed (2 byte length)
///   - CompressionMethods: length-prefixed (1 byte length, always `[0]`)
///   - Extensions: length-prefixed (2 byte length)
pub fn encode_client_hello(
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suites: &[CipherSuite],
    extensions_buf: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    // Calculate body size:
    // 2 (version) + 32 (random) + 1 (session_id len) + session_id.len()
    // + 2 (cipher_suites len) + cipher_suites.len() * 2
    // + 2 (compression: length byte + null method)
    // + 2 (extensions len) + extensions_buf.len()
    let cs_len = cipher_suites.len() * 2;
    let body_len = 2 + 32 + 1 + session_id.len() + 2 + cs_len + 2 + 2 + extensions_buf.len();
    let total = 4 + body_len;

    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    // Handshake header
    write_handshake_header(HandshakeType::ClientHello, body_len, out)?;
    let mut off = 4;

    // ProtocolVersion: legacy TLS 1.2
    out[off] = 0x03;
    out[off + 1] = 0x03;
    off += 2;

    // Random
    out[off..off + 32].copy_from_slice(random);
    off += 32;

    // Session ID
    out[off] = session_id.len() as u8;
    off += 1;
    if !session_id.is_empty() {
        out[off..off + session_id.len()].copy_from_slice(session_id);
        off += session_id.len();
    }

    // Cipher suites
    out[off] = ((cs_len >> 8) & 0xFF) as u8;
    out[off + 1] = (cs_len & 0xFF) as u8;
    off += 2;
    for cs in cipher_suites {
        let v = cs.to_u16();
        out[off] = (v >> 8) as u8;
        out[off + 1] = (v & 0xFF) as u8;
        off += 2;
    }

    // Compression methods: 1 byte length, 1 null method
    out[off] = 1;
    out[off + 1] = 0;
    off += 2;

    // Extensions
    let ext_len = extensions_buf.len();
    out[off] = ((ext_len >> 8) & 0xFF) as u8;
    out[off + 1] = (ext_len & 0xFF) as u8;
    off += 2;
    out[off..off + ext_len].copy_from_slice(extensions_buf);
    off += ext_len;

    Ok(off)
}

/// Parse a ServerHello message body (after the 4-byte handshake header).
pub fn parse_server_hello(data: &[u8]) -> Result<ServerHello<'_>, Error> {
    if data.len() < 2 + 32 + 1 {
        return Err(Error::Tls);
    }

    let mut off = 0;

    // ProtocolVersion (legacy, should be 0x0303)
    let _version = u16::from_be_bytes([data[off], data[off + 1]]);
    off += 2;

    // Random
    let random: &[u8; 32] = data[off..off + 32].try_into().map_err(|_| Error::Tls)?;
    off += 32;

    // Session ID
    let sid_len = data[off] as usize;
    off += 1;
    if off + sid_len > data.len() {
        return Err(Error::Tls);
    }
    let session_id = &data[off..off + sid_len];
    off += sid_len;

    // Cipher suite
    if off + 2 > data.len() {
        return Err(Error::Tls);
    }
    let cs_val = u16::from_be_bytes([data[off], data[off + 1]]);
    let cipher_suite = CipherSuite::from_u16(cs_val).ok_or(Error::Tls)?;
    off += 2;

    // Compression method (should be 0)
    if off >= data.len() {
        return Err(Error::Tls);
    }
    let _compression = data[off];
    off += 1;

    // Extensions
    let extensions = if off + 2 <= data.len() {
        let ext_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if off + ext_len > data.len() {
            return Err(Error::Tls);
        }
        &data[off..off + ext_len]
    } else {
        &[]
    };

    Ok(ServerHello {
        random,
        session_id,
        cipher_suite,
        extensions,
    })
}

/// Parse an EncryptedExtensions message body (after header).
/// Returns the raw extensions bytes.
pub fn parse_encrypted_extensions(data: &[u8]) -> Result<&[u8], Error> {
    if data.len() < 2 {
        return Err(Error::Tls);
    }
    let ext_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + ext_len > data.len() {
        return Err(Error::Tls);
    }
    Ok(&data[2..2 + ext_len])
}

/// Parse a Certificate message body (after header).
pub fn parse_certificate(data: &[u8]) -> Result<CertificatePayload<'_>, Error> {
    if data.is_empty() {
        return Err(Error::Tls);
    }

    let mut off = 0;

    // certificate_request_context
    let ctx_len = data[off] as usize;
    off += 1;
    if off + ctx_len > data.len() {
        return Err(Error::Tls);
    }
    let context = &data[off..off + ctx_len];
    off += ctx_len;

    // certificate_list (3-byte length prefix)
    if off + 3 > data.len() {
        return Err(Error::Tls);
    }
    let list_len =
        ((data[off] as usize) << 16) | ((data[off + 1] as usize) << 8) | (data[off + 2] as usize);
    off += 3;
    if off + list_len > data.len() {
        return Err(Error::Tls);
    }
    let entries = &data[off..off + list_len];

    Ok(CertificatePayload { context, entries })
}

/// Iterate over certificate entries in a CertificatePayload.
pub fn iter_certificate_entries(
    mut data: &[u8],
) -> impl Iterator<Item = Result<CertificateEntry<'_>, Error>> + '_ {
    core::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        if data.len() < 3 {
            let err = Err(Error::Tls);
            data = &[];
            return Some(err);
        }
        let cert_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
        data = &data[3..];
        if data.len() < cert_len {
            let err = Err(Error::Tls);
            data = &[];
            return Some(err);
        }
        let cert_data = &data[..cert_len];
        data = &data[cert_len..];

        // Extensions (2-byte length prefix)
        if data.len() < 2 {
            let err = Err(Error::Tls);
            data = &[];
            return Some(err);
        }
        let ext_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        data = &data[2..];
        if data.len() < ext_len {
            let err = Err(Error::Tls);
            data = &[];
            return Some(err);
        }
        let extensions = &data[..ext_len];
        data = &data[ext_len..];

        Some(Ok(CertificateEntry {
            cert_data,
            extensions,
        }))
    })
}

/// Parse a CertificateVerify message body (after header).
pub fn parse_certificate_verify(data: &[u8]) -> Result<CertificateVerify<'_>, Error> {
    if data.len() < 4 {
        return Err(Error::Tls);
    }

    let algorithm = u16::from_be_bytes([data[0], data[1]]);
    let sig_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    if 4 + sig_len > data.len() {
        return Err(Error::Tls);
    }

    Ok(CertificateVerify {
        algorithm,
        signature: &data[4..4 + sig_len],
    })
}

/// Parse a Finished message body (after header).
/// Returns the verify_data.
pub fn parse_finished(data: &[u8]) -> Result<&[u8], Error> {
    // For SHA-256, verify_data is 32 bytes
    if data.len() < 32 {
        return Err(Error::Tls);
    }
    Ok(&data[..32])
}

/// Parse a ClientHello message body (after the 4-byte handshake header).
pub fn parse_client_hello(data: &[u8]) -> Result<ClientHello<'_>, Error> {
    if data.len() < 2 + 32 + 1 {
        return Err(Error::Tls);
    }

    let mut off = 0;

    // ProtocolVersion (legacy, should be 0x0303)
    let _version = u16::from_be_bytes([data[off], data[off + 1]]);
    off += 2;

    // Random
    let random: &[u8; 32] = data[off..off + 32].try_into().map_err(|_| Error::Tls)?;
    off += 32;

    // Session ID
    let sid_len = data[off] as usize;
    off += 1;
    if off + sid_len > data.len() {
        return Err(Error::Tls);
    }
    let session_id = &data[off..off + sid_len];
    off += sid_len;

    // Cipher suites (2-byte length prefix)
    if off + 2 > data.len() {
        return Err(Error::Tls);
    }
    let cs_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    if off + cs_len > data.len() {
        return Err(Error::Tls);
    }
    let cipher_suites = &data[off..off + cs_len];
    off += cs_len;

    // Compression methods (1-byte length prefix)
    if off >= data.len() {
        return Err(Error::Tls);
    }
    let comp_len = data[off] as usize;
    off += 1;
    if off + comp_len > data.len() {
        return Err(Error::Tls);
    }
    // Skip compression methods
    off += comp_len;

    // Extensions
    let extensions = if off + 2 <= data.len() {
        let ext_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if off + ext_len > data.len() {
            return Err(Error::Tls);
        }
        &data[off..off + ext_len]
    } else {
        &[]
    };

    Ok(ClientHello {
        random,
        session_id,
        cipher_suites,
        extensions,
    })
}

/// Iterate over cipher suites in a ClientHello cipher_suites field.
/// The field is raw bytes: pairs of (u8, u8) representing u16 cipher suite IDs.
pub fn iter_cipher_suites(data: &[u8]) -> impl Iterator<Item = u16> + '_ {
    data.chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
}

/// Encode a ServerHello message.
///
/// Format:
///   - ProtocolVersion: 0x0303 (TLS 1.2 for compatibility)
///   - Random: 32 bytes
///   - SessionID: length-prefixed (1 byte length) — echoed from ClientHello
///   - CipherSuite: 2 bytes
///   - CompressionMethod: 1 byte (0 = null)
///   - Extensions: length-prefixed (2 byte length)
pub fn encode_server_hello(
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: CipherSuite,
    extensions_buf: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    // Body: 2 (version) + 32 (random) + 1 (sid len) + sid.len()
    //       + 2 (cipher suite) + 1 (compression)
    //       + 2 (ext len) + extensions_buf.len()
    let body_len = 2 + 32 + 1 + session_id.len() + 2 + 1 + 2 + extensions_buf.len();
    let total = 4 + body_len;

    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    // Handshake header
    write_handshake_header(HandshakeType::ServerHello, body_len, out)?;
    let mut off = 4;

    // ProtocolVersion: legacy TLS 1.2
    out[off] = 0x03;
    out[off + 1] = 0x03;
    off += 2;

    // Random
    out[off..off + 32].copy_from_slice(random);
    off += 32;

    // Session ID (echo client's)
    out[off] = session_id.len() as u8;
    off += 1;
    if !session_id.is_empty() {
        out[off..off + session_id.len()].copy_from_slice(session_id);
        off += session_id.len();
    }

    // Cipher suite
    let cs = cipher_suite.to_u16();
    out[off] = (cs >> 8) as u8;
    out[off + 1] = (cs & 0xFF) as u8;
    off += 2;

    // Compression method: null
    out[off] = 0;
    off += 1;

    // Extensions
    let ext_len = extensions_buf.len();
    out[off] = ((ext_len >> 8) & 0xFF) as u8;
    out[off + 1] = (ext_len & 0xFF) as u8;
    off += 2;
    out[off..off + ext_len].copy_from_slice(extensions_buf);
    off += ext_len;

    Ok(off)
}

/// Encode an EncryptedExtensions message.
///
/// `extensions_buf` is the already-encoded extensions data.
/// The body is simply: extensions_length(2) + extensions_data.
pub fn encode_encrypted_extensions(extensions_buf: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let body_len = 2 + extensions_buf.len();
    let total = 4 + body_len;

    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    write_handshake_header(HandshakeType::EncryptedExtensions, body_len, out)?;
    let mut off = 4;

    // Extensions list length
    let ext_len = extensions_buf.len();
    out[off] = ((ext_len >> 8) & 0xFF) as u8;
    out[off + 1] = (ext_len & 0xFF) as u8;
    off += 2;

    out[off..off + ext_len].copy_from_slice(extensions_buf);
    off += ext_len;

    Ok(off)
}

/// Encode a Certificate message with a single certificate.
///
/// Format:
///   - certificate_request_context length (1 byte) = 0
///   - certificate_list length (3 bytes)
///   - CertificateEntry:
///     - cert_data length (3 bytes)
///     - cert_data (DER bytes)
///     - extensions length (2 bytes) = 0
pub fn encode_certificate(cert_der: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    // Entry: 3 (cert_data_len) + cert_der.len() + 2 (ext_len)
    let entry_len = 3 + cert_der.len() + 2;
    // Body: 1 (context_len) + 3 (list_len) + entry_len
    let body_len = 1 + 3 + entry_len;
    let total = 4 + body_len;

    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    write_handshake_header(HandshakeType::Certificate, body_len, out)?;
    let mut off = 4;

    // certificate_request_context length = 0
    out[off] = 0;
    off += 1;

    // certificate_list length (3 bytes)
    out[off] = ((entry_len >> 16) & 0xFF) as u8;
    out[off + 1] = ((entry_len >> 8) & 0xFF) as u8;
    out[off + 2] = (entry_len & 0xFF) as u8;
    off += 3;

    // cert_data length (3 bytes)
    let cert_len = cert_der.len();
    out[off] = ((cert_len >> 16) & 0xFF) as u8;
    out[off + 1] = ((cert_len >> 8) & 0xFF) as u8;
    out[off + 2] = (cert_len & 0xFF) as u8;
    off += 3;

    // cert_data
    out[off..off + cert_len].copy_from_slice(cert_der);
    off += cert_len;

    // extensions length = 0
    out[off] = 0;
    out[off + 1] = 0;
    off += 2;

    Ok(off)
}

/// Encode a CertificateVerify message.
///
/// `algorithm` is the signature algorithm (e.g., 0x0807 for Ed25519).
/// `signature` is the signature bytes.
pub fn encode_certificate_verify(
    algorithm: u16,
    signature: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    // Body: 2 (algorithm) + 2 (sig_len) + signature.len()
    let body_len = 2 + 2 + signature.len();
    let total = 4 + body_len;

    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }

    write_handshake_header(HandshakeType::CertificateVerify, body_len, out)?;
    let mut off = 4;

    // Algorithm
    out[off] = (algorithm >> 8) as u8;
    out[off + 1] = (algorithm & 0xFF) as u8;
    off += 2;

    // Signature length
    let sig_len = signature.len();
    out[off] = ((sig_len >> 8) & 0xFF) as u8;
    out[off + 1] = (sig_len & 0xFF) as u8;
    off += 2;

    // Signature
    out[off..off + sig_len].copy_from_slice(signature);
    off += sig_len;

    Ok(off)
}

/// Encode a Finished message (header + verify_data).
pub fn encode_finished(verify_data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let total = 4 + verify_data.len();
    if out.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }
    write_handshake_header(HandshakeType::Finished, verify_data.len(), out)?;
    out[4..4 + verify_data.len()].copy_from_slice(verify_data);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_suite_roundtrip() {
        assert_eq!(
            CipherSuite::from_u16(CipherSuite::TlsAes128GcmSha256.to_u16()),
            Some(CipherSuite::TlsAes128GcmSha256)
        );
        assert_eq!(
            CipherSuite::from_u16(CipherSuite::TlsChacha20Poly1305Sha256.to_u16()),
            Some(CipherSuite::TlsChacha20Poly1305Sha256)
        );
        assert_eq!(CipherSuite::from_u16(0xFFFF), None);
    }

    #[test]
    fn handshake_type_roundtrip() {
        assert_eq!(HandshakeType::from_u8(1), Some(HandshakeType::ClientHello));
        assert_eq!(HandshakeType::from_u8(2), Some(HandshakeType::ServerHello));
        assert_eq!(
            HandshakeType::from_u8(8),
            Some(HandshakeType::EncryptedExtensions)
        );
        assert_eq!(HandshakeType::from_u8(11), Some(HandshakeType::Certificate));
        assert_eq!(
            HandshakeType::from_u8(15),
            Some(HandshakeType::CertificateVerify)
        );
        assert_eq!(HandshakeType::from_u8(20), Some(HandshakeType::Finished));
        assert_eq!(HandshakeType::from_u8(99), None);
    }

    #[test]
    fn encode_parse_client_hello() {
        let random = [0x42u8; 32];
        let session_id = [0u8; 0];
        let suites = [
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ];
        let extensions = [0xAA, 0xBB, 0xCC, 0xDD];

        let mut buf = [0u8; 512];
        let len =
            encode_client_hello(&random, &session_id, &suites, &extensions, &mut buf).unwrap();

        // Verify the handshake header
        assert_eq!(buf[0], HandshakeType::ClientHello as u8);
        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, 1);
        assert_eq!(body_len + 4, len);

        // Verify version
        assert_eq!(buf[4], 0x03);
        assert_eq!(buf[5], 0x03);

        // Verify random
        assert_eq!(&buf[6..38], &[0x42u8; 32]);

        // Verify session_id length = 0
        assert_eq!(buf[38], 0);

        // Verify cipher suites length = 4
        assert_eq!(buf[39], 0);
        assert_eq!(buf[40], 4);
        // First suite: 0x1301
        assert_eq!(buf[41], 0x13);
        assert_eq!(buf[42], 0x01);
        // Second suite: 0x1303
        assert_eq!(buf[43], 0x13);
        assert_eq!(buf[44], 0x03);

        // Compression methods: length=1, null=0
        assert_eq!(buf[45], 1);
        assert_eq!(buf[46], 0);

        // Extensions length = 4
        assert_eq!(buf[47], 0);
        assert_eq!(buf[48], 4);
        assert_eq!(&buf[49..53], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_server_hello_basic() {
        // Build a minimal ServerHello body
        let mut data = [0u8; 256];
        let mut off = 0;

        // Version
        data[off] = 0x03;
        data[off + 1] = 0x03;
        off += 2;

        // Random
        for i in 0..32 {
            data[off + i] = i as u8;
        }
        off += 32;

        // Session ID length = 0
        data[off] = 0;
        off += 1;

        // Cipher suite: TLS_AES_128_GCM_SHA256
        data[off] = 0x13;
        data[off + 1] = 0x01;
        off += 2;

        // Compression method: null
        data[off] = 0;
        off += 1;

        // Extensions length = 0
        data[off] = 0;
        data[off + 1] = 0;
        off += 2;

        let sh = parse_server_hello(&data[..off]).unwrap();
        assert_eq!(sh.cipher_suite, CipherSuite::TlsAes128GcmSha256);
        assert_eq!(sh.session_id.len(), 0);
        assert_eq!(sh.extensions.len(), 0);
        for i in 0..32 {
            assert_eq!(sh.random[i], i as u8);
        }
    }

    #[test]
    fn encode_parse_finished() {
        let verify_data = [0xAB; 32];
        let mut buf = [0u8; 64];
        let len = encode_finished(&verify_data, &mut buf).unwrap();
        assert_eq!(len, 36); // 4 header + 32 data

        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::Finished as u8);
        assert_eq!(body_len, 32);

        let vd = parse_finished(&buf[4..4 + body_len]).unwrap();
        assert_eq!(vd, &[0xAB; 32]);
    }

    #[test]
    fn parse_encrypted_extensions_basic() {
        // Extensions length = 4, then 4 bytes of data
        let data = [0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let ext = parse_encrypted_extensions(&data).unwrap();
        assert_eq!(ext, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn parse_certificate_verify_basic() {
        // Algorithm = 0x0807 (Ed25519), signature length = 4
        let data = [0x08, 0x07, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let cv = parse_certificate_verify(&data).unwrap();
        assert_eq!(cv.algorithm, 0x0807);
        assert_eq!(cv.signature, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_certificate_basic() {
        // Build a minimal Certificate message body
        let mut data = [0u8; 64];
        let mut off = 0;

        // certificate_request_context length = 0
        data[off] = 0;
        off += 1;

        // certificate_list length (3 bytes) = 12
        // One entry: 3 (cert_len) + 5 (cert_data) + 2 (ext_len) + 2 (ext) = 12
        data[off] = 0;
        data[off + 1] = 0;
        data[off + 2] = 12;
        off += 3;

        // cert_data_length (3 bytes) = 5
        data[off] = 0;
        data[off + 1] = 0;
        data[off + 2] = 5;
        off += 3;

        // cert_data = [1,2,3,4,5]
        data[off..off + 5].copy_from_slice(&[1, 2, 3, 4, 5]);
        off += 5;

        // extensions length = 2
        data[off] = 0;
        data[off + 1] = 2;
        off += 2;

        // extensions = [0xAA, 0xBB]
        data[off] = 0xAA;
        data[off + 1] = 0xBB;
        off += 2;

        let cert = parse_certificate(&data[..off]).unwrap();
        assert_eq!(cert.context.len(), 0);

        let mut count = 0;
        for entry in iter_certificate_entries(cert.entries) {
            let entry = entry.unwrap();
            if count == 0 {
                assert_eq!(entry.cert_data, &[1, 2, 3, 4, 5]);
                assert_eq!(entry.extensions, &[0xAA, 0xBB]);
            }
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn client_hello_buffer_too_small() {
        let random = [0u8; 32];
        let mut buf = [0u8; 4]; // Way too small
        let result = encode_client_hello(&random, &[], &[], &[], &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn parse_client_hello_basic() {
        // Encode a ClientHello, then parse it
        let random = [0x42u8; 32];
        let suites = [
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ];
        let extensions = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut buf = [0u8; 512];
        let len = encode_client_hello(&random, &[], &suites, &extensions, &mut buf).unwrap();

        // Parse the body (after header)
        let ch = parse_client_hello(&buf[4..len]).unwrap();
        assert_eq!(*ch.random, [0x42u8; 32]);
        assert_eq!(ch.session_id.len(), 0);
        assert_eq!(ch.extensions, &[0xAA, 0xBB, 0xCC, 0xDD]);

        // Check cipher suites
        let suites_found: heapless::Vec<u16, 8> = iter_cipher_suites(ch.cipher_suites).collect();
        assert_eq!(suites_found.len(), 2);
        assert_eq!(suites_found[0], 0x1301);
        assert_eq!(suites_found[1], 0x1303);
    }

    #[test]
    fn encode_parse_server_hello() {
        let random = [0xBB; 32];
        let extensions = [0x01, 0x02, 0x03];
        let mut buf = [0u8; 512];
        let len = encode_server_hello(
            &random,
            &[],
            CipherSuite::TlsAes128GcmSha256,
            &extensions,
            &mut buf,
        )
        .unwrap();

        // Verify header
        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerHello as u8);
        assert_eq!(body_len + 4, len);

        // Parse body
        let sh = parse_server_hello(&buf[4..len]).unwrap();
        assert_eq!(*sh.random, [0xBB; 32]);
        assert_eq!(sh.cipher_suite, CipherSuite::TlsAes128GcmSha256);
        assert_eq!(sh.extensions, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn encode_parse_encrypted_extensions_roundtrip() {
        let ext_data = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut buf = [0u8; 128];
        let len = encode_encrypted_extensions(&ext_data, &mut buf).unwrap();

        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::EncryptedExtensions as u8);

        let parsed_ext = parse_encrypted_extensions(&buf[4..4 + body_len]).unwrap();
        assert_eq!(parsed_ext, &ext_data);
    }

    #[test]
    fn encode_parse_certificate_roundtrip() {
        let cert_der = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut buf = [0u8; 256];
        let len = encode_certificate(&cert_der, &mut buf).unwrap();

        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::Certificate as u8);

        let cert = parse_certificate(&buf[4..4 + body_len]).unwrap();
        assert_eq!(cert.context.len(), 0);

        let mut count = 0;
        for entry in iter_certificate_entries(cert.entries) {
            let entry = entry.unwrap();
            if count == 0 {
                assert_eq!(entry.cert_data, &cert_der);
                assert_eq!(entry.extensions.len(), 0);
            }
            count += 1;
        }
        assert_eq!(count, 1);
    }

    // -----------------------------------------------------------------------
    // Phase 13: Edge case hardening tests for TLS messages
    // -----------------------------------------------------------------------

    #[test]
    fn parse_server_hello_truncated() {
        // Too short for version + random + session_id_len
        assert!(parse_server_hello(&[0x03, 0x03]).is_err());
        assert!(parse_server_hello(&[]).is_err());
    }

    #[test]
    fn parse_client_hello_truncated() {
        assert!(parse_client_hello(&[]).is_err());
        assert!(parse_client_hello(&[0x03]).is_err());
        // Just version + random but no session_id len
        let mut short = [0u8; 34];
        short[0] = 0x03;
        short[1] = 0x03;
        assert!(parse_client_hello(&short).is_err());
    }

    #[test]
    fn parse_encrypted_extensions_truncated() {
        assert!(parse_encrypted_extensions(&[]).is_err());
        assert!(parse_encrypted_extensions(&[0x00]).is_err());
        // Claims 10 bytes but only 2 available
        assert!(parse_encrypted_extensions(&[0x00, 0x0a]).is_err());
    }

    #[test]
    fn parse_certificate_empty() {
        assert!(parse_certificate(&[]).is_err());
    }

    #[test]
    fn parse_certificate_verify_truncated() {
        assert!(parse_certificate_verify(&[]).is_err());
        assert!(parse_certificate_verify(&[0x08]).is_err());
        assert!(parse_certificate_verify(&[0x08, 0x07, 0x00]).is_err());
        // Claims 10 byte signature but no data
        assert!(parse_certificate_verify(&[0x08, 0x07, 0x00, 0x0a]).is_err());
    }

    #[test]
    fn parse_finished_too_short() {
        assert!(parse_finished(&[]).is_err());
        assert!(parse_finished(&[0u8; 31]).is_err());
        // Exactly 32 bytes should succeed
        assert!(parse_finished(&[0u8; 32]).is_ok());
    }

    #[test]
    fn read_handshake_header_truncated() {
        assert!(read_handshake_header(&[]).is_err());
        assert!(read_handshake_header(&[0x01, 0x00]).is_err());
        assert!(read_handshake_header(&[0x01, 0x00, 0x00]).is_err());
        // Exactly 4 bytes: valid header
        let (msg_type, body_len) = read_handshake_header(&[0x01, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(msg_type, 1);
        assert_eq!(body_len, 0);
    }

    #[test]
    fn handshake_type_unknown_values() {
        assert_eq!(HandshakeType::from_u8(0), None);
        assert_eq!(HandshakeType::from_u8(3), None);
        assert_eq!(HandshakeType::from_u8(255), None);
    }

    #[test]
    fn cipher_suite_unknown_values() {
        assert_eq!(CipherSuite::from_u16(0x0000), None);
        assert_eq!(CipherSuite::from_u16(0x1302), None); // Not supported
        assert_eq!(CipherSuite::from_u16(0xFFFF), None);
    }

    #[test]
    fn encode_parse_client_hello_with_session_id() {
        let random = [0x42u8; 32];
        let session_id = [0x11, 0x22, 0x33, 0x44];
        let suites = [CipherSuite::TlsChacha20Poly1305Sha256];
        let extensions = [0xAA];

        let mut buf = [0u8; 512];
        let len =
            encode_client_hello(&random, &session_id, &suites, &extensions, &mut buf).unwrap();

        let ch = parse_client_hello(&buf[4..len]).unwrap();
        assert_eq!(ch.session_id, &session_id);
        assert_eq!(ch.extensions, &[0xAA]);
    }

    #[test]
    fn server_hello_unsupported_cipher_fails() {
        // Build a ServerHello with unsupported cipher suite 0x1302
        let mut data = [0u8; 256];
        let mut off = 0;
        data[off] = 0x03;
        data[off + 1] = 0x03;
        off += 2;
        off += 32; // random (zeros)
        data[off] = 0;
        off += 1; // session_id len
        data[off] = 0x13;
        data[off + 1] = 0x02;
        off += 2; // unsupported suite
        data[off] = 0;
        off += 1; // compression
        data[off] = 0;
        data[off + 1] = 0;
        off += 2; // extensions len

        assert!(parse_server_hello(&data[..off]).is_err());
    }

    #[test]
    fn iter_certificate_entries_empty() {
        let entries: &[u8] = &[];
        let count = iter_certificate_entries(entries).count();
        assert_eq!(count, 0);
    }

    #[test]
    fn iter_certificate_entries_truncated() {
        // Only 2 bytes (needs at least 3 for cert_data length)
        let entries: &[u8] = &[0x00, 0x01];
        let results: heapless::Vec<_, 4> = iter_certificate_entries(entries).collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn encode_parse_certificate_verify_roundtrip() {
        let signature = [0xAA; 64];
        let mut buf = [0u8; 256];
        let len = encode_certificate_verify(0x0807, &signature, &mut buf).unwrap();

        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateVerify as u8);

        let cv = parse_certificate_verify(&buf[4..4 + body_len]).unwrap();
        assert_eq!(cv.algorithm, 0x0807);
        assert_eq!(cv.signature, &signature);
    }
}
