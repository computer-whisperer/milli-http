//! TLS 1.3 extension encoding and decoding for QUIC.
//!
//! Extension format: type (2 bytes) + length (2 bytes) + data.

use crate::error::Error;
use crate::tls::transport_params::TransportParams;

// Extension type codes
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_QUIC_TRANSPORT_PARAMS: u16 = 0x0039;

// Named group for X25519
const GROUP_X25519: u16 = 0x001d;

/// Parsed extensions from ServerHello.
pub struct ServerHelloExtensions {
    /// Selected TLS version (should be 0x0304 for TLS 1.3).
    pub selected_version: u16,
    /// Server's X25519 public key from key_share extension.
    pub key_share: Option<[u8; 32]>,
}

/// Parsed extensions from EncryptedExtensions.
pub struct EncryptedExtensionsData {
    /// Selected ALPN protocol.
    pub alpn: Option<heapless::Vec<u8, 16>>,
    /// Peer's QUIC transport parameters.
    pub transport_params: Option<TransportParams>,
}

/// Parsed extensions from ClientHello.
pub struct ClientHelloExtensions {
    /// Client's X25519 public key from key_share.
    pub key_share: Option<[u8; 32]>,
    /// Supported versions list (true if TLS 1.3 is included).
    pub supports_tls13: bool,
    /// ALPN protocols offered by the client.
    pub alpn_protocols: heapless::Vec<heapless::Vec<u8, 16>, 4>,
    /// Client's QUIC transport parameters.
    pub transport_params: Option<TransportParams>,
}

/// Write a 2-byte big-endian value.
fn put_u16(buf: &mut [u8], off: &mut usize, val: u16) -> Result<(), Error> {
    if buf.len() < *off + 2 {
        return Err(Error::BufferTooSmall { needed: *off + 2 });
    }
    buf[*off] = (val >> 8) as u8;
    buf[*off + 1] = (val & 0xFF) as u8;
    *off += 2;
    Ok(())
}

/// Read a 2-byte big-endian value.
fn get_u16(data: &[u8], off: &mut usize) -> Result<u16, Error> {
    if data.len() < *off + 2 {
        return Err(Error::Tls);
    }
    let val = u16::from_be_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Ok(val)
}

/// Encode ClientHello extensions into a buffer.
///
/// Includes: server_name, supported_versions, key_share,
/// signature_algorithms, ALPN, QUIC transport parameters.
pub fn encode_client_hello_extensions(
    server_name: &str,
    public_key: &[u8; 32],
    alpn: &[&[u8]],
    transport_params: Option<&TransportParams>,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut off = 0;

    // --- server_name (SNI) ---
    if !server_name.is_empty() {
        let name_bytes = server_name.as_bytes();
        // ServerNameList: list_length(2) + type(1) + name_length(2) + name
        let sni_data_len = 2 + 1 + 2 + name_bytes.len();
        put_u16(buf, &mut off, EXT_SERVER_NAME)?;
        put_u16(buf, &mut off, sni_data_len as u16)?;
        // ServerNameList length
        put_u16(buf, &mut off, (1 + 2 + name_bytes.len()) as u16)?;
        // HostName type = 0
        if buf.len() < off + 1 {
            return Err(Error::BufferTooSmall { needed: off + 1 });
        }
        buf[off] = 0;
        off += 1;
        // HostName length
        put_u16(buf, &mut off, name_bytes.len() as u16)?;
        // HostName
        if buf.len() < off + name_bytes.len() {
            return Err(Error::BufferTooSmall {
                needed: off + name_bytes.len(),
            });
        }
        buf[off..off + name_bytes.len()].copy_from_slice(name_bytes);
        off += name_bytes.len();
    }

    // --- supported_versions ---
    // For ClientHello: list_length(1) + version(2)
    put_u16(buf, &mut off, EXT_SUPPORTED_VERSIONS)?;
    put_u16(buf, &mut off, 3)?; // extension data length
    if buf.len() < off + 3 {
        return Err(Error::BufferTooSmall { needed: off + 3 });
    }
    buf[off] = 2; // list length
    off += 1;
    buf[off] = 0x03;
    buf[off + 1] = 0x04; // TLS 1.3
    off += 2;

    // --- key_share ---
    // client_shares: length(2) + KeyShareEntry(group(2) + key_length(2) + key(32))
    let ks_entry_len = 2 + 2 + 32; // group + key_exchange_length + key
    put_u16(buf, &mut off, EXT_KEY_SHARE)?;
    put_u16(buf, &mut off, (2 + ks_entry_len) as u16)?; // extension data length
    put_u16(buf, &mut off, ks_entry_len as u16)?; // client_shares length
    put_u16(buf, &mut off, GROUP_X25519)?;
    put_u16(buf, &mut off, 32)?; // key length
    if buf.len() < off + 32 {
        return Err(Error::BufferTooSmall { needed: off + 32 });
    }
    buf[off..off + 32].copy_from_slice(public_key);
    off += 32;

    // --- signature_algorithms ---
    // We advertise: Ed25519(0x0807), ECDSA-SHA256(0x0403), RSA-PSS-SHA256(0x0804)
    let sig_algs: [u16; 3] = [0x0807, 0x0403, 0x0804];
    let sig_algs_list_len = sig_algs.len() * 2;
    put_u16(buf, &mut off, EXT_SIGNATURE_ALGORITHMS)?;
    put_u16(buf, &mut off, (2 + sig_algs_list_len) as u16)?;
    put_u16(buf, &mut off, sig_algs_list_len as u16)?;
    for &alg in &sig_algs {
        put_u16(buf, &mut off, alg)?;
    }

    // --- ALPN ---
    if !alpn.is_empty() {
        // protocol_name_list: length(2) + entries(length_byte + protocol)
        let mut list_len = 0usize;
        for proto in alpn {
            list_len += 1 + proto.len();
        }
        put_u16(buf, &mut off, EXT_ALPN)?;
        put_u16(buf, &mut off, (2 + list_len) as u16)?;
        put_u16(buf, &mut off, list_len as u16)?;
        for proto in alpn {
            if buf.len() < off + 1 + proto.len() {
                return Err(Error::BufferTooSmall {
                    needed: off + 1 + proto.len(),
                });
            }
            buf[off] = proto.len() as u8;
            off += 1;
            buf[off..off + proto.len()].copy_from_slice(proto);
            off += proto.len();
        }
    }

    // --- QUIC transport parameters (skipped in TCP mode) ---
    if let Some(tp) = transport_params {
        let mut tp_buf = [0u8; 256];
        let tp_len = tp.encode(&mut tp_buf)?;
        put_u16(buf, &mut off, EXT_QUIC_TRANSPORT_PARAMS)?;
        put_u16(buf, &mut off, tp_len as u16)?;
        if buf.len() < off + tp_len {
            return Err(Error::BufferTooSmall {
                needed: off + tp_len,
            });
        }
        buf[off..off + tp_len].copy_from_slice(&tp_buf[..tp_len]);
        off += tp_len;
    }

    Ok(off)
}

/// Parse ServerHello extensions.
pub fn parse_server_hello_extensions(data: &[u8]) -> Result<ServerHelloExtensions, Error> {
    let mut result = ServerHelloExtensions {
        selected_version: 0,
        key_share: None,
    };

    let mut off = 0;
    while off + 4 <= data.len() {
        let ext_type = get_u16(data, &mut off)?;
        let ext_len = get_u16(data, &mut off)? as usize;

        if off + ext_len > data.len() {
            return Err(Error::Tls);
        }
        let ext_data = &data[off..off + ext_len];
        off += ext_len;

        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                // ServerHello: just the selected version (2 bytes)
                if ext_data.len() < 2 {
                    return Err(Error::Tls);
                }
                result.selected_version = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            }
            EXT_KEY_SHARE => {
                // ServerHello KeyShareEntry: group(2) + key_length(2) + key
                if ext_data.len() < 4 {
                    return Err(Error::Tls);
                }
                let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                if group != GROUP_X25519 || key_len != 32 {
                    return Err(Error::Tls);
                }
                if ext_data.len() < 4 + 32 {
                    return Err(Error::Tls);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&ext_data[4..36]);
                result.key_share = Some(key);
            }
            _ => {
                // Ignore unknown extensions in ServerHello
            }
        }
    }

    Ok(result)
}

/// Parse EncryptedExtensions body (already extracted by parse_encrypted_extensions).
pub fn parse_encrypted_extensions_data(data: &[u8]) -> Result<EncryptedExtensionsData, Error> {
    let mut result = EncryptedExtensionsData {
        alpn: None,
        transport_params: None,
    };

    let mut off = 0;
    while off + 4 <= data.len() {
        let ext_type = get_u16(data, &mut off)?;
        let ext_len = get_u16(data, &mut off)? as usize;

        if off + ext_len > data.len() {
            return Err(Error::Tls);
        }
        let ext_data = &data[off..off + ext_len];
        off += ext_len;

        match ext_type {
            EXT_ALPN => {
                // protocol_name_list: length(2) + entries
                if ext_data.len() < 2 {
                    return Err(Error::Tls);
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if 2 + list_len > ext_data.len() {
                    return Err(Error::Tls);
                }
                // Server selects exactly one protocol
                let list = &ext_data[2..2 + list_len];
                if list.is_empty() {
                    return Err(Error::Tls);
                }
                let proto_len = list[0] as usize;
                if 1 + proto_len > list.len() {
                    return Err(Error::Tls);
                }
                let mut alpn = heapless::Vec::new();
                for &b in &list[1..1 + proto_len] {
                    alpn.push(b).map_err(|_| Error::Tls)?;
                }
                result.alpn = Some(alpn);
            }
            EXT_QUIC_TRANSPORT_PARAMS => {
                result.transport_params = Some(TransportParams::decode(ext_data)?);
            }
            _ => {
                // Ignore unknown extensions
            }
        }
    }

    Ok(result)
}

/// Parse ClientHello extensions.
pub fn parse_client_hello_extensions(data: &[u8]) -> Result<ClientHelloExtensions, Error> {
    let mut result = ClientHelloExtensions {
        key_share: None,
        supports_tls13: false,
        alpn_protocols: heapless::Vec::new(),
        transport_params: None,
    };

    let mut off = 0;
    while off + 4 <= data.len() {
        let ext_type = get_u16(data, &mut off)?;
        let ext_len = get_u16(data, &mut off)? as usize;

        if off + ext_len > data.len() {
            return Err(Error::Tls);
        }
        let ext_data = &data[off..off + ext_len];
        off += ext_len;

        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                // ClientHello: list_length(1) + versions
                if ext_data.is_empty() {
                    return Err(Error::Tls);
                }
                let list_len = ext_data[0] as usize;
                if 1 + list_len > ext_data.len() {
                    return Err(Error::Tls);
                }
                let mut voff = 1;
                while voff + 1 < 1 + list_len {
                    let ver = u16::from_be_bytes([ext_data[voff], ext_data[voff + 1]]);
                    if ver == 0x0304 {
                        result.supports_tls13 = true;
                    }
                    voff += 2;
                }
            }
            EXT_KEY_SHARE => {
                // ClientHello key_share: client_shares_length(2) + KeyShareEntry list
                if ext_data.len() < 2 {
                    return Err(Error::Tls);
                }
                let shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if 2 + shares_len > ext_data.len() {
                    return Err(Error::Tls);
                }
                let mut soff = 2;
                while soff + 4 <= 2 + shares_len {
                    let group = u16::from_be_bytes([ext_data[soff], ext_data[soff + 1]]);
                    let key_len =
                        u16::from_be_bytes([ext_data[soff + 2], ext_data[soff + 3]]) as usize;
                    soff += 4;
                    if soff + key_len > 2 + shares_len {
                        return Err(Error::Tls);
                    }
                    if group == GROUP_X25519 && key_len == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ext_data[soff..soff + 32]);
                        result.key_share = Some(key);
                    }
                    soff += key_len;
                }
            }
            EXT_ALPN => {
                // protocol_name_list: length(2) + entries
                if ext_data.len() < 2 {
                    return Err(Error::Tls);
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if 2 + list_len > ext_data.len() {
                    return Err(Error::Tls);
                }
                let mut aoff = 2;
                while aoff < 2 + list_len {
                    let proto_len = ext_data[aoff] as usize;
                    aoff += 1;
                    if aoff + proto_len > 2 + list_len {
                        return Err(Error::Tls);
                    }
                    let mut proto = heapless::Vec::new();
                    for &b in &ext_data[aoff..aoff + proto_len] {
                        proto.push(b).map_err(|_| Error::Tls)?;
                    }
                    result.alpn_protocols.push(proto).map_err(|_| Error::Tls)?;
                    aoff += proto_len;
                }
            }
            EXT_QUIC_TRANSPORT_PARAMS => {
                result.transport_params = Some(TransportParams::decode(ext_data)?);
            }
            _ => {
                // Ignore unknown extensions (SNI, signature_algorithms, etc.)
            }
        }
    }

    Ok(result)
}

/// Encode ServerHello extensions.
///
/// Includes: supported_versions (TLS 1.3) and key_share (X25519).
pub fn encode_server_hello_extensions(
    public_key: &[u8; 32],
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut off = 0;

    // --- supported_versions ---
    // ServerHello: just the selected version (2 bytes), no list length byte
    put_u16(buf, &mut off, EXT_SUPPORTED_VERSIONS)?;
    put_u16(buf, &mut off, 2)?; // extension data length
    put_u16(buf, &mut off, 0x0304)?; // TLS 1.3

    // --- key_share ---
    // ServerHello KeyShareEntry: group(2) + key_length(2) + key(32) = 36
    let entry_len = 2 + 2 + 32;
    put_u16(buf, &mut off, EXT_KEY_SHARE)?;
    put_u16(buf, &mut off, entry_len as u16)?;
    put_u16(buf, &mut off, GROUP_X25519)?;
    put_u16(buf, &mut off, 32)?;
    if buf.len() < off + 32 {
        return Err(Error::BufferTooSmall { needed: off + 32 });
    }
    buf[off..off + 32].copy_from_slice(public_key);
    off += 32;

    Ok(off)
}

/// Encode EncryptedExtensions data for the server.
///
/// Includes: ALPN (selected protocol) and QUIC transport parameters.
pub fn encode_encrypted_extensions_data(
    selected_alpn: &[u8],
    transport_params: Option<&TransportParams>,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut off = 0;

    // --- ALPN ---
    if !selected_alpn.is_empty() {
        // Server sends exactly one protocol
        let list_len = 1 + selected_alpn.len();
        put_u16(buf, &mut off, EXT_ALPN)?;
        put_u16(buf, &mut off, (2 + list_len) as u16)?; // extension data length
        put_u16(buf, &mut off, list_len as u16)?; // list length
        if buf.len() < off + 1 + selected_alpn.len() {
            return Err(Error::BufferTooSmall {
                needed: off + 1 + selected_alpn.len(),
            });
        }
        buf[off] = selected_alpn.len() as u8;
        off += 1;
        buf[off..off + selected_alpn.len()].copy_from_slice(selected_alpn);
        off += selected_alpn.len();
    }

    // --- QUIC transport parameters (skipped in TCP mode) ---
    if let Some(tp) = transport_params {
        let mut tp_buf = [0u8; 256];
        let tp_len = tp.encode(&mut tp_buf)?;
        put_u16(buf, &mut off, EXT_QUIC_TRANSPORT_PARAMS)?;
        put_u16(buf, &mut off, tp_len as u16)?;
        if buf.len() < off + tp_len {
            return Err(Error::BufferTooSmall {
                needed: off + tp_len,
            });
        }
        buf[off..off + tp_len].copy_from_slice(&tp_buf[..tp_len]);
        off += tp_len;
    }

    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_client_hello_extensions_basic() {
        let params = TransportParams::default_params();
        let public_key = [0x42u8; 32];
        let mut buf = [0u8; 1024];
        let len = encode_client_hello_extensions(
            "example.com",
            &public_key,
            &[b"h3"],
            Some(&params),
            &mut buf,
        )
        .unwrap();
        assert!(len > 0);

        // Parse the extensions to verify they're well-formed
        // Walk through and check we find the expected extension types
        let mut off = 0;
        let mut found_sni = false;
        let mut found_versions = false;
        let mut found_key_share = false;
        let mut found_sig_algs = false;
        let mut found_alpn = false;
        let mut found_tp = false;

        while off + 4 <= len {
            let ext_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let ext_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            off += 4;
            match ext_type {
                EXT_SERVER_NAME => found_sni = true,
                EXT_SUPPORTED_VERSIONS => found_versions = true,
                EXT_KEY_SHARE => found_key_share = true,
                EXT_SIGNATURE_ALGORITHMS => found_sig_algs = true,
                EXT_ALPN => found_alpn = true,
                EXT_QUIC_TRANSPORT_PARAMS => found_tp = true,
                _ => {}
            }
            off += ext_len;
        }

        assert!(found_sni, "SNI extension missing");
        assert!(found_versions, "supported_versions extension missing");
        assert!(found_key_share, "key_share extension missing");
        assert!(found_sig_algs, "signature_algorithms extension missing");
        assert!(found_alpn, "ALPN extension missing");
        assert!(found_tp, "QUIC transport parameters extension missing");
    }

    #[test]
    fn parse_server_hello_extensions_basic() {
        // Build supported_versions + key_share extensions
        let mut data = [0u8; 128];
        let mut off = 0;

        // supported_versions: type=0x002b, length=2, value=0x0304
        put_u16(&mut data, &mut off, EXT_SUPPORTED_VERSIONS).unwrap();
        put_u16(&mut data, &mut off, 2).unwrap();
        data[off] = 0x03;
        data[off + 1] = 0x04;
        off += 2;

        // key_share: type=0x0033, length=2+2+32=36
        put_u16(&mut data, &mut off, EXT_KEY_SHARE).unwrap();
        put_u16(&mut data, &mut off, 36).unwrap();
        put_u16(&mut data, &mut off, GROUP_X25519).unwrap();
        put_u16(&mut data, &mut off, 32).unwrap();
        let server_key = [0xBB; 32];
        data[off..off + 32].copy_from_slice(&server_key);
        off += 32;

        let parsed = parse_server_hello_extensions(&data[..off]).unwrap();
        assert_eq!(parsed.selected_version, 0x0304);
        assert_eq!(parsed.key_share.unwrap(), server_key);
    }

    #[test]
    fn parse_encrypted_extensions_data_alpn() {
        // Build ALPN extension: type=0x0010
        let mut data = [0u8; 64];
        let mut off = 0;

        put_u16(&mut data, &mut off, EXT_ALPN).unwrap();
        // ALPN data: list_length(2) + proto_length(1) + "h3"(2) = 5
        put_u16(&mut data, &mut off, 5).unwrap();
        put_u16(&mut data, &mut off, 3).unwrap(); // list length = 3
        data[off] = 2; // "h3" length
        off += 1;
        data[off] = b'h';
        data[off + 1] = b'3';
        off += 2;

        let parsed = parse_encrypted_extensions_data(&data[..off]).unwrap();
        assert_eq!(parsed.alpn.as_ref().unwrap().as_slice(), b"h3");
    }

    #[test]
    fn parse_encrypted_extensions_data_transport_params() {
        let params = TransportParams::default_params();
        let mut tp_buf = [0u8; 256];
        let tp_len = params.encode(&mut tp_buf).unwrap();

        let mut data = [0u8; 512];
        let mut off = 0;

        put_u16(&mut data, &mut off, EXT_QUIC_TRANSPORT_PARAMS).unwrap();
        put_u16(&mut data, &mut off, tp_len as u16).unwrap();
        data[off..off + tp_len].copy_from_slice(&tp_buf[..tp_len]);
        off += tp_len;

        let parsed = parse_encrypted_extensions_data(&data[..off]).unwrap();
        assert_eq!(parsed.transport_params.unwrap(), params);
    }

    #[test]
    fn no_sni_when_empty() {
        let params = TransportParams::default_params();
        let public_key = [0x42u8; 32];
        let mut buf = [0u8; 1024];
        let len =
            encode_client_hello_extensions("", &public_key, &[b"h3"], Some(&params), &mut buf)
                .unwrap();

        // Walk through and verify no SNI
        let mut off = 0;
        while off + 4 <= len {
            let ext_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let ext_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            off += 4;
            assert_ne!(ext_type, EXT_SERVER_NAME, "SNI should not be present");
            off += ext_len;
        }
    }

    #[test]
    fn parse_client_hello_extensions_basic() {
        let params = TransportParams::default_params();
        let public_key = [0x42u8; 32];
        let mut buf = [0u8; 1024];
        let len = encode_client_hello_extensions(
            "example.com",
            &public_key,
            &[b"h3", b"hq-29"],
            Some(&params),
            &mut buf,
        )
        .unwrap();

        let parsed = parse_client_hello_extensions(&buf[..len]).unwrap();
        assert!(parsed.supports_tls13);
        assert_eq!(parsed.key_share.unwrap(), public_key);
        assert_eq!(parsed.alpn_protocols.len(), 2);
        assert_eq!(parsed.alpn_protocols[0].as_slice(), b"h3");
        assert_eq!(parsed.alpn_protocols[1].as_slice(), b"hq-29");
        assert!(parsed.transport_params.is_some());
        assert_eq!(parsed.transport_params.unwrap(), params);
    }

    #[test]
    fn encode_parse_server_hello_extensions_roundtrip() {
        let public_key = [0xBB; 32];
        let mut buf = [0u8; 256];
        let len = encode_server_hello_extensions(&public_key, &mut buf).unwrap();

        let parsed = parse_server_hello_extensions(&buf[..len]).unwrap();
        assert_eq!(parsed.selected_version, 0x0304);
        assert_eq!(parsed.key_share.unwrap(), public_key);
    }

    #[test]
    fn encode_parse_encrypted_extensions_data_roundtrip() {
        let params = TransportParams::default_params();
        let mut buf = [0u8; 512];
        let len = encode_encrypted_extensions_data(b"h3", Some(&params), &mut buf).unwrap();

        let parsed = parse_encrypted_extensions_data(&buf[..len]).unwrap();
        assert_eq!(parsed.alpn.as_ref().unwrap().as_slice(), b"h3");
        assert_eq!(parsed.transport_params.unwrap(), params);
    }
}
