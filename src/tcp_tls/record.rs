//! TLS 1.3 record layer codec (RFC 8446 §5).

use crate::error::Error;

/// TLS record content types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// TLS record header (5 bytes).
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub legacy_version: u16,
    pub length: u16,
}

/// TLS 1.3 record header size.
pub const RECORD_HEADER_LEN: usize = 5;

/// Maximum TLS record payload (RFC 8446 §5.1).
pub const MAX_RECORD_PAYLOAD: usize = 16384 + 256; // plaintext + expansion

/// Encode a TLS record header.
pub fn encode_record_header(ct: ContentType, length: u16, buf: &mut [u8]) -> Result<usize, Error> {
    if buf.len() < RECORD_HEADER_LEN {
        return Err(Error::BufferTooSmall {
            needed: RECORD_HEADER_LEN,
        });
    }
    buf[0] = ct as u8;
    buf[1] = 0x03;
    buf[2] = 0x03; // legacy_record_version = TLS 1.2
    buf[3] = (length >> 8) as u8;
    buf[4] = (length & 0xff) as u8;
    Ok(RECORD_HEADER_LEN)
}

/// Decode a TLS record header from exactly 5 bytes.
pub fn decode_record_header(data: &[u8]) -> Result<RecordHeader, Error> {
    if data.len() < RECORD_HEADER_LEN {
        return Err(Error::BufferTooSmall {
            needed: RECORD_HEADER_LEN,
        });
    }
    let content_type = ContentType::from_byte(data[0]).ok_or(Error::Tls)?;
    let legacy_version = ((data[1] as u16) << 8) | (data[2] as u16);
    let length = ((data[3] as u16) << 8) | (data[4] as u16);
    Ok(RecordHeader {
        content_type,
        legacy_version,
        length,
    })
}

/// Build a nonce for AEAD: iv XOR padded_sequence_number (RFC 8446 §5.3).
pub fn build_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    // XOR the last 8 bytes of the IV with the sequence number
    for i in 0..8 {
        nonce[12 - 8 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Encrypt a TLS record in-place.
///
/// `buf` layout: `[plaintext | content_type_byte | <space for tag>]`
/// - `payload_len` is the plaintext length (not including inner content type)
/// - The inner content type byte is at `buf[payload_len]`
/// - After encryption: `buf[..payload_len + 1 + TAG_LEN]` contains ciphertext + tag
///
/// Returns total ciphertext length (payload + 1 inner CT + TAG_LEN).
pub fn seal_record<A: crate::crypto::Aead>(
    aead: &A,
    nonce: &[u8; 12],
    buf: &mut [u8],
    payload_len: usize,
    inner_content_type: ContentType,
) -> Result<usize, Error> {
    // Write inner content type after plaintext
    let inner_len = payload_len + 1; // plaintext + inner CT byte
    if buf.len() < inner_len + A::TAG_LEN {
        return Err(Error::BufferTooSmall {
            needed: inner_len + A::TAG_LEN,
        });
    }
    buf[payload_len] = inner_content_type as u8;

    // AAD is the record header for the outer record (content_type=ApplicationData)
    let outer_len = (inner_len + A::TAG_LEN) as u16;
    let aad = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03, // TLS 1.2
        (outer_len >> 8) as u8,
        (outer_len & 0xff) as u8,
    ];

    let ciphertext_len = aead.seal_in_place(nonce, &aad, buf, inner_len)?;
    Ok(ciphertext_len)
}

/// Decrypt a TLS record in-place.
///
/// `buf[..ciphertext_len]` contains the encrypted record payload (including tag).
/// After decryption: `buf[..plaintext_len]` contains plaintext, and the inner
/// content type is the last non-zero byte.
///
/// Returns `(plaintext_len, inner_content_type)`.
pub fn open_record<A: crate::crypto::Aead>(
    aead: &A,
    nonce: &[u8; 12],
    buf: &mut [u8],
    ciphertext_len: usize,
    record_header_bytes: &[u8; 5],
) -> Result<(usize, ContentType), Error> {
    let plaintext_len = aead.open_in_place(nonce, record_header_bytes, buf, ciphertext_len)?;

    // Find inner content type: scan backwards for first non-zero byte (RFC 8446 §5.4)
    let mut inner_ct_pos = plaintext_len;
    while inner_ct_pos > 0 && buf[inner_ct_pos - 1] == 0 {
        inner_ct_pos -= 1;
    }
    if inner_ct_pos == 0 {
        return Err(Error::Tls); // No content type found
    }
    let inner_ct = ContentType::from_byte(buf[inner_ct_pos - 1]).ok_or(Error::Tls)?;
    let data_len = inner_ct_pos - 1;

    Ok((data_len, inner_ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_header_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_record_header(ContentType::Handshake, 42, &mut buf).unwrap();
        assert_eq!(n, 5);
        let hdr = decode_record_header(&buf[..5]).unwrap();
        assert_eq!(hdr.content_type, ContentType::Handshake);
        assert_eq!(hdr.legacy_version, 0x0303);
        assert_eq!(hdr.length, 42);
    }

    #[test]
    fn nonce_construction() {
        let iv = [0u8; 12];
        let nonce = build_nonce(&iv, 0);
        assert_eq!(nonce, [0u8; 12]);

        let nonce1 = build_nonce(&iv, 1);
        assert_eq!(nonce1[11], 1);
        assert_eq!(nonce1[10], 0);

        let iv2 = [0xff; 12];
        let nonce2 = build_nonce(&iv2, 0);
        assert_eq!(nonce2, [0xff; 12]);
    }

    #[test]
    fn decode_invalid_content_type() {
        let data = [0xff, 0x03, 0x03, 0x00, 0x01];
        assert!(decode_record_header(&data).is_err());
    }

    #[test]
    fn decode_too_short() {
        let data = [0x17, 0x03, 0x03, 0x00];
        assert!(decode_record_header(&data).is_err());
    }
}
