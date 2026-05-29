//! Long header packet parsing and encoding (RFC 9000 section 17.2).

use crate::error::Error;
use crate::packet::{
    HandshakeHeader, InitialHeader, LongHeader, LongPacketType, PacketHeader, QUIC_VERSION_1,
    VersionNegotiationHeader,
};
use crate::varint::{decode_varint, encode_varint, varint_len};

/// Parse the common long header fields from a buffer.
///
/// Returns the parsed header and total bytes consumed. For version negotiation
/// packets (version == 0), returns a `VersionNegotiation` variant and consumes
/// the entire buffer.
pub fn parse_long_header(buf: &[u8]) -> Result<(PacketHeader<'_>, usize), Error> {
    // Minimum: 1 (first byte) + 4 (version) + 1 (dcid len) + 1 (scid len) = 7
    if buf.len() < 7 {
        return Err(Error::BufferTooSmall { needed: 7 });
    }

    let first_byte = buf[0];

    // Long header: form bit (bit 7) must be 1
    if first_byte & 0x80 == 0 {
        return Err(Error::Transport(
            crate::error::TransportError::ProtocolViolation,
        ));
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    let dcid_len = buf[5] as usize;
    let mut pos = 6;
    if pos + dcid_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + dcid_len,
        });
    }
    let dcid = &buf[pos..pos + dcid_len];
    pos += dcid_len;

    // Need one more byte for the SCID length. The DCID check above only
    // guarantees `pos <= buf.len()`, so a packet whose DCID fills the datagram
    // exactly would otherwise index out of bounds (remote panic / DoS).
    if pos >= buf.len() {
        return Err(Error::BufferTooSmall { needed: pos + 1 });
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + scid_len,
        });
    }
    let scid = &buf[pos..pos + scid_len];
    pos += scid_len;

    // Version Negotiation: version == 0
    if version == 0 {
        let supported_versions = &buf[pos..];
        return Ok((
            PacketHeader::VersionNegotiation(VersionNegotiationHeader {
                dcid,
                scid,
                supported_versions,
            }),
            buf.len(),
        ));
    }

    let packet_type = match (first_byte & 0x30) >> 4 {
        0b00 => LongPacketType::Initial,
        0b01 => LongPacketType::ZeroRtt,
        0b10 => LongPacketType::Handshake,
        0b11 => LongPacketType::Retry,
        _ => unreachable!(),
    };

    let type_specific_bits = first_byte & 0x0f;

    Ok((
        PacketHeader::Long(LongHeader {
            packet_type,
            version,
            dcid,
            scid,
            type_specific_bits,
        }),
        pos,
    ))
}

/// Parse a complete Initial packet header.
///
/// Returns the parsed header and the offset where the packet number begins
/// (equal to the header size). The `payload_length` field in the returned
/// header is the value from the Length field (covering packet number + encrypted payload).
pub fn parse_initial_header(buf: &[u8]) -> Result<(InitialHeader<'_>, usize), Error> {
    if buf.len() < 7 {
        return Err(Error::BufferTooSmall { needed: 7 });
    }

    let first_byte = buf[0];
    if first_byte & 0x80 == 0 {
        return Err(Error::Transport(
            crate::error::TransportError::ProtocolViolation,
        ));
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    let dcid_len = buf[5] as usize;
    let mut pos = 6;
    if pos + dcid_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + dcid_len,
        });
    }
    let dcid = &buf[pos..pos + dcid_len];
    pos += dcid_len;

    // Need one more byte for the SCID length. The DCID check above only
    // guarantees `pos <= buf.len()`, so a packet whose DCID fills the datagram
    // exactly would otherwise index out of bounds (remote panic / DoS).
    if pos >= buf.len() {
        return Err(Error::BufferTooSmall { needed: pos + 1 });
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + scid_len,
        });
    }
    let scid = &buf[pos..pos + scid_len];
    pos += scid_len;

    // Token length (varint) + token
    let (token_len, consumed) = decode_varint(&buf[pos..])?;
    pos += consumed;
    let token_len = token_len as usize;
    if pos + token_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + token_len,
        });
    }
    let token = &buf[pos..pos + token_len];
    pos += token_len;

    // Length field (varint) - covers PN + encrypted payload
    let (payload_length, consumed) = decode_varint(&buf[pos..])?;
    pos += consumed;

    Ok((
        InitialHeader {
            version,
            dcid,
            scid,
            token,
            pn_offset: pos,
            payload_length: payload_length as usize,
        },
        pos,
    ))
}

/// Parse a Handshake packet header.
///
/// Same as Initial but packet type is 0b10 and there is no token field.
pub fn parse_handshake_header(buf: &[u8]) -> Result<(HandshakeHeader<'_>, usize), Error> {
    if buf.len() < 7 {
        return Err(Error::BufferTooSmall { needed: 7 });
    }

    let first_byte = buf[0];
    if first_byte & 0x80 == 0 {
        return Err(Error::Transport(
            crate::error::TransportError::ProtocolViolation,
        ));
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    let dcid_len = buf[5] as usize;
    let mut pos = 6;
    if pos + dcid_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + dcid_len,
        });
    }
    let dcid = &buf[pos..pos + dcid_len];
    pos += dcid_len;

    // Need one more byte for the SCID length. The DCID check above only
    // guarantees `pos <= buf.len()`, so a packet whose DCID fills the datagram
    // exactly would otherwise index out of bounds (remote panic / DoS).
    if pos >= buf.len() {
        return Err(Error::BufferTooSmall { needed: pos + 1 });
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        return Err(Error::BufferTooSmall {
            needed: pos + scid_len,
        });
    }
    let scid = &buf[pos..pos + scid_len];
    pos += scid_len;

    // Length field (varint)
    let (payload_length, consumed) = decode_varint(&buf[pos..])?;
    pos += consumed;

    Ok((
        HandshakeHeader {
            version,
            dcid,
            scid,
            pn_offset: pos,
            payload_length: payload_length as usize,
        },
        pos,
    ))
}

/// Encode an Initial packet header into `buf`.
///
/// `pn_len` is the packet number length (1-4) and is encoded in the first byte's
/// lower 2 bits. `payload_len` is the value for the Length field (pn + encrypted payload).
///
/// Returns the number of bytes written (the header size, not including PN or payload).
pub fn encode_initial_header(
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn_len: usize,
    payload_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let token_vi_len = varint_len(token.len() as u64);
    let payload_vi_len = varint_len(payload_len as u64);
    let needed =
        1 + 4 + 1 + dcid.len() + 1 + scid.len() + token_vi_len + token.len() + payload_vi_len;

    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut pos = 0;

    // First byte: 1100_xxxx where xxxx = reserved(2) + pn_len(2)
    // pn_len is encoded as (pn_len - 1) in the lower 2 bits
    buf[pos] = 0xC0 | ((pn_len as u8).wrapping_sub(1) & 0x03);
    pos += 1;

    // Version
    buf[pos..pos + 4].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());
    pos += 4;

    // DCID
    buf[pos] = dcid.len() as u8;
    pos += 1;
    buf[pos..pos + dcid.len()].copy_from_slice(dcid);
    pos += dcid.len();

    // SCID
    buf[pos] = scid.len() as u8;
    pos += 1;
    buf[pos..pos + scid.len()].copy_from_slice(scid);
    pos += scid.len();

    // Token length + token
    let written = encode_varint(token.len() as u64, &mut buf[pos..])?;
    pos += written;
    buf[pos..pos + token.len()].copy_from_slice(token);
    pos += token.len();

    // Length (covers PN + encrypted payload)
    let written = encode_varint(payload_len as u64, &mut buf[pos..])?;
    pos += written;

    Ok(pos)
}

/// Encode a Handshake packet header into `buf`.
///
/// Same as Initial but packet type is 0b10 and there is no token field.
///
/// Returns the number of bytes written.
pub fn encode_handshake_header(
    dcid: &[u8],
    scid: &[u8],
    pn_len: usize,
    payload_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let payload_vi_len = varint_len(payload_len as u64);
    let needed = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + payload_vi_len;

    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut pos = 0;

    // First byte: 1110_xxxx where xxxx = reserved(2) + pn_len(2)
    // type bits = 10 => 0b1110_xxxx
    buf[pos] = 0xE0 | ((pn_len as u8).wrapping_sub(1) & 0x03);
    pos += 1;

    // Version
    buf[pos..pos + 4].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());
    pos += 4;

    // DCID
    buf[pos] = dcid.len() as u8;
    pos += 1;
    buf[pos..pos + dcid.len()].copy_from_slice(dcid);
    pos += dcid.len();

    // SCID
    buf[pos] = scid.len() as u8;
    pos += 1;
    buf[pos..pos + scid.len()].copy_from_slice(scid);
    pos += scid.len();

    // Length (covers PN + encrypted payload)
    let written = encode_varint(payload_len as u64, &mut buf[pos..])?;
    pos += written;

    Ok(pos)
}
