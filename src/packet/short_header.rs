//! Short header (1-RTT) packet parsing and encoding (RFC 9000 section 17.3).

use crate::error::Error;
use crate::packet::ShortHeader;

/// Parse a short header packet.
///
/// The caller must know the DCID length from connection state.
/// Returns the parsed header and bytes consumed (first byte + DCID).
pub fn parse_short_header(buf: &[u8], dcid_len: usize) -> Result<(ShortHeader<'_>, usize), Error> {
    let needed = 1 + dcid_len;
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let first_byte = buf[0];

    // Short header: form bit (bit 7) must be 0, fixed bit (bit 6) must be 1
    if first_byte & 0x80 != 0 {
        return Err(Error::Transport(
            crate::error::TransportError::ProtocolViolation,
        ));
    }

    let dcid = &buf[1..1 + dcid_len];

    Ok((ShortHeader { dcid, first_byte }, needed))
}

/// Encode a short header packet into `buf`.
///
/// Writes the first byte and DCID. Returns the number of bytes written.
pub fn encode_short_header(dcid: &[u8], first_byte: u8, buf: &mut [u8]) -> Result<usize, Error> {
    let needed = 1 + dcid.len();
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    buf[0] = first_byte;
    buf[1..1 + dcid.len()].copy_from_slice(dcid);

    Ok(needed)
}
