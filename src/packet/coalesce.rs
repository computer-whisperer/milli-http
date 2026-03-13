//! Iterator over coalesced QUIC packets in a single UDP datagram.

use crate::error::Error;
use crate::varint::decode_varint;

/// Iterator over coalesced packets in a single UDP datagram.
///
/// Multiple QUIC packets can be coalesced into a single UDP datagram.
/// Long header packets use the Length field to determine packet boundaries.
/// A short header packet must be the last packet in the datagram (it consumes
/// the rest of the buffer).
pub struct CoalescedPackets<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> CoalescedPackets<'a> {
    pub fn new(datagram: &'a [u8]) -> Self {
        CoalescedPackets {
            buf: datagram,
            offset: 0,
        }
    }
}

impl<'a> Iterator for CoalescedPackets<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.buf.len() {
            return None;
        }

        let remaining = &self.buf[self.offset..];
        let first_byte = remaining[0];

        // Check if this is a long header (form bit set)
        if first_byte & 0x80 != 0 {
            // Long header: we need to find the Length field to determine the boundary.
            // Skip: first byte (1) + version (4) + dcid_len (1) + dcid + scid_len (1) + scid
            if remaining.len() < 6 {
                self.offset = self.buf.len();
                return Some(Err(Error::BufferTooSmall { needed: 6 }));
            }

            let version =
                u32::from_be_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]);

            // Version Negotiation (version == 0) -- consume rest
            if version == 0 {
                let pkt = &self.buf[self.offset..];
                self.offset = self.buf.len();
                return Some(Ok(pkt));
            }

            let dcid_len = remaining[5] as usize;
            let mut pos = 6;
            if pos + dcid_len >= remaining.len() {
                self.offset = self.buf.len();
                return Some(Err(Error::BufferTooSmall {
                    needed: pos + dcid_len + 1,
                }));
            }
            pos += dcid_len;

            let scid_len = remaining[pos] as usize;
            pos += 1;
            if pos + scid_len > remaining.len() {
                self.offset = self.buf.len();
                return Some(Err(Error::BufferTooSmall {
                    needed: pos + scid_len,
                }));
            }
            pos += scid_len;

            // Determine packet type for token handling
            let pkt_type = (first_byte & 0x30) >> 4;

            // Initial packets (type 0b00) have a token field
            if pkt_type == 0b00 {
                match decode_varint(&remaining[pos..]) {
                    Ok((token_len, consumed)) => {
                        pos += consumed;
                        pos += token_len as usize;
                        if pos > remaining.len() {
                            self.offset = self.buf.len();
                            return Some(Err(Error::BufferTooSmall { needed: pos }));
                        }
                    }
                    Err(e) => {
                        self.offset = self.buf.len();
                        return Some(Err(e));
                    }
                }
            }

            // Retry packets (type 0b11) have no Length field -- consume rest
            if pkt_type == 0b11 {
                let pkt = &self.buf[self.offset..];
                self.offset = self.buf.len();
                return Some(Ok(pkt));
            }

            // Length field
            match decode_varint(&remaining[pos..]) {
                Ok((payload_length, consumed)) => {
                    pos += consumed;
                    let total = pos + payload_length as usize;
                    if total > remaining.len() {
                        self.offset = self.buf.len();
                        return Some(Err(Error::BufferTooSmall {
                            needed: self.offset + total,
                        }));
                    }
                    let pkt = &self.buf[self.offset..self.offset + total];
                    self.offset += total;
                    Some(Ok(pkt))
                }
                Err(e) => {
                    self.offset = self.buf.len();
                    Some(Err(e))
                }
            }
        } else {
            // Short header: consumes the rest of the datagram
            let pkt = &self.buf[self.offset..];
            self.offset = self.buf.len();
            Some(Ok(pkt))
        }
    }
}
