//! HPACK encoder and decoder (RFC 7541).
//!
//! Static-only mode: no dynamic table. This is sufficient for HTTP/2
//! interop when combined with literal encoding for entries not in the
//! static table.

use super::integer;
use super::static_table::{self, LookupResult, STATIC_TABLE};
use crate::error::Error;

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// HPACK encoder (static-only mode, no dynamic table).
pub struct HpackEncoder;

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackEncoder {
    pub fn new() -> Self {
        Self
    }

    /// Encode a header block from a list of (name, value) pairs.
    ///
    /// Unlike QPACK, HPACK has no field section prefix.
    /// Returns the number of bytes written.
    pub fn encode(&self, headers: &[(&[u8], &[u8])], buf: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;

        for &(name, value) in headers {
            let result = static_table::lookup(name, value);
            match result {
                LookupResult::ExactMatch(idx) => {
                    // Indexed Header Field (§6.1): 1xxxxxxx, prefix=7
                    offset +=
                        integer::encode_integer(idx as u64, 7, 0b1000_0000, &mut buf[offset..])?;
                }
                LookupResult::NameMatch(idx) => {
                    // Literal Header Field without Indexing — Name Reference (§6.2.2):
                    // 0000xxxx, prefix=4
                    offset +=
                        integer::encode_integer(idx as u64, 4, 0b0000_0000, &mut buf[offset..])?;
                    // Value: H=0, length prefix=7
                    offset += self.encode_string_literal(value, &mut buf[offset..])?;
                }
                LookupResult::NotFound => {
                    // Literal Header Field without Indexing — New Name (§6.2.2):
                    // First byte: 0x00 (index=0)
                    if offset >= buf.len() {
                        return Err(Error::BufferTooSmall { needed: offset + 1 });
                    }
                    buf[offset] = 0x00;
                    offset += 1;
                    // Name: H=0, length prefix=7
                    offset += self.encode_string_literal(name, &mut buf[offset..])?;
                    // Value: H=0, length prefix=7
                    offset += self.encode_string_literal(value, &mut buf[offset..])?;
                }
            }
        }

        Ok(offset)
    }

    /// Encode a string literal: H=0 (no Huffman), length (prefix=7), raw bytes.
    fn encode_string_literal(&self, s: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;
        // H=0 (bit 7 = 0), length in prefix=7
        offset += integer::encode_integer(s.len() as u64, 7, 0x00, &mut buf[offset..])?;
        if buf.len() - offset < s.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + s.len(),
            });
        }
        buf[offset..offset + s.len()].copy_from_slice(s);
        offset += s.len();
        Ok(offset)
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// HPACK decoder (static-only mode, no dynamic table).
pub struct HpackDecoder;

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    pub fn new() -> Self {
        Self
    }

    /// Decode an HPACK-encoded header block.
    ///
    /// Calls `emit(name, value)` for each decoded header.
    /// Returns the number of bytes consumed.
    pub fn decode<F>(&self, src: &[u8], mut emit: F) -> Result<usize, Error>
    where
        F: FnMut(&[u8], &[u8]),
    {
        let mut pos = 0;

        while pos < src.len() {
            let first = src[pos];

            if first & 0b1000_0000 != 0 {
                // §6.1 Indexed Header Field: 1xxxxxxx
                let (index, consumed) = integer::decode_integer(&src[pos..], 7)?;
                pos += consumed;
                let index = index as usize;
                if index == 0 || index > STATIC_TABLE.len() {
                    return Err(Error::InvalidState);
                }
                let entry = &STATIC_TABLE[index - 1]; // 1-based → 0-based
                emit(entry.name, entry.value);
            } else if first & 0b1100_0000 == 0b0100_0000 {
                // §6.2.1 Literal with Incremental Indexing: 01xxxxxx
                // We don't maintain a dynamic table, but we can still decode these.
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 6)?;
                pos += consumed;
                pos += self.decode_literal_field(src, pos, name_index as usize, &mut emit)?;
            } else if first & 0b1111_0000 == 0b0000_0000 {
                // §6.2.2 Literal without Indexing: 0000xxxx
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 4)?;
                pos += consumed;
                pos += self.decode_literal_field(src, pos, name_index as usize, &mut emit)?;
            } else if first & 0b1111_0000 == 0b0001_0000 {
                // §6.2.3 Literal Never Indexed: 0001xxxx
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 4)?;
                pos += consumed;
                pos += self.decode_literal_field(src, pos, name_index as usize, &mut emit)?;
            } else if first & 0b1110_0000 == 0b0010_0000 {
                // §6.3 Dynamic Table Size Update: 001xxxxx
                // We ignore these since we don't use a dynamic table.
                let (_new_size, consumed) = integer::decode_integer(&src[pos..], 5)?;
                pos += consumed;
            } else {
                return Err(Error::InvalidState);
            }
        }

        Ok(pos)
    }

    /// Decode a literal header field (name from index or literal, plus value).
    /// Returns bytes consumed starting from `start`.
    ///
    /// Handles Huffman-encoded strings by decoding into stack-local buffers.
    fn decode_literal_field<F>(
        &self,
        src: &[u8],
        start: usize,
        name_index: usize,
        emit: &mut F,
    ) -> Result<usize, Error>
    where
        F: FnMut(&[u8], &[u8]),
    {
        let mut pos = start;

        if name_index > 0 {
            // Name from static table
            if name_index > STATIC_TABLE.len() {
                return Err(Error::InvalidState);
            }
            let name = STATIC_TABLE[name_index - 1].name;

            // Decode value string (may be Huffman-encoded)
            let (huffman, length, len_consumed) = Self::parse_string_header(&src[pos..])?;
            let raw = &src[pos + len_consumed..pos + len_consumed + length];
            pos += len_consumed + length;

            if huffman {
                let mut val_buf = [0u8; 1024];
                let decoded_len = super::huffman::decode(raw, &mut val_buf)?;
                emit(name, &val_buf[..decoded_len]);
            } else {
                emit(name, raw);
            }
        } else {
            // Literal name + value (both may be Huffman-encoded)
            let (huf_n, len_n, lc_n) = Self::parse_string_header(&src[pos..])?;
            let raw_name = &src[pos + lc_n..pos + lc_n + len_n];
            pos += lc_n + len_n;

            let (huf_v, len_v, lc_v) = Self::parse_string_header(&src[pos..])?;
            let raw_value = &src[pos + lc_v..pos + lc_v + len_v];
            pos += lc_v + len_v;

            let mut name_buf = [0u8; 256];
            let mut val_buf = [0u8; 1024];

            let name: &[u8] = if huf_n {
                let n = super::huffman::decode(raw_name, &mut name_buf)?;
                &name_buf[..n]
            } else {
                raw_name
            };

            let value: &[u8] = if huf_v {
                let n = super::huffman::decode(raw_value, &mut val_buf)?;
                &val_buf[..n]
            } else {
                raw_value
            };

            emit(name, value);
        }

        Ok(pos - start)
    }

    /// Parse the header of an HPACK string literal (H bit + length).
    /// Returns `(is_huffman, string_length, header_bytes_consumed)`.
    fn parse_string_header(src: &[u8]) -> Result<(bool, usize, usize), Error> {
        if src.is_empty() {
            return Err(Error::BufferTooSmall { needed: 1 });
        }
        let huffman = src[0] & 0x80 != 0;
        let (length, len_consumed) = integer::decode_integer(src, 7)?;
        let length = length as usize;

        if src.len() - len_consumed < length {
            return Err(Error::BufferTooSmall {
                needed: len_consumed + length,
            });
        }

        Ok((huffman, length, len_consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::Vec as HVec;

    struct Collected {
        entries: HVec<(HVec<u8, 256>, HVec<u8, 512>), 32>,
    }

    impl Collected {
        fn new() -> Self {
            Self {
                entries: HVec::new(),
            }
        }
        fn push(&mut self, name: &[u8], value: &[u8]) {
            let mut n = HVec::new();
            n.extend_from_slice(name).unwrap();
            let mut v = HVec::new();
            v.extend_from_slice(value).unwrap();
            self.entries.push((n, v)).unwrap();
        }
    }

    #[test]
    fn roundtrip_indexed() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b":method", b"GET")];
        let mut buf = [0u8; 256];
        let n = encoder.encode(headers, &mut buf).unwrap();
        // :method GET is index 2 → single byte 0x82
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x82);

        let mut c = Collected::new();
        let consumed = decoder
            .decode(&buf[..n], |name, val| c.push(name, val))
            .unwrap();
        assert_eq!(consumed, n);
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b":method");
        assert_eq!(c.entries[0].1.as_slice(), b"GET");
    }

    #[test]
    fn roundtrip_name_ref() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b":path", b"/api/users")];
        let mut buf = [0u8; 256];
        let n = encoder.encode(headers, &mut buf).unwrap();

        let mut c = Collected::new();
        decoder
            .decode(&buf[..n], |name, val| c.push(name, val))
            .unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b":path");
        assert_eq!(c.entries[0].1.as_slice(), b"/api/users");
    }

    #[test]
    fn roundtrip_literal() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b"x-custom", b"hello")];
        let mut buf = [0u8; 256];
        let n = encoder.encode(headers, &mut buf).unwrap();

        let mut c = Collected::new();
        decoder
            .decode(&buf[..n], |name, val| c.push(name, val))
            .unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b"x-custom");
        assert_eq!(c.entries[0].1.as_slice(), b"hello");
    }

    #[test]
    fn roundtrip_multiple_headers() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        let headers: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b"accept", b"text/html"),
        ];
        let mut buf = [0u8; 512];
        let n = encoder.encode(headers, &mut buf).unwrap();

        let mut c = Collected::new();
        decoder
            .decode(&buf[..n], |name, val| c.push(name, val))
            .unwrap();
        assert_eq!(c.entries.len(), 5);
        assert_eq!(c.entries[0].0.as_slice(), b":method");
        assert_eq!(c.entries[0].1.as_slice(), b"GET");
        assert_eq!(c.entries[1].0.as_slice(), b":path");
        assert_eq!(c.entries[1].1.as_slice(), b"/");
        assert_eq!(c.entries[2].0.as_slice(), b":scheme");
        assert_eq!(c.entries[2].1.as_slice(), b"https");
        assert_eq!(c.entries[3].0.as_slice(), b":authority");
        assert_eq!(c.entries[3].1.as_slice(), b"example.com");
        assert_eq!(c.entries[4].0.as_slice(), b"accept");
        assert_eq!(c.entries[4].1.as_slice(), b"text/html");
    }

    #[test]
    fn roundtrip_empty() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        let mut buf = [0u8; 256];
        let n = encoder.encode(&[], &mut buf).unwrap();
        assert_eq!(n, 0);

        let mut count = 0;
        decoder.decode(&buf[..n], |_, _| count += 1).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn roundtrip_status_200() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b":status", b"200")];
        let mut buf = [0u8; 256];
        let n = encoder.encode(headers, &mut buf).unwrap();
        // :status 200 is index 8 → 0x88
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x88);

        let mut c = Collected::new();
        decoder
            .decode(&buf[..n], |name, val| c.push(name, val))
            .unwrap();
        assert_eq!(c.entries[0].0.as_slice(), b":status");
        assert_eq!(c.entries[0].1.as_slice(), b"200");
    }

    #[test]
    fn roundtrip_all_exact_match_entries() {
        let encoder = HpackEncoder::new();
        let decoder = HpackDecoder::new();
        // Only entries with non-empty values can exact-match
        for (i, entry) in STATIC_TABLE.iter().enumerate() {
            if !entry.value.is_empty() {
                let headers: &[(&[u8], &[u8])] = &[(entry.name, entry.value)];
                let mut buf = [0u8; 256];
                let n = encoder.encode(headers, &mut buf).unwrap();

                let mut c = Collected::new();
                decoder
                    .decode(&buf[..n], |name, val| c.push(name, val))
                    .unwrap();
                assert_eq!(c.entries.len(), 1, "failed at index {}", i + 1);
                assert_eq!(c.entries[0].0.as_slice(), entry.name);
                assert_eq!(c.entries[0].1.as_slice(), entry.value);
            }
        }
    }

    #[test]
    fn buffer_too_small_encode() {
        let encoder = HpackEncoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b"x-long-header-name", b"a-long-value-here")];
        let mut buf = [0u8; 2];
        assert!(encoder.encode(headers, &mut buf).is_err());
    }

    #[test]
    fn decode_invalid_index() {
        let decoder = HpackDecoder::new();
        // Indexed field with index 62 (out of range for 61-entry table)
        let buf = [0x80 | 62]; // 0xBE
        assert!(decoder.decode(&buf, |_, _| {}).is_err());
    }

    #[test]
    fn decode_index_zero_is_error() {
        let decoder = HpackDecoder::new();
        // Index 0 is not valid in indexed representation
        let buf = [0x80]; // index 0
        assert!(decoder.decode(&buf, |_, _| {}).is_err());
    }

    // ====== RFC 7541 Wire-Format Decode Tests ======

    #[test]
    fn rfc7541_c2_1_literal_with_indexing() {
        // RFC 7541 Appendix C.2.1: Literal Header Field with Incremental Indexing
        // custom-key: custom-header
        let input: &[u8] = &[
            0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63,
            0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
        ];
        let decoder = HpackDecoder::new();
        let mut c = Collected {
            entries: HVec::new(),
        };
        let consumed = decoder
            .decode(input, |name, value| {
                c.entries
                    .push((
                        HVec::from_slice(name).unwrap(),
                        HVec::from_slice(value).unwrap(),
                    ))
                    .unwrap();
            })
            .unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b"custom-key");
        assert_eq!(c.entries[0].1.as_slice(), b"custom-header");
    }

    #[test]
    fn rfc7541_c2_2_literal_no_indexing() {
        // RFC 7541 Appendix C.2.2: Literal Header Field without Indexing
        // :path: /sample/path (name index 4 = :path)
        let input: &[u8] = &[
            0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68,
        ];
        let decoder = HpackDecoder::new();
        let mut c = Collected {
            entries: HVec::new(),
        };
        decoder
            .decode(input, |name, value| {
                c.entries
                    .push((
                        HVec::from_slice(name).unwrap(),
                        HVec::from_slice(value).unwrap(),
                    ))
                    .unwrap();
            })
            .unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b":path");
        assert_eq!(c.entries[0].1.as_slice(), b"/sample/path");
    }

    #[test]
    fn rfc7541_c2_3_literal_never_indexed() {
        // RFC 7541 Appendix C.2.3: Literal Header Field Never Indexed
        // password: secret
        let input: &[u8] = &[
            0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65, 0x63,
            0x72, 0x65, 0x74,
        ];
        let decoder = HpackDecoder::new();
        let mut c = Collected {
            entries: HVec::new(),
        };
        decoder
            .decode(input, |name, value| {
                c.entries
                    .push((
                        HVec::from_slice(name).unwrap(),
                        HVec::from_slice(value).unwrap(),
                    ))
                    .unwrap();
            })
            .unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b"password");
        assert_eq!(c.entries[0].1.as_slice(), b"secret");
    }

    #[test]
    fn rfc7541_c4_indexed_method_get() {
        // Indexed representation: index 2 = :method GET
        let input: &[u8] = &[0x82];
        let decoder = HpackDecoder::new();
        let mut c = Collected {
            entries: HVec::new(),
        };
        decoder
            .decode(input, |name, value| {
                c.entries
                    .push((
                        HVec::from_slice(name).unwrap(),
                        HVec::from_slice(value).unwrap(),
                    ))
                    .unwrap();
            })
            .unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b":method");
        assert_eq!(c.entries[0].1.as_slice(), b"GET");
    }

    #[test]
    fn rfc7541_c4_indexed_status_200() {
        // Indexed representation: index 8 = :status 200
        let input: &[u8] = &[0x88];
        let decoder = HpackDecoder::new();
        let mut c = Collected {
            entries: HVec::new(),
        };
        decoder
            .decode(input, |name, value| {
                c.entries
                    .push((
                        HVec::from_slice(name).unwrap(),
                        HVec::from_slice(value).unwrap(),
                    ))
                    .unwrap();
            })
            .unwrap();
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[0].0.as_slice(), b":status");
        assert_eq!(c.entries[0].1.as_slice(), b"200");
    }
}
