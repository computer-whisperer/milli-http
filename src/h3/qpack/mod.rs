//! QPACK header compression codec (RFC 9204).
//!
//! This implementation operates in **static-only mode** (`TABLE_SIZE = 0`):
//! no dynamic table, no encoder/decoder streams.  This is fully
//! RFC-compliant and sufficient for HTTP/3 interoperability.

pub mod huffman;
pub mod integer;
pub mod static_table;

use crate::error::{Error, H3Error, TransportError};
use static_table::{LookupResult, STATIC_TABLE};

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// QPACK encoder (static-only mode).
pub struct QpackEncoder;

impl Default for QpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QpackEncoder {
    /// Create a new encoder.
    pub fn new() -> Self {
        Self
    }

    /// Encode a field section (list of header name/value pairs).
    ///
    /// Each element of `headers` is a `(&[u8], &[u8])` pair of (name, value).
    /// The encoded representation is written into `buf` and the number of
    /// bytes written is returned.
    pub fn encode_field_section(
        &self,
        headers: &[(&[u8], &[u8])],
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let mut offset = 0;

        // -- Required Insert Count: 0 (prefix-8 integer) --
        offset += integer::encode_integer(0, 8, 0x00, &mut buf[offset..])
            .map_err(|_| Error::BufferTooSmall { needed: offset + 1 })?;

        // -- Delta Base: 0 with sign bit = 0 (prefix-7 integer) --
        // Sign bit (bit 7) = 0, delta base = 0.
        offset += integer::encode_integer(0, 7, 0x00, &mut buf[offset..])
            .map_err(|_| Error::BufferTooSmall { needed: offset + 1 })?;

        for &(name, value) in headers {
            let result = static_table::lookup(name, value);
            match result {
                LookupResult::ExactMatch(idx) => {
                    // Indexed Field Line (static): 0b11xxxxxx, prefix=6
                    offset += self.encode_indexed_static(idx, &mut buf[offset..])?;
                }
                LookupResult::NameMatch(idx) => {
                    // Literal with Name Reference (static)
                    offset += self.encode_literal_name_ref(idx, value, &mut buf[offset..])?;
                }
                LookupResult::NotFound => {
                    // Literal with Literal Name
                    offset += self.encode_literal(name, value, &mut buf[offset..])?;
                }
            }
        }

        Ok(offset)
    }

    /// Encode an indexed field line referencing the static table.
    ///
    /// Bit pattern: `0b11xxxxxx` — T=1 (static), prefix=6 for index.
    fn encode_indexed_static(&self, index: usize, buf: &mut [u8]) -> Result<usize, Error> {
        // First byte high bits: 1 (indexed) + 1 (static) = 0b1100_0000
        integer::encode_integer(index as u64, 6, 0b1100_0000, buf)
    }

    /// Encode a literal field line with a name reference to the static table.
    ///
    /// Bit pattern: `0b0101xxxx` — N=0 (allow indexing by peer), T=1 (static).
    /// We use N=1 (never index) since there is no dynamic table: `0b0111xxxx`.
    fn encode_literal_name_ref(
        &self,
        name_index: usize,
        value: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let mut offset = 0;

        // First byte: 01NT where N=1, T=1 => 0b0111_xxxx, prefix=4
        offset += integer::encode_integer(name_index as u64, 4, 0b0111_0000, buf)?;

        // Value: H=0 (no Huffman) + length (prefix=7)
        offset += integer::encode_integer(value.len() as u64, 7, 0x00, &mut buf[offset..])?;

        // Value bytes
        if buf.len() - offset < value.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + value.len(),
            });
        }
        buf[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len();

        Ok(offset)
    }

    /// Encode a literal field line with a literal name (no table reference).
    ///
    /// Bit pattern: `0b001Nxxxx`.  We use N=1 (never index): `0b0011xxxx`.
    fn encode_literal(&self, name: &[u8], value: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;

        // Name: first byte 0b0011_xxxx (N=1), H=0 (no Huffman), prefix=3 for length
        offset += integer::encode_integer(name.len() as u64, 3, 0b0010_0000, buf)?;

        // Name bytes
        if buf.len() - offset < name.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + name.len(),
            });
        }
        buf[offset..offset + name.len()].copy_from_slice(name);
        offset += name.len();

        // Value: H=0 (no Huffman) + length (prefix=7)
        offset += integer::encode_integer(value.len() as u64, 7, 0x00, &mut buf[offset..])?;

        // Value bytes
        if buf.len() - offset < value.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + value.len(),
            });
        }
        buf[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len();

        Ok(offset)
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// QPACK decoder (static-only mode).
pub struct QpackDecoder;

impl Default for QpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QpackDecoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self
    }

    /// Decode a QPACK-encoded field section.
    ///
    /// For each decoded header the callback `emit(name, value)` is invoked.
    /// Returns the number of bytes consumed from `src`.
    pub fn decode_field_section<F>(&self, src: &[u8], mut emit: F) -> Result<usize, Error>
    where
        F: FnMut(&[u8], &[u8]),
    {
        if src.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let mut pos = 0;

        // -- Required Insert Count (prefix=8) --
        let (ric, consumed) = integer::decode_integer(&src[pos..], 8)?;
        pos += consumed;
        if ric != 0 {
            // We only support static-only mode (no dynamic table).
            return Err(Error::Http3(H3Error::QpackDecompressionFailed));
        }

        // -- Sign bit + Delta Base (prefix=7) --
        if pos >= src.len() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }
        let _sign = (src[pos] >> 7) & 1;
        let (delta_base, consumed) = integer::decode_integer(&src[pos..], 7)?;
        pos += consumed;
        // For static-only, sign=0 and delta_base=0 is typical.
        let _ = delta_base;

        // -- Header field lines --
        while pos < src.len() {
            let first = src[pos];

            if first & 0b1000_0000 != 0 {
                // Indexed Field Line: 1Txxxxxx
                let t = (first >> 6) & 1;
                if t == 0 {
                    // Dynamic table reference — not supported.
                    return Err(Error::Http3(H3Error::QpackDecompressionFailed));
                }
                // Static table: prefix=6
                let (index, consumed) = integer::decode_integer(&src[pos..], 6)?;
                pos += consumed;

                let index = index as usize;
                if index >= STATIC_TABLE.len() {
                    return Err(Error::Http3(H3Error::QpackDecompressionFailed));
                }
                emit(STATIC_TABLE[index].name, STATIC_TABLE[index].value);
            } else if first & 0b1100_0000 == 0b0100_0000 {
                // Literal Field Line With Name Reference: 01NTxxxx
                let t = (first >> 4) & 1;
                if t == 0 {
                    // Dynamic table reference — not supported.
                    return Err(Error::Http3(H3Error::QpackDecompressionFailed));
                }
                // Static name reference, prefix=4
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 4)?;
                pos += consumed;

                let name_index = name_index as usize;
                if name_index >= STATIC_TABLE.len() {
                    return Err(Error::Http3(H3Error::QpackDecompressionFailed));
                }

                // Value: H bit + length (prefix=7)
                if pos >= src.len() {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                let huffman = (src[pos] >> 7) & 1 != 0;
                let (value_len, consumed) = integer::decode_integer(&src[pos..], 7)?;
                pos += consumed;

                let value_len = value_len as usize;
                if pos + value_len > src.len() {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }

                let value = &src[pos..pos + value_len];
                pos += value_len;

                if huffman {
                    let mut huff_buf = [0u8; 512];
                    let decoded_len = huffman::decode(value, &mut huff_buf)
                        .map_err(|_| Error::Http3(H3Error::QpackDecompressionFailed))?;
                    emit(STATIC_TABLE[name_index].name, &huff_buf[..decoded_len]);
                } else {
                    emit(STATIC_TABLE[name_index].name, value);
                }
            } else if first & 0b1110_0000 == 0b0010_0000 {
                // Literal Field Line With Literal Name: 001Nxxxx
                // H bit for name is embedded in first byte below the N bit.
                // Actually, the first byte is 001N_Hxxx where H is Huffman for name
                // and the name length has prefix=3.

                let name_huffman = (first >> 3) & 1 != 0;

                // Name length: prefix=3
                let (name_len, consumed) = integer::decode_integer(&src[pos..], 3)?;
                pos += consumed;

                let name_len = name_len as usize;
                if pos + name_len > src.len() {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }

                let name_raw = &src[pos..pos + name_len];
                pos += name_len;

                // Decode name (possibly Huffman-encoded)
                let mut name_huff_buf = [0u8; 256];
                let name_slice = if name_huffman {
                    let decoded_len = huffman::decode(name_raw, &mut name_huff_buf)
                        .map_err(|_| Error::Http3(H3Error::QpackDecompressionFailed))?;
                    &name_huff_buf[..decoded_len]
                } else {
                    name_raw
                };

                // Value: H bit + length (prefix=7)
                if pos >= src.len() {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                let value_huffman = (src[pos] >> 7) & 1 != 0;
                let (value_len, consumed) = integer::decode_integer(&src[pos..], 7)?;
                pos += consumed;

                let value_len = value_len as usize;
                if pos + value_len > src.len() {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }

                let value_raw = &src[pos..pos + value_len];
                pos += value_len;

                // Decode value (possibly Huffman-encoded)
                let mut value_huff_buf = [0u8; 512];
                let value_slice = if value_huffman {
                    let decoded_len = huffman::decode(value_raw, &mut value_huff_buf)
                        .map_err(|_| Error::Http3(H3Error::QpackDecompressionFailed))?;
                    &value_huff_buf[..decoded_len]
                } else {
                    value_raw
                };

                emit(name_slice, value_slice);
            } else if first & 0b1111_0000 == 0b0001_0000 {
                // Indexed Field Line With Post-Base Index: 0001xxxx
                // Not used in static-only mode.
                return Err(Error::Http3(H3Error::QpackDecompressionFailed));
            } else if first & 0b1111_0000 == 0b0000_0000 {
                // Literal Field Line With Post-Base Name Reference: 0000Nxxx
                // Not used in static-only mode.
                return Err(Error::Http3(H3Error::QpackDecompressionFailed));
            } else {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
        }

        Ok(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::Vec as HVec;

    // Collect decoded headers into a heapless Vec of (name, value) byte slices.
    // We copy into owned byte vecs for comparison.
    struct CollectedHeaders {
        entries: HVec<(HVec<u8, 256>, HVec<u8, 512>), 32>,
    }

    impl CollectedHeaders {
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

    // -----------------------------------------------------------------------
    // 1. Integer roundtrip (delegated, but verify through the module)
    // -----------------------------------------------------------------------

    #[test]
    fn integer_roundtrip_various() {
        let cases: &[(u64, u8)] = &[
            (0, 5),
            (1, 5),
            (30, 5),
            (31, 5),
            (127, 7),
            (128, 7),
            (255, 8),
            (1337, 5),
            (65535, 6),
        ];
        for &(val, prefix) in cases {
            let mut buf = [0u8; 16];
            let n = integer::encode_integer(val, prefix, 0, &mut buf).unwrap();
            let (decoded, consumed) = integer::decode_integer(&buf[..n], prefix).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, n);
        }
    }

    // -----------------------------------------------------------------------
    // 2. Static table lookups
    // -----------------------------------------------------------------------

    #[test]
    fn static_table_specific_entries() {
        assert_eq!(STATIC_TABLE[0].name, b":authority");
        assert_eq!(STATIC_TABLE[17].name, b":method");
        assert_eq!(STATIC_TABLE[17].value, b"GET");
        assert_eq!(STATIC_TABLE[25].name, b":status");
        assert_eq!(STATIC_TABLE[25].value, b"200");
    }

    // -----------------------------------------------------------------------
    // 3. Encode/decode roundtrip — indexed (exact match)
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_method_get() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b":method", b"GET")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        let consumed = decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(consumed, n);
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b":method");
        assert_eq!(collected.entries[0].1.as_slice(), b"GET");
    }

    #[test]
    fn roundtrip_path_root() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b":path", b"/")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b":path");
        assert_eq!(collected.entries[0].1.as_slice(), b"/");
    }

    #[test]
    fn roundtrip_status_200() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b":status", b"200")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b":status");
        assert_eq!(collected.entries[0].1.as_slice(), b"200");
    }

    // -----------------------------------------------------------------------
    // 4. Encode/decode with static name + literal value
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_path_literal_value() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b":path", b"/index.html")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b":path");
        assert_eq!(collected.entries[0].1.as_slice(), b"/index.html");
    }

    #[test]
    fn roundtrip_status_literal_value() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b":status", b"201")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b":status");
        assert_eq!(collected.entries[0].1.as_slice(), b"201");
    }

    // -----------------------------------------------------------------------
    // 5. Fully literal headers
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_custom_header() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b"x-custom", b"value")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b"x-custom");
        assert_eq!(collected.entries[0].1.as_slice(), b"value");
    }

    #[test]
    fn roundtrip_literal_empty_value() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[(b"x-empty", b"")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].0.as_slice(), b"x-empty");
        assert_eq!(collected.entries[0].1.as_slice(), b"");
    }

    // -----------------------------------------------------------------------
    // 6. Multiple headers in one field section
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_multiple_headers() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ];
        let mut buf = [0u8; 512];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 4);

        assert_eq!(collected.entries[0].0.as_slice(), b":method");
        assert_eq!(collected.entries[0].1.as_slice(), b"GET");

        assert_eq!(collected.entries[1].0.as_slice(), b":path");
        assert_eq!(collected.entries[1].1.as_slice(), b"/");

        assert_eq!(collected.entries[2].0.as_slice(), b":scheme");
        assert_eq!(collected.entries[2].1.as_slice(), b"https");

        assert_eq!(collected.entries[3].0.as_slice(), b":authority");
        assert_eq!(collected.entries[3].1.as_slice(), b"example.com");
    }

    // -----------------------------------------------------------------------
    // 7. Real-world HTTP request headers
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_realistic_request() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[
            (b":method", b"POST"),
            (b":path", b"/api/v1/data"),
            (b":scheme", b"https"),
            (b":authority", b"api.example.com"),
            (b"accept", b"application/json"),
            (b"content-type", b"application/json"),
            (b"user-agent", b"milli-quic/0.1"),
            (b"accept-encoding", b"gzip, deflate, br"),
        ];
        let mut buf = [0u8; 1024];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 8);

        assert_eq!(collected.entries[0].0.as_slice(), b":method");
        assert_eq!(collected.entries[0].1.as_slice(), b"POST");
        assert_eq!(collected.entries[1].0.as_slice(), b":path");
        assert_eq!(collected.entries[1].1.as_slice(), b"/api/v1/data");
        assert_eq!(collected.entries[2].0.as_slice(), b":scheme");
        assert_eq!(collected.entries[2].1.as_slice(), b"https");
        assert_eq!(collected.entries[3].0.as_slice(), b":authority");
        assert_eq!(collected.entries[3].1.as_slice(), b"api.example.com");
        // accept "application/json" is not an exact match (static has */* at 29 and
        // application/dns-message at 30), so name-match at index 29.
        assert_eq!(collected.entries[4].0.as_slice(), b"accept");
        assert_eq!(collected.entries[4].1.as_slice(), b"application/json");
        assert_eq!(collected.entries[5].0.as_slice(), b"content-type");
        assert_eq!(collected.entries[5].1.as_slice(), b"application/json");
        assert_eq!(collected.entries[6].0.as_slice(), b"user-agent");
        assert_eq!(collected.entries[6].1.as_slice(), b"milli-quic/0.1");
        assert_eq!(collected.entries[7].0.as_slice(), b"accept-encoding");
        assert_eq!(collected.entries[7].1.as_slice(), b"gzip, deflate, br");
    }

    // -----------------------------------------------------------------------
    // 8. Real-world HTTP response headers
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_realistic_response() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[
            (b":status", b"200"),
            (b"content-type", b"application/json"),
            (b"content-length", b"42"),
            (b"cache-control", b"no-cache"),
            (b"server", b"milli-quic"),
            (b"strict-transport-security", b"max-age=31536000"),
        ];
        let mut buf = [0u8; 1024];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 6);

        assert_eq!(collected.entries[0].0.as_slice(), b":status");
        assert_eq!(collected.entries[0].1.as_slice(), b"200");
        assert_eq!(collected.entries[1].0.as_slice(), b"content-type");
        assert_eq!(collected.entries[1].1.as_slice(), b"application/json");
        assert_eq!(collected.entries[2].0.as_slice(), b"content-length");
        assert_eq!(collected.entries[2].1.as_slice(), b"42");
        assert_eq!(collected.entries[3].0.as_slice(), b"cache-control");
        assert_eq!(collected.entries[3].1.as_slice(), b"no-cache");
        assert_eq!(collected.entries[4].0.as_slice(), b"server");
        assert_eq!(collected.entries[4].1.as_slice(), b"milli-quic");
        assert_eq!(
            collected.entries[5].0.as_slice(),
            b"strict-transport-security"
        );
        assert_eq!(collected.entries[5].1.as_slice(), b"max-age=31536000");
    }

    // -----------------------------------------------------------------------
    // 9. Buffer-too-small errors
    // -----------------------------------------------------------------------

    #[test]
    fn encode_buffer_too_small() {
        let encoder = QpackEncoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b":method", b"GET")];
        let mut buf = [0u8; 2]; // Way too small (need preamble + indexed line).
        let result = encoder.encode_field_section(headers, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn encode_buffer_too_small_literal() {
        let encoder = QpackEncoder::new();
        let headers: &[(&[u8], &[u8])] =
            &[(b"x-custom-header-name", b"some-long-value-that-wont-fit")];
        let mut buf = [0u8; 4]; // Too small for literal.
        let result = encoder.encode_field_section(headers, &mut buf);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // 10. Empty field section
    // -----------------------------------------------------------------------

    #[test]
    fn empty_field_section() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        // Should just be the 2-byte preamble (RIC=0, delta_base=0).
        assert_eq!(n, 2);

        let mut count = 0usize;
        let consumed = decoder
            .decode_field_section(&buf[..n], |_name, _value| {
                count += 1;
            })
            .unwrap();
        assert_eq!(consumed, n);
        assert_eq!(count, 0);
    }

    // -----------------------------------------------------------------------
    // Extra: encoding strategy verification
    // -----------------------------------------------------------------------

    #[test]
    fn exact_match_produces_indexed_line() {
        let encoder = QpackEncoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b":method", b"GET")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        // Preamble: 2 bytes (RIC=0, delta_base=0)
        // Indexed static line: 1 byte (0b11 | index 17)
        assert_eq!(n, 3);
        // Verify the indexed byte: 0b1100_0000 | 17 = 0xD1
        assert_eq!(buf[2], 0b1100_0000 | 17);
    }

    #[test]
    fn name_ref_produces_literal_with_name_ref() {
        let encoder = QpackEncoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b":path", b"/foo")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        // Preamble: 2 bytes
        // Literal with name ref: first byte = 0b0111_0000 | name_index(1) = 0x71
        // Value length: 1 byte (4 with prefix=7 fits in single byte) = 0x04
        // Value: 4 bytes "/foo"
        assert_eq!(n, 2 + 1 + 1 + 4);
        assert_eq!(buf[2], 0b0111_0000 | 1); // name_index=1 (:path)
    }

    #[test]
    fn literal_name_produces_literal_with_literal_name() {
        let encoder = QpackEncoder::new();
        let headers: &[(&[u8], &[u8])] = &[(b"x-foo", b"bar")];
        let mut buf = [0u8; 256];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        // Preamble: 2 bytes
        // Literal name: first byte = 0b0010_0000 | name_len(5) = 0b0010_0101 = 0x25
        // Name: 5 bytes "x-foo"
        // Value length: 1 byte (3) = 0x03
        // Value: 3 bytes "bar"
        assert_eq!(n, 2 + 1 + 5 + 1 + 3);
        assert_eq!(buf[2], 0b0010_0000 | 5);
    }

    #[test]
    fn roundtrip_all_exact_match_methods() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let methods: &[&[u8]] = &[
            b"CONNECT", b"DELETE", b"GET", b"HEAD", b"OPTIONS", b"POST", b"PUT",
        ];

        for method in methods {
            let headers: &[(&[u8], &[u8])] = &[(b":method", method)];
            let mut buf = [0u8; 256];
            let n = encoder.encode_field_section(headers, &mut buf).unwrap();

            let mut collected = CollectedHeaders::new();
            decoder
                .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
                .unwrap();
            assert_eq!(collected.entries.len(), 1);
            assert_eq!(collected.entries[0].0.as_slice(), b":method");
            assert_eq!(collected.entries[0].1.as_slice(), *method);
        }
    }

    #[test]
    fn roundtrip_all_exact_match_statuses() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let statuses: &[&[u8]] = &[
            b"100", b"103", b"200", b"204", b"206", b"302", b"304", b"400", b"403", b"404", b"421",
            b"425", b"500", b"503",
        ];

        for status in statuses {
            let headers: &[(&[u8], &[u8])] = &[(b":status", status)];
            let mut buf = [0u8; 256];
            let n = encoder.encode_field_section(headers, &mut buf).unwrap();

            let mut collected = CollectedHeaders::new();
            decoder
                .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
                .unwrap();
            assert_eq!(collected.entries.len(), 1);
            assert_eq!(collected.entries[0].0.as_slice(), b":status");
            assert_eq!(collected.entries[0].1.as_slice(), *status);
        }
    }

    #[test]
    fn decode_empty_src_fails() {
        let decoder = QpackDecoder::new();
        let result = decoder.decode_field_section(&[], |_, _| {});
        assert!(result.is_err());
    }

    #[test]
    fn decode_nonzero_ric_fails() {
        let decoder = QpackDecoder::new();
        // RIC = 1 (non-zero), delta_base = 0
        let src = [0x01, 0x00];
        let result = decoder.decode_field_section(&src, |_, _| {});
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Phase 13: Edge case hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn all_99_static_table_entries_encode_decode() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        for (idx, entry) in static_table::STATIC_TABLE.iter().enumerate() {
            // Exact match: encode a single header matching this entry
            let headers: &[(&[u8], &[u8])] = &[(entry.name, entry.value)];
            let mut buf = [0u8; 512];
            let n = encoder
                .encode_field_section(headers, &mut buf)
                .unwrap_or_else(|e| panic!("encode failed for index {idx}: {e:?}"));

            let mut collected = CollectedHeaders::new();
            let consumed = decoder
                .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
                .unwrap_or_else(|e| panic!("decode failed for index {idx}: {e:?}"));

            assert_eq!(consumed, n, "consumed mismatch for index {idx}");
            assert_eq!(
                collected.entries.len(),
                1,
                "expected 1 header for index {idx}"
            );
            assert_eq!(
                collected.entries[0].0.as_slice(),
                entry.name,
                "name mismatch for index {idx}"
            );
            assert_eq!(
                collected.entries[0].1.as_slice(),
                entry.value,
                "value mismatch for index {idx}"
            );
        }
    }

    #[test]
    fn headers_with_empty_values() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[
            (b"x-empty1", b""),
            (b"x-empty2", b""),
            (b":authority", b""), // static table entry 0 has empty value
        ];
        let mut buf = [0u8; 512];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 3);
        assert_eq!(collected.entries[0].1.as_slice(), b"");
        assert_eq!(collected.entries[1].1.as_slice(), b"");
        assert_eq!(collected.entries[2].1.as_slice(), b"");
    }

    #[test]
    fn headers_with_long_values() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        // Value up to buffer limit: use 200 bytes
        let long_value = [0x61u8; 200]; // 200 'a' bytes
        let headers: &[(&[u8], &[u8])] = &[(b"x-long", &long_value)];
        let mut buf = [0u8; 1024];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].1.as_slice(), &long_value[..]);
    }

    #[test]
    fn integer_encoding_at_prefix_boundaries() {
        // Test values at exact prefix boundaries for each prefix size
        let prefixes: &[u8] = &[3, 4, 5, 6, 7, 8];
        for &prefix in prefixes {
            let max_prefix_val = (1u64 << prefix) - 2; // just below multi-byte threshold
            let threshold = (1u64 << prefix) - 1; // exactly at threshold
            let above = threshold + 1; // just above

            for val in [max_prefix_val, threshold, above] {
                let mut buf = [0u8; 16];
                let n = integer::encode_integer(val, prefix, 0, &mut buf).unwrap();
                let (decoded, consumed) = integer::decode_integer(&buf[..n], prefix).unwrap();
                assert_eq!(decoded, val, "prefix={prefix}, value={val}");
                assert_eq!(consumed, n);
            }
        }
    }

    #[test]
    fn decode_invalid_static_index() {
        let decoder = QpackDecoder::new();
        // Manually build: RIC=0, delta_base=0, then indexed static line with index 99 (out of bounds)
        let mut src = [0u8; 16];
        src[0] = 0x00; // RIC=0
        src[1] = 0x00; // delta_base=0
        // Indexed: 0b11_xxxxxx with index=99 (but STATIC_TABLE only has 99 entries, max index=98)
        // 99 > 63 so it needs multi-byte: 0b11_111111, then 99-63=36
        src[2] = 0b1111_1111; // 0xC0 | 0x3F = 0xFF
        src[3] = 36; // 99 - 63 = 36

        let result = decoder.decode_field_section(&src[..4], |_, _| {});
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_mixed_encoding_types() {
        let encoder = QpackEncoder::new();
        let decoder = QpackDecoder::new();

        let headers: &[(&[u8], &[u8])] = &[
            // Exact match (indexed)
            (b":method", b"GET"),
            // Exact match (indexed)
            (b":scheme", b"https"),
            // Name ref + literal value
            (b":path", b"/api/users/123"),
            // Name ref + literal value (authority with value)
            (b":authority", b"example.com:443"),
            // Fully literal
            (b"x-request-id", b"abc-123-def"),
            // Exact match (indexed)
            (b"accept-encoding", b"gzip, deflate, br"),
            // Name ref + literal value
            (b"content-type", b"text/xml"),
        ];
        let mut buf = [0u8; 1024];
        let n = encoder.encode_field_section(headers, &mut buf).unwrap();

        let mut collected = CollectedHeaders::new();
        decoder
            .decode_field_section(&buf[..n], |name, value| collected.push(name, value))
            .unwrap();
        assert_eq!(collected.entries.len(), 7);

        assert_eq!(collected.entries[0].1.as_slice(), b"GET");
        assert_eq!(collected.entries[1].1.as_slice(), b"https");
        assert_eq!(collected.entries[2].1.as_slice(), b"/api/users/123");
        assert_eq!(collected.entries[3].1.as_slice(), b"example.com:443");
        assert_eq!(collected.entries[4].0.as_slice(), b"x-request-id");
        assert_eq!(collected.entries[4].1.as_slice(), b"abc-123-def");
        assert_eq!(collected.entries[5].1.as_slice(), b"gzip, deflate, br");
        assert_eq!(collected.entries[6].1.as_slice(), b"text/xml");
    }
}
