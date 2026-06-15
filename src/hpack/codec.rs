//! HPACK encoder and decoder (RFC 7541).
//!
//! The **encoder** is static-only: entries not in the static table are sent
//! as literals and nothing is ever indexed, which is always legal.
//!
//! The **decoder** (with the `alloc` feature) maintains a real dynamic table.
//! This is not optional for interop: RFC 7541 §4.2 gives the table an initial
//! size of 4096, and a peer may legally index against it from its very first
//! header block — our `SETTINGS_HEADER_TABLE_SIZE` only binds the peer's
//! encoder once it has processed our SETTINGS and emitted a size update.
//! hyper does exactly this when its requests race the SETTINGS exchange; a
//! static-only decoder then fails mid-block, dropping `:path`/`:method` from
//! whatever request lost the race (observed in the field as bogus 404/405s).
//! Once the peer acknowledges a `SETTINGS_HEADER_TABLE_SIZE` of 0 the size
//! update frees the table, so steady-state memory use is zero.
//!
//! Without `alloc` the decoder remains static-only: incremental-indexing
//! literals are emitted but not stored, and indexed references to the dynamic
//! table fail the block. no_alloc consumers must pair it with peers that do
//! not index (e.g. this crate's own encoder).

#[cfg(feature = "alloc")]
use alloc::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::integer;
use super::static_table::{self, LookupResult, STATIC_TABLE};
use crate::error::Error;

/// RFC 7541 §4.2: the dynamic table's initial maximum size. The peer's
/// encoder may use this much until it acknowledges our
/// `SETTINGS_HEADER_TABLE_SIZE` with a dynamic table size update.
const INITIAL_DYNAMIC_TABLE_SIZE: usize = 4096;

/// RFC 7541 §4.1: per-entry overhead added to the name + value lengths.
const ENTRY_OVERHEAD: usize = 32;

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

/// HPACK decoder. See the module docs for the dynamic-table story; without
/// `alloc` it is static-only.
pub struct HpackDecoder {
    /// Dynamic table, newest entry at the front (index 62 in the combined
    /// address space). Sized per RFC accounting (name + value + 32 per entry).
    #[cfg(feature = "alloc")]
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Current RFC-accounted size of `dynamic`.
    #[cfg(feature = "alloc")]
    dynamic_size: usize,
    /// Current maximum table size: starts at the RFC initial (4096) and
    /// follows the peer's dynamic table size updates.
    #[cfg(feature = "alloc")]
    max_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "alloc")]
            dynamic: VecDeque::new(),
            #[cfg(feature = "alloc")]
            dynamic_size: 0,
            #[cfg(feature = "alloc")]
            max_size: INITIAL_DYNAMIC_TABLE_SIZE,
        }
    }

    /// Look up an index in the combined static + dynamic address space
    /// (RFC 7541 §2.3.3). Returns `(name, value)`.
    fn table_lookup(&self, index: usize) -> Result<(&[u8], &[u8]), Error> {
        if index == 0 {
            return Err(Error::InvalidState);
        }
        if index <= STATIC_TABLE.len() {
            let entry = &STATIC_TABLE[index - 1];
            return Ok((entry.name, entry.value));
        }
        #[cfg(feature = "alloc")]
        if let Some((name, value)) = self.dynamic.get(index - STATIC_TABLE.len() - 1) {
            return Ok((name, value));
        }
        Err(Error::InvalidState)
    }

    /// Insert an entry at the head of the dynamic table, evicting from the
    /// tail per RFC 7541 §4.4. An entry larger than the whole table empties
    /// it and is not stored (also §4.4 — not an error).
    #[cfg(feature = "alloc")]
    fn dynamic_insert(&mut self, name: &[u8], value: &[u8]) {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        while self.dynamic_size + entry_size > self.max_size {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.dynamic_size -= n.len() + v.len() + ENTRY_OVERHEAD,
                None => return, // entry larger than the table: drop it
            }
        }
        self.dynamic.push_front((Vec::from(name), Vec::from(value)));
        self.dynamic_size += entry_size;
    }

    #[cfg(not(feature = "alloc"))]
    fn dynamic_insert(&mut self, _name: &[u8], _value: &[u8]) {}

    /// Apply a dynamic table size update (RFC 7541 §6.3).
    fn resize(&mut self, new_size: usize) -> Result<(), Error> {
        // Strictly the bound is the SETTINGS_HEADER_TABLE_SIZE we advertised
        // once acknowledged; accept anything up to the RFC initial to stay
        // lenient about acknowledgement races.
        if new_size > INITIAL_DYNAMIC_TABLE_SIZE {
            return Err(Error::InvalidState);
        }
        #[cfg(feature = "alloc")]
        {
            self.max_size = new_size;
            while self.dynamic_size > self.max_size {
                if let Some((n, v)) = self.dynamic.pop_back() {
                    self.dynamic_size -= n.len() + v.len() + ENTRY_OVERHEAD;
                } else {
                    break;
                }
            }
            if self.dynamic.is_empty() {
                // A shrink to 0 (the common case once the peer acknowledges
                // our SETTINGS_HEADER_TABLE_SIZE of 0) frees the allocation.
                self.dynamic.shrink_to_fit();
            }
        }
        Ok(())
    }

    /// Decode an HPACK-encoded header block.
    ///
    /// Calls `emit(name, value)` for each decoded header.
    /// Returns the number of bytes consumed.
    pub fn decode<F>(&mut self, src: &[u8], mut emit: F) -> Result<usize, Error>
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
                let (name, value) = self.table_lookup(index as usize)?;
                emit(name, value);
            } else if first & 0b1100_0000 == 0b0100_0000 {
                // §6.2.1 Literal with Incremental Indexing: 01xxxxxx
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 6)?;
                pos += consumed;
                pos += self.decode_literal_field(src, pos, name_index as usize, true, &mut emit)?;
            } else if first & 0b1111_0000 == 0b0000_0000 {
                // §6.2.2 Literal without Indexing: 0000xxxx
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 4)?;
                pos += consumed;
                pos +=
                    self.decode_literal_field(src, pos, name_index as usize, false, &mut emit)?;
            } else if first & 0b1111_0000 == 0b0001_0000 {
                // §6.2.3 Literal Never Indexed: 0001xxxx
                let (name_index, consumed) = integer::decode_integer(&src[pos..], 4)?;
                pos += consumed;
                pos +=
                    self.decode_literal_field(src, pos, name_index as usize, false, &mut emit)?;
            } else if first & 0b1110_0000 == 0b0010_0000 {
                // §6.3 Dynamic Table Size Update: 001xxxxx
                let (new_size, consumed) = integer::decode_integer(&src[pos..], 5)?;
                pos += consumed;
                self.resize(new_size as usize)?;
            } else {
                return Err(Error::InvalidState);
            }
        }

        Ok(pos)
    }

    /// Decode a literal header field (name from index or literal, plus value),
    /// optionally inserting it into the dynamic table (`index` = §6.2.1).
    /// Returns bytes consumed starting from `start`.
    ///
    /// Handles Huffman-encoded strings by decoding into stack-local buffers.
    fn decode_literal_field<F>(
        &mut self,
        src: &[u8],
        start: usize,
        name_index: usize,
        index: bool,
        emit: &mut F,
    ) -> Result<usize, Error>
    where
        F: FnMut(&[u8], &[u8]),
    {
        let mut pos = start;
        let mut name_buf = [0u8; 256];
        let mut val_buf = [0u8; 1024];

        let name_len: usize;
        if name_index > 0 {
            // Name from the static or dynamic table. Copied out because an
            // indexed insert below may evict the entry it came from.
            let (name, _) = self.table_lookup(name_index)?;
            if name.len() > name_buf.len() {
                return Err(Error::BufferTooSmall { needed: name.len() });
            }
            name_buf[..name.len()].copy_from_slice(name);
            name_len = name.len();
        } else {
            // Literal name (may be Huffman-encoded)
            let (huf_n, len_n, lc_n) = Self::parse_string_header(&src[pos..])?;
            let raw_name = &src[pos + lc_n..pos + lc_n + len_n];
            pos += lc_n + len_n;
            if huf_n {
                name_len = super::huffman::decode(raw_name, &mut name_buf)?;
            } else {
                if len_n > name_buf.len() {
                    return Err(Error::BufferTooSmall { needed: len_n });
                }
                name_buf[..len_n].copy_from_slice(raw_name);
                name_len = len_n;
            }
        }

        // Value string (may be Huffman-encoded)
        let (huf_v, len_v, lc_v) = Self::parse_string_header(&src[pos..])?;
        let raw_value = &src[pos + lc_v..pos + lc_v + len_v];
        pos += lc_v + len_v;
        let value: &[u8] = if huf_v {
            let n = super::huffman::decode(raw_value, &mut val_buf)?;
            &val_buf[..n]
        } else {
            raw_value
        };

        let name = &name_buf[..name_len];
        if index {
            self.dynamic_insert(name, value);
        }
        emit(name, value);

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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
        // Indexed field with index 62 (out of range for 61-entry table)
        let buf = [0x80 | 62]; // 0xBE
        assert!(decoder.decode(&buf, |_, _| {}).is_err());
    }

    #[test]
    fn decode_index_zero_is_error() {
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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
        let mut decoder = HpackDecoder::new();
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

    // ===== Dynamic table (RFC 7541 §2.3.2, §4, §6.2.1, §6.3) =====
    //
    // A peer may index against the initial 4096-byte table from its first
    // header block (its obligation to honour our SETTINGS_HEADER_TABLE_SIZE
    // only starts once it acknowledges it). hyper does this whenever its
    // requests race the SETTINGS exchange — see the module docs.

    /// Incremental-indexing literal in one block, indexed reference in the
    /// next: the wire pattern hyper produces for repeated `:authority`.
    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_insert_then_reference_across_blocks() {
        let mut decoder = HpackDecoder::new();
        // 0x42: literal w/ incremental indexing, name = static 2 (:method);
        // value = "PUT" raw. Inserts (:method, PUT) at index 62.
        let block1 = [0x42, 0x03, b'P', b'U', b'T'];
        let mut c = Collected::new();
        decoder.decode(&block1, |n, v| c.push(n, v)).unwrap();
        assert_eq!(c.entries[0].1.as_slice(), b"PUT");

        // 0xbe: indexed field, index 62 (first dynamic entry).
        let block2 = [0xbe];
        let mut c = Collected::new();
        decoder.decode(&block2, |n, v| c.push(n, v)).unwrap();
        assert_eq!(c.entries[0].0.as_slice(), b":method");
        assert_eq!(c.entries[0].1.as_slice(), b"PUT");
    }

    /// An entry inserted earlier in the same block is referenceable later in
    /// that block.
    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_reference_within_block() {
        let mut decoder = HpackDecoder::new();
        let block = [0x42, 0x03, b'P', b'U', b'T', 0xbe];
        let mut c = Collected::new();
        decoder.decode(&block, |n, v| c.push(n, v)).unwrap();
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.entries[1].1.as_slice(), b"PUT");
    }

    /// A literal field may take its *name* from a dynamic entry.
    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_name_reference() {
        let mut decoder = HpackDecoder::new();
        // Insert (x-custom, a) — new-name incremental literal (0x40).
        let block1 = [
            0x40, 0x08, b'x', b'-', b'c', b'u', b's', b't', b'o', b'm', 0x01, b'a',
        ];
        let mut c = Collected::new();
        decoder.decode(&block1, |n, v| c.push(n, v)).unwrap();
        // Literal without indexing, name = index 62 (prefix-4 escape: 0x0f +
        // 47), value "b".
        let block2 = [0x0f, 0x2f, 0x01, b'b'];
        let mut c = Collected::new();
        decoder.decode(&block2, |n, v| c.push(n, v)).unwrap();
        assert_eq!(c.entries[0].0.as_slice(), b"x-custom");
        assert_eq!(c.entries[0].1.as_slice(), b"b");
    }

    /// A size update to 0 (the peer acknowledging our
    /// SETTINGS_HEADER_TABLE_SIZE) evicts everything; stale references then
    /// fail the block.
    #[cfg(feature = "alloc")]
    #[test]
    fn size_update_to_zero_evicts() {
        let mut decoder = HpackDecoder::new();
        let block1 = [0x42, 0x03, b'P', b'U', b'T'];
        decoder.decode(&block1, |_, _| {}).unwrap();
        // 0x20: dynamic table size update, new size 0.
        decoder.decode(&[0x20], |_, _| {}).unwrap();
        assert!(decoder.decode(&[0xbe], |_, _| {}).is_err());
        // Inserts while the table max is 0 are legal but not retained (§4.4).
        decoder.decode(&block1, |_, _| {}).unwrap();
        assert!(decoder.decode(&[0xbe], |_, _| {}).is_err());
    }

    /// A size update above the RFC-initial 4096 is rejected — we never
    /// advertise more.
    #[cfg(feature = "alloc")]
    #[test]
    fn size_update_above_initial_is_error() {
        let mut decoder = HpackDecoder::new();
        // Size update, 5-bit prefix: 0x3f (=31) + varint 4066 → 4097.
        let block = [0x3f, 0xe2, 0x1f];
        assert!(decoder.decode(&block, |_, _| {}).is_err());
    }
}
