//! QPACK/HPACK integer encoding (RFC 7541 Section 5.1).
//!
//! This is a prefix-based integer encoding that is distinct from the QUIC
//! variable-length integer format.  An integer is packed into the low N bits
//! of a byte; if the value does not fit, the remaining value is encoded as a
//! series of 7-bit continuation bytes.

use crate::error::Error;

/// Encode an integer with the given prefix size (1..=8 bits).
///
/// `first_byte_mask` contains the high bits already set in the first byte
/// (the bits above the prefix).  `prefix_bits` is the number of low bits
/// available in the first byte.
///
/// Returns the number of bytes written into `buf`.
pub fn encode_integer(
    value: u64,
    prefix_bits: u8,
    first_byte_mask: u8,
    buf: &mut [u8],
) -> Result<usize, Error> {
    debug_assert!((1..=8).contains(&prefix_bits));

    if buf.is_empty() {
        return Err(Error::BufferTooSmall { needed: 1 });
    }

    let max_prefix: u64 = (1u64 << prefix_bits) - 1;

    if value < max_prefix {
        buf[0] = first_byte_mask | (value as u8);
        Ok(1)
    } else {
        buf[0] = first_byte_mask | (max_prefix as u8);
        let mut remaining = value - max_prefix;
        let mut i = 1;

        loop {
            if i >= buf.len() {
                return Err(Error::BufferTooSmall { needed: i + 1 });
            }
            if remaining >= 128 {
                buf[i] = 0x80 | (remaining & 0x7f) as u8;
                remaining >>= 7;
                i += 1;
            } else {
                buf[i] = remaining as u8;
                i += 1;
                break;
            }
        }

        Ok(i)
    }
}

/// Decode an integer with the given prefix size (1..=8 bits).
///
/// Returns `(value, bytes_consumed)`.
pub fn decode_integer(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), Error> {
    debug_assert!((1..=8).contains(&prefix_bits));

    if buf.is_empty() {
        return Err(Error::BufferTooSmall { needed: 1 });
    }

    let max_prefix: u64 = (1u64 << prefix_bits) - 1;
    let value = u64::from(buf[0]) & max_prefix;

    if value < max_prefix {
        return Ok((value, 1));
    }

    // Multi-byte encoding
    let mut value = max_prefix;
    let mut shift: u32 = 0;
    let mut i = 1;

    loop {
        if i >= buf.len() {
            return Err(Error::BufferTooSmall { needed: i + 1 });
        }

        let byte = buf[i];
        let addition = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Error::Transport(
                crate::error::TransportError::FrameEncodingError,
            ))?;

        value = value.checked_add(addition).ok_or(Error::Transport(
            crate::error::TransportError::FrameEncodingError,
        ))?;

        i += 1;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift > 63 {
            return Err(Error::Transport(
                crate::error::TransportError::FrameEncodingError,
            ));
        }
    }

    Ok((value, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_small_value_prefix5() {
        // Value 10 with 5-bit prefix fits in a single byte.
        let mut buf = [0u8; 16];
        let n = encode_integer(10, 5, 0b1010_0000, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0b1010_0000 | 10);
    }

    #[test]
    fn encode_max_prefix_boundary_prefix5() {
        // Value 30 with 5-bit prefix: max_prefix = 31, so 30 < 31 => single byte.
        let mut buf = [0u8; 16];
        let n = encode_integer(30, 5, 0x00, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 30);
    }

    #[test]
    fn encode_multibyte_prefix5() {
        // Value 1337 with 5-bit prefix (RFC 7541 C.1.3 example).
        // max_prefix = 31
        // 1337 - 31 = 1306
        // 1306 = 0x51A
        // 0x51A in 7-bit chunks: 0x1A (26), 0x0A (10)
        // Bytes: first=0x1F, then 0x9A (26|0x80), then 0x0A (10)
        let mut buf = [0u8; 16];
        let n = encode_integer(1337, 5, 0x00, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf[0], 0x1f); // 31 = 0x1f
        assert_eq!(buf[1], 0x9a); // 26 | 0x80
        assert_eq!(buf[2], 0x0a); // 10
    }

    #[test]
    fn decode_small_prefix5() {
        let buf = [0b1010_1010u8];
        let (val, consumed) = decode_integer(&buf, 5).unwrap();
        assert_eq!(val, 10); // low 5 bits of 0b01010 = 10
        assert_eq!(consumed, 1);
    }

    #[test]
    fn decode_multibyte_prefix5() {
        // Decoding the 1337 example from RFC 7541.
        let buf = [0x1f, 0x9a, 0x0a];
        let (val, consumed) = decode_integer(&buf, 5).unwrap();
        assert_eq!(val, 1337);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn roundtrip_various_prefixes() {
        let prefixes = [1, 2, 3, 4, 5, 6, 7, 8];
        let values = [
            0, 1, 5, 30, 31, 62, 63, 127, 128, 255, 256, 1337, 65535, 100_000,
        ];

        for &prefix in &prefixes {
            for &value in &values {
                let mut buf = [0u8; 16];
                let mask = 0u8;
                let n = encode_integer(value, prefix, mask, &mut buf).unwrap();
                let (decoded, consumed) = decode_integer(&buf[..n], prefix).unwrap();
                assert_eq!(
                    decoded, value,
                    "roundtrip failed: prefix={prefix}, value={value}"
                );
                assert_eq!(consumed, n);
            }
        }
    }

    #[test]
    fn roundtrip_with_mask() {
        // Ensure high bits in the first byte don't corrupt the integer value.
        let mut buf = [0u8; 16];
        let mask = 0b1110_0000;
        let n = encode_integer(42, 5, mask, &mut buf).unwrap();
        assert_eq!(buf[0] & 0b1110_0000, mask);
        let (val, consumed) = decode_integer(&buf[..n], 5).unwrap();
        assert_eq!(val, 42);
        assert_eq!(consumed, n);
    }

    #[test]
    fn roundtrip_large_value() {
        let mut buf = [0u8; 16];
        let val = 1_000_000u64;
        let n = encode_integer(val, 6, 0x00, &mut buf).unwrap();
        let (decoded, consumed) = decode_integer(&buf[..n], 6).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, n);
    }

    #[test]
    fn encode_zero() {
        let mut buf = [0u8; 16];
        let n = encode_integer(0, 5, 0b1100_0000, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0b1100_0000);
    }

    #[test]
    fn decode_empty_buffer() {
        let result = decode_integer(&[], 5);
        assert!(result.is_err());
    }

    #[test]
    fn encode_buffer_too_small() {
        let mut buf = [0u8; 1];
        // Value 1337 needs 3 bytes with prefix 5, so 1-byte buffer fails.
        let result = encode_integer(1337, 5, 0x00, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_truncated_multibyte() {
        // Multi-byte encoding but missing continuation bytes.
        let buf = [0x1f, 0x9a]; // Missing the final byte (no continuation bit clear).
        let result = decode_integer(&buf, 5);
        assert!(result.is_err());
    }

    #[test]
    fn prefix_8_fits_all_single_byte_values() {
        // With prefix=8, values 0..254 fit in one byte.
        for v in 0..255u64 {
            let mut buf = [0u8; 16];
            let n = encode_integer(v, 8, 0x00, &mut buf).unwrap();
            assert_eq!(n, 1);
            let (decoded, _) = decode_integer(&buf[..n], 8).unwrap();
            assert_eq!(decoded, v);
        }
        // Value 255 requires multi-byte.
        let mut buf = [0u8; 16];
        let n = encode_integer(255, 8, 0x00, &mut buf).unwrap();
        assert!(n > 1);
        let (decoded, consumed) = decode_integer(&buf[..n], 8).unwrap();
        assert_eq!(decoded, 255);
        assert_eq!(consumed, n);
    }

    #[test]
    fn prefix_1_only_zero_fits() {
        // With prefix=1, only value 0 fits in a single byte.
        let mut buf = [0u8; 16];
        let n = encode_integer(0, 1, 0b1111_1110, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0b1111_1110);

        let mut buf2 = [0u8; 16];
        let n2 = encode_integer(1, 1, 0b1111_1110, &mut buf2).unwrap();
        assert!(n2 > 1);
        let (decoded, consumed) = decode_integer(&buf2[..n2], 1).unwrap();
        assert_eq!(decoded, 1);
        assert_eq!(consumed, n2);
    }

    // ====== RFC 7541 Appendix C.1 Wire-Format Tests ======

    #[test]
    fn rfc7541_c1_1_encode_10_prefix5() {
        // RFC 7541 C.1.1: Encoding 10 using a 5-bit prefix.
        // 10 < 31 (2^5 - 1), so it fits in a single byte: 0x0a.
        let mut buf = [0u8; 16];
        let n = encode_integer(10, 5, 0x00, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x0a);
        let (decoded, consumed) = decode_integer(&[0x0a], 5).unwrap();
        assert_eq!(decoded, 10);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn rfc7541_c1_2_encode_42_prefix8() {
        // RFC 7541 C.1.2-style: Encoding 42 using an 8-bit prefix.
        // 42 < 255 (2^8 - 1), so it fits in a single byte: 0x2a.
        let mut buf = [0u8; 16];
        let n = encode_integer(42, 8, 0x00, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x2a);
        let (decoded, consumed) = decode_integer(&[0x2a], 8).unwrap();
        assert_eq!(decoded, 42);
        assert_eq!(consumed, 1);
    }
}
