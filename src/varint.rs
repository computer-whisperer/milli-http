//! QUIC variable-length integer encoding (RFC 9000 §16).
//!
//! | 2MSB | Length  | Usable Bits | Range                        |
//! |------|---------|-------------|------------------------------|
//! | 00   | 1 byte  | 6           | 0–63                         |
//! | 01   | 2 bytes | 14          | 0–16383                      |
//! | 10   | 4 bytes | 30          | 0–1073741823                 |
//! | 11   | 8 bytes | 62          | 0–4611686018427387903        |

use crate::error::Error;

/// Maximum value representable as a QUIC varint (2^62 - 1).
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// How many bytes are needed to encode `value`?
pub const fn varint_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// Decode a QUIC variable-length integer from `buf`.
///
/// Returns `(value, bytes_consumed)` on success.
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), Error> {
    if buf.is_empty() {
        return Err(Error::BufferTooSmall { needed: 1 });
    }

    let first = buf[0];
    let len = 1 << (first >> 6);

    if buf.len() < len {
        return Err(Error::BufferTooSmall { needed: len });
    }

    let value = match len {
        1 => u64::from(first & 0x3f),
        2 => {
            let v = u16::from_be_bytes([first & 0x3f, buf[1]]);
            u64::from(v)
        }
        4 => {
            let v = u32::from_be_bytes([first & 0x3f, buf[1], buf[2], buf[3]]);
            u64::from(v)
        }
        8 => u64::from_be_bytes([
            first & 0x3f,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => unreachable!(),
    };

    Ok((value, len))
}

/// Encode a QUIC variable-length integer into `buf`.
///
/// Returns the number of bytes written.
pub fn encode_varint(value: u64, buf: &mut [u8]) -> Result<usize, Error> {
    if value > MAX_VARINT {
        return Err(Error::Transport(
            crate::error::TransportError::InternalError,
        ));
    }

    let len = varint_len(value);

    if buf.len() < len {
        return Err(Error::BufferTooSmall { needed: len });
    }

    match len {
        1 => {
            buf[0] = value as u8;
        }
        2 => {
            let bytes = (value as u16).to_be_bytes();
            buf[0] = bytes[0] | 0x40;
            buf[1] = bytes[1];
        }
        4 => {
            let bytes = (value as u32).to_be_bytes();
            buf[0] = bytes[0] | 0x80;
            buf[1] = bytes[1];
            buf[2] = bytes[2];
            buf[3] = bytes[3];
        }
        8 => {
            let bytes = value.to_be_bytes();
            buf[0] = bytes[0] | 0xc0;
            buf[1] = bytes[1];
            buf[2] = bytes[2];
            buf[3] = bytes[3];
            buf[4] = bytes[4];
            buf[5] = bytes[5];
            buf[6] = bytes[6];
            buf[7] = bytes[7];
        }
        _ => unreachable!(),
    }

    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_1byte() {
        for v in 0..=63u64 {
            let mut buf = [0u8; 8];
            let written = encode_varint(v, &mut buf).unwrap();
            assert_eq!(written, 1);
            let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn roundtrip_2byte() {
        for v in [64, 100, 1000, 16383] {
            let mut buf = [0u8; 8];
            let written = encode_varint(v, &mut buf).unwrap();
            assert_eq!(written, 2);
            let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 2);
        }
    }

    #[test]
    fn roundtrip_4byte() {
        for v in [16384, 100_000, 1_073_741_823] {
            let mut buf = [0u8; 8];
            let written = encode_varint(v, &mut buf).unwrap();
            assert_eq!(written, 4);
            let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 4);
        }
    }

    #[test]
    fn roundtrip_8byte() {
        for v in [1_073_741_824, MAX_VARINT] {
            let mut buf = [0u8; 8];
            let written = encode_varint(v, &mut buf).unwrap();
            assert_eq!(written, 8);
            let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 8);
        }
    }

    /// RFC 9000 §A.1 test vectors.
    #[test]
    fn rfc_test_vectors() {
        // 151288809941952652 => 0xc2197c5eff14e88c
        let input = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let (v, len) = decode_varint(&input).unwrap();
        assert_eq!(v, 151_288_809_941_952_652);
        assert_eq!(len, 8);

        // 494878333 => 0x9d7f3e7d
        let input = [0x9d, 0x7f, 0x3e, 0x7d];
        let (v, len) = decode_varint(&input).unwrap();
        assert_eq!(v, 494_878_333);
        assert_eq!(len, 4);

        // 15293 => 0x7bbd
        let input = [0x7b, 0xbd];
        let (v, len) = decode_varint(&input).unwrap();
        assert_eq!(v, 15293);
        assert_eq!(len, 2);

        // 37 => 0x25
        let input = [0x25];
        let (v, len) = decode_varint(&input).unwrap();
        assert_eq!(v, 37);
        assert_eq!(len, 1);
    }

    #[test]
    fn varint_len_boundaries() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16383), 2);
        assert_eq!(varint_len(16384), 4);
        assert_eq!(varint_len(1_073_741_823), 4);
        assert_eq!(varint_len(1_073_741_824), 8);
        assert_eq!(varint_len(MAX_VARINT), 8);
    }

    #[test]
    fn buffer_too_small_encode() {
        let mut buf = [0u8; 1];
        assert!(encode_varint(16384, &mut buf).is_err());
    }

    #[test]
    fn buffer_too_small_decode() {
        assert!(decode_varint(&[]).is_err());
        // 2-byte varint prefix but only 1 byte of data
        assert!(decode_varint(&[0x40]).is_err());
    }

    #[test]
    fn value_too_large() {
        let mut buf = [0u8; 8];
        assert!(encode_varint(MAX_VARINT + 1, &mut buf).is_err());
    }

    // -----------------------------------------------------------------------
    // Phase 13: Edge case hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn max_62bit_value_roundtrip() {
        let v = MAX_VARINT; // 2^62 - 1
        let mut buf = [0u8; 8];
        let written = encode_varint(v, &mut buf).unwrap();
        assert_eq!(written, 8);
        let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn all_boundary_values_roundtrip() {
        let boundaries = [63u64, 16383, 1073741823, 4611686018427387903];
        let expected_lens = [1, 2, 4, 8];
        for (v, expected_len) in boundaries.iter().zip(expected_lens.iter()) {
            let mut buf = [0u8; 8];
            let written = encode_varint(*v, &mut buf).unwrap();
            assert_eq!(
                written, *expected_len,
                "boundary {v} should need {expected_len} bytes"
            );
            let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, *v);
            assert_eq!(consumed, *expected_len);
        }
    }

    #[test]
    fn truncated_input_2byte() {
        // 2-byte varint prefix (0x40) but only 1 byte
        assert!(decode_varint(&[0x40]).is_err());
    }

    #[test]
    fn truncated_input_4byte() {
        // 4-byte varint prefix (0x80) but only 1, 2, or 3 bytes
        assert!(decode_varint(&[0x80]).is_err());
        assert!(decode_varint(&[0x80, 0x00]).is_err());
        assert!(decode_varint(&[0x80, 0x00, 0x00]).is_err());
    }

    #[test]
    fn truncated_input_8byte() {
        // 8-byte varint prefix (0xC0) but truncated at each length
        for len in 1..8 {
            let mut buf = [0u8; 8];
            buf[0] = 0xC0;
            assert!(
                decode_varint(&buf[..len]).is_err(),
                "should fail at len={len}"
            );
        }
    }

    #[test]
    fn every_single_byte_value_0_to_63() {
        for v in 0..=63u64 {
            let mut buf = [0u8; 1];
            let written = encode_varint(v, &mut buf).unwrap();
            assert_eq!(written, 1);
            let (decoded, consumed) = decode_varint(&buf[..1]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn values_just_above_boundaries() {
        // Just above 1-byte boundary
        let v = 64u64;
        let mut buf = [0u8; 8];
        let written = encode_varint(v, &mut buf).unwrap();
        assert_eq!(written, 2);
        let (decoded, _) = decode_varint(&buf[..written]).unwrap();
        assert_eq!(decoded, v);

        // Just above 2-byte boundary
        let v = 16384u64;
        let written = encode_varint(v, &mut buf).unwrap();
        assert_eq!(written, 4);
        let (decoded, _) = decode_varint(&buf[..written]).unwrap();
        assert_eq!(decoded, v);

        // Just above 4-byte boundary
        let v = 1073741824u64;
        let written = encode_varint(v, &mut buf).unwrap();
        assert_eq!(written, 8);
        let (decoded, _) = decode_varint(&buf[..written]).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn encode_exact_buffer_sizes() {
        // 1-byte value in a 1-byte buffer
        let mut buf = [0u8; 1];
        assert!(encode_varint(0, &mut buf).is_ok());

        // 2-byte value in a 2-byte buffer
        let mut buf = [0u8; 2];
        assert!(encode_varint(64, &mut buf).is_ok());

        // 2-byte value in a 1-byte buffer should fail
        let mut buf = [0u8; 1];
        assert!(encode_varint(64, &mut buf).is_err());

        // 4-byte value in a 4-byte buffer
        let mut buf = [0u8; 4];
        assert!(encode_varint(16384, &mut buf).is_ok());

        // 4-byte value in a 3-byte buffer should fail
        let mut buf = [0u8; 3];
        assert!(encode_varint(16384, &mut buf).is_err());
    }
}
