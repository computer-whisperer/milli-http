//! HTTP/3 frame types and encode/decode (RFC 9114 §7).
//!
//! HTTP/3 frames are carried on QUIC streams and use a simple TLV format:
//!
//! ```text
//! Frame {
//!   Type (varint),
//!   Length (varint),
//!   Payload (..)
//! }
//! ```

use crate::error::{Error, H3Error};
use crate::varint::{decode_varint, encode_varint, varint_len};

use super::{
    H3Settings, SETTINGS_MAX_FIELD_SECTION_SIZE, SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
};

// HTTP/3 frame type codes (RFC 9114 §7.2).
const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;
const H3_FRAME_CANCEL_PUSH: u64 = 0x03;
const H3_FRAME_SETTINGS: u64 = 0x04;
const H3_FRAME_PUSH_PROMISE: u64 = 0x05;
const H3_FRAME_GOAWAY: u64 = 0x07;
const H3_FRAME_MAX_PUSH_ID: u64 = 0x0d;

/// HTTP/3 frame (carried on QUIC streams, not QUIC frames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Frame<'a> {
    /// DATA frame (type 0x00).
    Data(&'a [u8]),
    /// HEADERS frame (type 0x01) — QPACK-encoded field section.
    Headers(&'a [u8]),
    /// CANCEL_PUSH frame (type 0x03).
    CancelPush(u64),
    /// SETTINGS frame (type 0x04).
    Settings(H3Settings),
    /// PUSH_PROMISE frame (type 0x05).
    PushPromise(PushPromiseFrame<'a>),
    /// GOAWAY frame (type 0x07).
    GoAway(u64),
    /// MAX_PUSH_ID frame (type 0x0d).
    MaxPushId(u64),
    /// Unknown or reserved frame type — callers should ignore this per RFC 9114 §7.2.8.
    Unknown(u64),
}

/// PUSH_PROMISE frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPromiseFrame<'a> {
    pub push_id: u64,
    pub header_block: &'a [u8],
}

/// Decode a single HTTP/3 frame from a buffer.
///
/// Returns `(frame, bytes_consumed)` on success.
pub fn decode_h3_frame(buf: &[u8]) -> Result<(H3Frame<'_>, usize), Error> {
    // Decode frame type.
    let (frame_type, type_len) = decode_varint(buf)?;
    let rest = &buf[type_len..];

    // Decode payload length.
    let (payload_len, len_len) = decode_varint(rest)?;
    let payload_len = payload_len as usize;
    let header_len = type_len + len_len;
    let rest = &buf[header_len..];

    if rest.len() < payload_len {
        return Err(Error::BufferTooSmall {
            needed: header_len + payload_len,
        });
    }

    let payload = &rest[..payload_len];
    let total_consumed = header_len + payload_len;

    let frame = match frame_type {
        H3_FRAME_DATA => H3Frame::Data(payload),
        H3_FRAME_HEADERS => H3Frame::Headers(payload),
        H3_FRAME_CANCEL_PUSH => {
            let (push_id, id_len) =
                decode_varint(payload).map_err(|_| Error::Http3(H3Error::FrameError))?;
            if id_len != payload_len {
                return Err(Error::Http3(H3Error::FrameError));
            }
            H3Frame::CancelPush(push_id)
        }
        H3_FRAME_SETTINGS => {
            let settings = decode_settings(payload)?;
            H3Frame::Settings(settings)
        }
        H3_FRAME_PUSH_PROMISE => {
            let (push_id, id_len) =
                decode_varint(payload).map_err(|_| Error::Http3(H3Error::FrameError))?;
            let header_block = &payload[id_len..];
            H3Frame::PushPromise(PushPromiseFrame {
                push_id,
                header_block,
            })
        }
        H3_FRAME_GOAWAY => {
            let (stream_id, id_len) =
                decode_varint(payload).map_err(|_| Error::Http3(H3Error::FrameError))?;
            if id_len != payload_len {
                return Err(Error::Http3(H3Error::FrameError));
            }
            H3Frame::GoAway(stream_id)
        }
        H3_FRAME_MAX_PUSH_ID => {
            let (push_id, id_len) =
                decode_varint(payload).map_err(|_| Error::Http3(H3Error::FrameError))?;
            if id_len != payload_len {
                return Err(Error::Http3(H3Error::FrameError));
            }
            H3Frame::MaxPushId(push_id)
        }
        // Unknown or reserved frame types: skip over them per RFC 9114 §7.2.8.
        // "Implementations MUST discard frames [...] that have unknown or unsupported types."
        // H3 frames are TLV, so we can safely skip by consuming type + length + payload.
        _ => H3Frame::Unknown(frame_type),
    };

    Ok((frame, total_consumed))
}

/// Encode an HTTP/3 frame into a buffer.
///
/// Returns the number of bytes written.
pub fn encode_h3_frame(frame: &H3Frame<'_>, buf: &mut [u8]) -> Result<usize, Error> {
    match frame {
        H3Frame::Data(data) => encode_simple_frame(H3_FRAME_DATA, data, buf),
        H3Frame::Headers(data) => encode_simple_frame(H3_FRAME_HEADERS, data, buf),
        H3Frame::CancelPush(push_id) => {
            encode_varint_payload_frame(H3_FRAME_CANCEL_PUSH, *push_id, buf)
        }
        H3Frame::Settings(settings) => encode_settings_frame(settings, buf),
        H3Frame::PushPromise(pp) => encode_push_promise_frame(pp, buf),
        H3Frame::GoAway(stream_id) => encode_varint_payload_frame(H3_FRAME_GOAWAY, *stream_id, buf),
        H3Frame::MaxPushId(push_id) => {
            encode_varint_payload_frame(H3_FRAME_MAX_PUSH_ID, *push_id, buf)
        }
        H3Frame::Unknown(_) => Ok(0), // Unknown frames are receive-only, nothing to encode
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encode a frame whose payload is a raw byte slice (DATA, HEADERS).
fn encode_simple_frame(frame_type: u64, payload: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
    let payload_len = payload.len() as u64;
    let needed = varint_len(frame_type) + varint_len(payload_len) + payload.len();
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut off = 0;
    off += encode_varint(frame_type, &mut buf[off..])?;
    off += encode_varint(payload_len, &mut buf[off..])?;
    buf[off..off + payload.len()].copy_from_slice(payload);
    off += payload.len();
    Ok(off)
}

/// Encode a frame whose payload is a single varint (CancelPush, GoAway, MaxPushId).
fn encode_varint_payload_frame(
    frame_type: u64,
    value: u64,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let payload_size = varint_len(value);
    let needed = varint_len(frame_type) + varint_len(payload_size as u64) + payload_size;
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut off = 0;
    off += encode_varint(frame_type, &mut buf[off..])?;
    off += encode_varint(payload_size as u64, &mut buf[off..])?;
    off += encode_varint(value, &mut buf[off..])?;
    Ok(off)
}

/// Compute the byte size of the settings payload (identifier-value pairs).
fn settings_payload_len(settings: &H3Settings) -> usize {
    let mut len = 0;
    if let Some(v) = settings.max_field_section_size {
        len += varint_len(SETTINGS_MAX_FIELD_SECTION_SIZE) + varint_len(v);
    }
    if let Some(v) = settings.qpack_max_table_capacity {
        len += varint_len(SETTINGS_QPACK_MAX_TABLE_CAPACITY) + varint_len(v);
    }
    if let Some(v) = settings.qpack_blocked_streams {
        len += varint_len(SETTINGS_QPACK_BLOCKED_STREAMS) + varint_len(v);
    }
    len
}

/// Encode a SETTINGS frame.
fn encode_settings_frame(settings: &H3Settings, buf: &mut [u8]) -> Result<usize, Error> {
    let payload_len = settings_payload_len(settings);
    let needed = varint_len(H3_FRAME_SETTINGS) + varint_len(payload_len as u64) + payload_len;
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut off = 0;
    off += encode_varint(H3_FRAME_SETTINGS, &mut buf[off..])?;
    off += encode_varint(payload_len as u64, &mut buf[off..])?;

    // Encode each present setting as identifier (varint) + value (varint).
    if let Some(v) = settings.max_field_section_size {
        off += encode_varint(SETTINGS_MAX_FIELD_SECTION_SIZE, &mut buf[off..])?;
        off += encode_varint(v, &mut buf[off..])?;
    }
    if let Some(v) = settings.qpack_max_table_capacity {
        off += encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY, &mut buf[off..])?;
        off += encode_varint(v, &mut buf[off..])?;
    }
    if let Some(v) = settings.qpack_blocked_streams {
        off += encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS, &mut buf[off..])?;
        off += encode_varint(v, &mut buf[off..])?;
    }

    Ok(off)
}

/// Encode a PUSH_PROMISE frame.
fn encode_push_promise_frame(pp: &PushPromiseFrame<'_>, buf: &mut [u8]) -> Result<usize, Error> {
    let id_len = varint_len(pp.push_id);
    let payload_len = id_len + pp.header_block.len();
    let needed = varint_len(H3_FRAME_PUSH_PROMISE) + varint_len(payload_len as u64) + payload_len;
    if buf.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut off = 0;
    off += encode_varint(H3_FRAME_PUSH_PROMISE, &mut buf[off..])?;
    off += encode_varint(payload_len as u64, &mut buf[off..])?;
    off += encode_varint(pp.push_id, &mut buf[off..])?;
    buf[off..off + pp.header_block.len()].copy_from_slice(pp.header_block);
    off += pp.header_block.len();
    Ok(off)
}

/// Decode the payload of a SETTINGS frame into an [`H3Settings`].
///
/// Unknown setting identifiers are silently ignored per RFC 9114 §7.2.4.1.
fn decode_settings(mut payload: &[u8]) -> Result<H3Settings, Error> {
    let mut settings = H3Settings::default();

    while !payload.is_empty() {
        let (id, id_len) =
            decode_varint(payload).map_err(|_| Error::Http3(H3Error::SettingsError))?;
        payload = &payload[id_len..];

        let (value, val_len) =
            decode_varint(payload).map_err(|_| Error::Http3(H3Error::SettingsError))?;
        payload = &payload[val_len..];

        match id {
            SETTINGS_MAX_FIELD_SECTION_SIZE => {
                settings.max_field_section_size = Some(value);
            }
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                settings.qpack_max_table_capacity = Some(value);
            }
            SETTINGS_QPACK_BLOCKED_STREAMS => {
                settings.qpack_blocked_streams = Some(value);
            }
            // Unknown settings MUST be ignored (RFC 9114 §7.2.4.1).
            _ => {}
        }
    }

    Ok(settings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode then decode, check roundtrip.
    fn roundtrip(frame: &H3Frame<'_>) {
        let mut buf = [0u8; 512];
        let written = encode_h3_frame(frame, &mut buf).expect("encode failed");
        let (decoded, consumed) = decode_h3_frame(&buf[..written]).expect("decode failed");
        assert_eq!(consumed, written, "consumed != written");
        assert_eq!(&decoded, frame, "roundtrip mismatch");
    }

    // -----------------------------------------------------------------------
    // 1. Roundtrip encode/decode for every frame type
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_data() {
        let data = b"Hello, HTTP/3!";
        roundtrip(&H3Frame::Data(data));
    }

    #[test]
    fn roundtrip_headers() {
        let headers = b"\x00\x00\xd1\xd7";
        roundtrip(&H3Frame::Headers(headers));
    }

    #[test]
    fn roundtrip_cancel_push() {
        roundtrip(&H3Frame::CancelPush(42));
    }

    #[test]
    fn roundtrip_settings() {
        let settings = H3Settings {
            max_field_section_size: Some(8192),
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(100),
        };
        roundtrip(&H3Frame::Settings(settings));
    }

    #[test]
    fn roundtrip_push_promise() {
        let pp = PushPromiseFrame {
            push_id: 7,
            header_block: b"\xd1\xd7\x51\x86",
        };
        roundtrip(&H3Frame::PushPromise(pp));
    }

    #[test]
    fn roundtrip_goaway() {
        roundtrip(&H3Frame::GoAway(0));
        roundtrip(&H3Frame::GoAway(12345));
    }

    #[test]
    fn roundtrip_max_push_id() {
        roundtrip(&H3Frame::MaxPushId(0));
        roundtrip(&H3Frame::MaxPushId(999));
    }

    // -----------------------------------------------------------------------
    // 2. Settings frame with various combinations
    // -----------------------------------------------------------------------

    #[test]
    fn settings_empty() {
        let settings = H3Settings::default();
        roundtrip(&H3Frame::Settings(settings));
    }

    #[test]
    fn settings_only_max_field_section_size() {
        let settings = H3Settings {
            max_field_section_size: Some(65536),
            ..Default::default()
        };
        roundtrip(&H3Frame::Settings(settings));
    }

    #[test]
    fn settings_only_qpack_max_table_capacity() {
        let settings = H3Settings {
            qpack_max_table_capacity: Some(0),
            ..Default::default()
        };
        roundtrip(&H3Frame::Settings(settings));
    }

    #[test]
    fn settings_only_qpack_blocked_streams() {
        let settings = H3Settings {
            qpack_blocked_streams: Some(16),
            ..Default::default()
        };
        roundtrip(&H3Frame::Settings(settings));
    }

    #[test]
    fn settings_two_fields() {
        let settings = H3Settings {
            max_field_section_size: Some(1024),
            qpack_blocked_streams: Some(50),
            ..Default::default()
        };
        roundtrip(&H3Frame::Settings(settings));
    }

    // -----------------------------------------------------------------------
    // 3. Settings with unknown identifiers (should be ignored on decode)
    // -----------------------------------------------------------------------

    #[test]
    fn settings_unknown_identifiers_ignored() {
        // Build a SETTINGS frame by hand with an unknown identifier (0xff)
        // followed by a known one.
        let mut buf = [0u8; 64];
        let mut off = 0;

        // Frame type = SETTINGS (0x04)
        off += encode_varint(H3_FRAME_SETTINGS, &mut buf[off..]).unwrap();

        // Compute payload: unknown(0xff)=42, known(0x06)=8192
        // 0xff takes 2 bytes, 42 takes 1 byte, 0x06 takes 1 byte, 8192 takes 4 bytes = 8
        let mut payload = [0u8; 32];
        let mut poff = 0;
        poff += encode_varint(0xff, &mut payload[poff..]).unwrap(); // unknown id
        poff += encode_varint(42, &mut payload[poff..]).unwrap(); // unknown value
        poff += encode_varint(SETTINGS_MAX_FIELD_SECTION_SIZE, &mut payload[poff..]).unwrap();
        poff += encode_varint(8192, &mut payload[poff..]).unwrap();

        // Frame length
        off += encode_varint(poff as u64, &mut buf[off..]).unwrap();
        buf[off..off + poff].copy_from_slice(&payload[..poff]);
        off += poff;

        let (frame, consumed) = decode_h3_frame(&buf[..off]).unwrap();
        assert_eq!(consumed, off);

        let expected = H3Settings {
            max_field_section_size: Some(8192),
            ..Default::default()
        };
        assert_eq!(frame, H3Frame::Settings(expected));
    }

    #[test]
    fn settings_all_unknown_identifiers() {
        // A settings frame with only unknown identifiers should decode to default.
        let mut buf = [0u8; 64];
        let mut off = 0;
        off += encode_varint(H3_FRAME_SETTINGS, &mut buf[off..]).unwrap();

        let mut payload = [0u8; 32];
        let mut poff = 0;
        poff += encode_varint(0xfe, &mut payload[poff..]).unwrap();
        poff += encode_varint(100, &mut payload[poff..]).unwrap();
        poff += encode_varint(0xabcd, &mut payload[poff..]).unwrap();
        poff += encode_varint(200, &mut payload[poff..]).unwrap();

        off += encode_varint(poff as u64, &mut buf[off..]).unwrap();
        buf[off..off + poff].copy_from_slice(&payload[..poff]);
        off += poff;

        let (frame, consumed) = decode_h3_frame(&buf[..off]).unwrap();
        assert_eq!(consumed, off);
        assert_eq!(frame, H3Frame::Settings(H3Settings::default()));
    }

    // -----------------------------------------------------------------------
    // 4. Empty DATA frame
    // -----------------------------------------------------------------------

    #[test]
    fn empty_data_frame() {
        roundtrip(&H3Frame::Data(b""));
    }

    // -----------------------------------------------------------------------
    // 5. Empty HEADERS frame
    // -----------------------------------------------------------------------

    #[test]
    fn empty_headers_frame() {
        roundtrip(&H3Frame::Headers(b""));
    }

    // -----------------------------------------------------------------------
    // 6. Large SETTINGS values
    // -----------------------------------------------------------------------

    #[test]
    fn settings_large_values() {
        let settings = H3Settings {
            max_field_section_size: Some(0x3FFF_FFFF_FFFF_FFFF), // max varint
            qpack_max_table_capacity: Some(1_073_741_824),       // 8-byte varint
            qpack_blocked_streams: Some(0),
        };
        roundtrip(&H3Frame::Settings(settings));
    }

    // -----------------------------------------------------------------------
    // 7. Buffer-too-small errors for encoding
    // -----------------------------------------------------------------------

    #[test]
    fn encode_buffer_too_small_data() {
        let frame = H3Frame::Data(b"hello");
        let mut buf = [0u8; 2]; // too small
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn encode_buffer_too_small_headers() {
        let frame = H3Frame::Headers(b"\xd1\xd7");
        let mut buf = [0u8; 1];
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn encode_buffer_too_small_settings() {
        let frame = H3Frame::Settings(H3Settings {
            max_field_section_size: Some(65536),
            ..Default::default()
        });
        let mut buf = [0u8; 2];
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn encode_buffer_too_small_goaway() {
        let frame = H3Frame::GoAway(999);
        let mut buf = [0u8; 1];
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn encode_buffer_too_small_cancel_push() {
        let frame = H3Frame::CancelPush(1);
        let mut buf = [0u8; 1];
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn encode_buffer_too_small_max_push_id() {
        let frame = H3Frame::MaxPushId(1);
        let mut buf = [0u8; 1];
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn encode_buffer_too_small_push_promise() {
        let pp = PushPromiseFrame {
            push_id: 7,
            header_block: b"\xd1\xd7",
        };
        let frame = H3Frame::PushPromise(pp);
        let mut buf = [0u8; 2];
        let err = encode_h3_frame(&frame, &mut buf).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    // -----------------------------------------------------------------------
    // 8. Truncated frame decoding errors
    // -----------------------------------------------------------------------

    #[test]
    fn decode_empty_buffer() {
        let err = decode_h3_frame(&[]).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn decode_type_only_no_length() {
        // Just a frame type byte, no length.
        let err = decode_h3_frame(&[0x00]).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn decode_truncated_payload() {
        // DATA frame with claimed length 10 but only 3 payload bytes.
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(H3_FRAME_DATA, &mut buf[off..]).unwrap();
        off += encode_varint(10, &mut buf[off..]).unwrap();
        buf[off] = 0xAA;
        buf[off + 1] = 0xBB;
        buf[off + 2] = 0xCC;
        off += 3; // only 3 bytes of "payload"

        let err = decode_h3_frame(&buf[..off]).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn decode_truncated_settings_payload() {
        // SETTINGS frame with length indicating more data than present.
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(H3_FRAME_SETTINGS, &mut buf[off..]).unwrap();
        off += encode_varint(4, &mut buf[off..]).unwrap(); // claims 4 bytes
        off += encode_varint(SETTINGS_MAX_FIELD_SECTION_SIZE, &mut buf[off..]).unwrap(); // 1 byte
        // Missing value — only wrote 1 byte of the 4 claimed.

        let err = decode_h3_frame(&buf[..off]).unwrap_err();
        assert!(matches!(err, Error::BufferTooSmall { .. }));
    }

    #[test]
    fn decode_truncated_cancel_push() {
        // CancelPush with length 0 (no varint in payload).
        let mut buf = [0u8; 8];
        let mut off = 0;
        off += encode_varint(H3_FRAME_CANCEL_PUSH, &mut buf[off..]).unwrap();
        off += encode_varint(0, &mut buf[off..]).unwrap(); // length=0, empty payload

        let err = decode_h3_frame(&buf[..off]).unwrap_err();
        assert!(matches!(err, Error::Http3(H3Error::FrameError)));
    }

    // -----------------------------------------------------------------------
    // 9. Frame type 0x02 (reserved/removed PRIORITY) treated as unknown
    // -----------------------------------------------------------------------

    #[test]
    fn reserved_priority_frame_type_skipped() {
        // Frame type 0x02 was PRIORITY in draft specs, removed in RFC 9114.
        // Per RFC 9114 §7.2.8, unknown frame types are skipped.
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(0x02, &mut buf[off..]).unwrap(); // reserved type
        off += encode_varint(0, &mut buf[off..]).unwrap(); // length=0

        let (frame, consumed) = decode_h3_frame(&buf[..off]).unwrap();
        assert!(matches!(frame, H3Frame::Unknown(0x02)));
        assert_eq!(consumed, off);
    }

    #[test]
    fn unknown_frame_type_skipped_with_payload() {
        // Arbitrary unknown frame type 0x21 with 3-byte payload.
        // Per RFC 9114 §7.2.8, unknown types are skipped (consumed).
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(0x21, &mut buf[off..]).unwrap();
        off += encode_varint(3, &mut buf[off..]).unwrap(); // length=3
        buf[off] = 0x01;
        buf[off + 1] = 0x02;
        buf[off + 2] = 0x03;
        off += 3;

        let (frame, consumed) = decode_h3_frame(&buf[..off]).unwrap();
        assert!(matches!(frame, H3Frame::Unknown(0x21)));
        assert_eq!(consumed, off);
    }

    // -----------------------------------------------------------------------
    // Additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_push_extra_payload_rejected() {
        // CancelPush with more payload than just the varint should be rejected.
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(H3_FRAME_CANCEL_PUSH, &mut buf[off..]).unwrap();
        off += encode_varint(2, &mut buf[off..]).unwrap(); // length=2
        buf[off] = 0x05; // varint 5, 1 byte
        buf[off + 1] = 0xFF; // extra byte
        off += 2;

        let err = decode_h3_frame(&buf[..off]).unwrap_err();
        assert!(matches!(err, Error::Http3(H3Error::FrameError)));
    }

    #[test]
    fn goaway_extra_payload_rejected() {
        // GoAway with trailing bytes should be rejected.
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(H3_FRAME_GOAWAY, &mut buf[off..]).unwrap();
        off += encode_varint(2, &mut buf[off..]).unwrap(); // length=2
        buf[off] = 0x00; // varint 0, 1 byte
        buf[off + 1] = 0xFF; // extra byte
        off += 2;

        let err = decode_h3_frame(&buf[..off]).unwrap_err();
        assert!(matches!(err, Error::Http3(H3Error::FrameError)));
    }

    #[test]
    fn max_push_id_extra_payload_rejected() {
        // MaxPushId with trailing bytes should be rejected.
        let mut buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(H3_FRAME_MAX_PUSH_ID, &mut buf[off..]).unwrap();
        off += encode_varint(2, &mut buf[off..]).unwrap(); // length=2
        buf[off] = 0x00;
        buf[off + 1] = 0xFF;
        off += 2;

        let err = decode_h3_frame(&buf[..off]).unwrap_err();
        assert!(matches!(err, Error::Http3(H3Error::FrameError)));
    }

    #[test]
    fn push_promise_empty_header_block() {
        let pp = PushPromiseFrame {
            push_id: 0,
            header_block: b"",
        };
        roundtrip(&H3Frame::PushPromise(pp));
    }

    #[test]
    fn data_large_payload() {
        let data = [0xABu8; 256];
        roundtrip(&H3Frame::Data(&data));
    }

    #[test]
    fn cancel_push_large_id() {
        roundtrip(&H3Frame::CancelPush(0x3FFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn goaway_large_stream_id() {
        roundtrip(&H3Frame::GoAway(0x3FFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn max_push_id_large() {
        roundtrip(&H3Frame::MaxPushId(0x3FFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn encode_buffer_exact_size() {
        // Verify encoding works with exactly the right size buffer.
        let frame = H3Frame::Data(b"abc");
        // type=0x00 (1 byte) + length=3 (1 byte) + payload (3 bytes) = 5 bytes
        let mut buf = [0u8; 5];
        let written = encode_h3_frame(&frame, &mut buf).unwrap();
        assert_eq!(written, 5);
    }

    // -----------------------------------------------------------------------
    // Phase 13: Edge case hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn zero_length_data_h3() {
        roundtrip(&H3Frame::Data(b""));
    }

    #[test]
    fn settings_with_unknown_identifiers_preserved() {
        // Build a SETTINGS frame with an unknown identifier interleaved
        let mut buf = [0u8; 64];
        let mut off = 0;
        off += encode_varint(H3_FRAME_SETTINGS, &mut buf[off..]).unwrap();

        let mut payload = [0u8; 32];
        let mut poff = 0;
        // Unknown identifier 0x1234
        poff += encode_varint(0x1234, &mut payload[poff..]).unwrap();
        poff += encode_varint(99, &mut payload[poff..]).unwrap();
        // Known: qpack_blocked_streams = 16
        poff += encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS, &mut payload[poff..]).unwrap();
        poff += encode_varint(16, &mut payload[poff..]).unwrap();
        // Unknown identifier 0xFFFF
        poff += encode_varint(0xFFFF, &mut payload[poff..]).unwrap();
        poff += encode_varint(0, &mut payload[poff..]).unwrap();

        off += encode_varint(poff as u64, &mut buf[off..]).unwrap();
        buf[off..off + poff].copy_from_slice(&payload[..poff]);
        off += poff;

        let (frame, consumed) = decode_h3_frame(&buf[..off]).unwrap();
        assert_eq!(consumed, off);
        let expected = H3Settings {
            qpack_blocked_streams: Some(16),
            ..Default::default()
        };
        assert_eq!(frame, H3Frame::Settings(expected));
    }

    #[test]
    fn goaway_max_push_id_value() {
        roundtrip(&H3Frame::GoAway(crate::varint::MAX_VARINT));
    }

    #[test]
    fn push_promise_roundtrip_with_data() {
        let pp = PushPromiseFrame {
            push_id: 42,
            header_block: b"\x00\x00\xd1\xd7\x51\x86\xaa\xbb",
        };
        roundtrip(&H3Frame::PushPromise(pp));
    }

    #[test]
    fn push_promise_large_push_id() {
        let pp = PushPromiseFrame {
            push_id: crate::varint::MAX_VARINT,
            header_block: b"",
        };
        roundtrip(&H3Frame::PushPromise(pp));
    }

    #[test]
    fn multiple_frames_in_buffer() {
        // Encode two frames back-to-back and decode them sequentially.
        let mut buf = [0u8; 64];
        let f1 = H3Frame::Data(b"hi");
        let f2 = H3Frame::GoAway(100);

        let w1 = encode_h3_frame(&f1, &mut buf).unwrap();
        let w2 = encode_h3_frame(&f2, &mut buf[w1..]).unwrap();

        let (d1, c1) = decode_h3_frame(&buf[..w1 + w2]).unwrap();
        assert_eq!(d1, f1);
        assert_eq!(c1, w1);

        let (d2, c2) = decode_h3_frame(&buf[c1..w1 + w2]).unwrap();
        assert_eq!(d2, f2);
        assert_eq!(c2, w2);
    }
}
