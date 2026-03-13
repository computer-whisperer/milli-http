//! HTTP/2 frame codec (RFC 9113 §4).
//!
//! HTTP/2 frames have a fixed 9-byte header:
//! ```text
//!  +-----------------------------------------------+
//!  |                 Length (24)                     |
//!  +---------------+---------------+---------------+
//!  |   Type (8)    |   Flags (8)   |
//!  +-+-------------+---------------+------+--------+
//!  |R|                Stream Identifier (31)        |
//!  +-+----------------------------------------------+
//!  |                Frame Payload (0...)           ...
//!  +-----------------------------------------------+
//! ```

use crate::error::Error;

// Frame type constants (RFC 9113 §6).
pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_PRIORITY: u8 = 0x2;
pub const FRAME_RST_STREAM: u8 = 0x3;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_PING: u8 = 0x6;
pub const FRAME_GOAWAY: u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_CONTINUATION: u8 = 0x9;

// Flag bits.
pub const FLAG_ACK: u8 = 0x1;
pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;

/// HTTP/2 frame header (9 bytes on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2FrameHeader {
    pub length: u32, // 24-bit payload length
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u64, // 31-bit on wire (MSB reserved), u64 for API consistency with H3
}

/// HTTP/2 stream priority weight/dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Priority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u8,
}

/// Decoded HTTP/2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Frame<'a> {
    Data {
        stream_id: u64,
        payload: &'a [u8],
        end_stream: bool,
    },
    Headers {
        stream_id: u64,
        fragment: &'a [u8],
        end_stream: bool,
        end_headers: bool,
        priority: Option<H2Priority>,
    },
    Priority {
        stream_id: u64,
        priority: H2Priority,
    },
    RstStream {
        stream_id: u64,
        error_code: u32,
    },
    Settings {
        ack: bool,
        params: &'a [u8],
    },
    PushPromise {
        stream_id: u64,
        promised_id: u64,
        fragment: &'a [u8],
        end_headers: bool,
    },
    Ping {
        data: [u8; 8],
        ack: bool,
    },
    GoAway {
        last_stream_id: u64,
        error_code: u32,
        debug: &'a [u8],
    },
    WindowUpdate {
        stream_id: u64,
        increment: u32,
    },
    Continuation {
        stream_id: u64,
        fragment: &'a [u8],
        end_headers: bool,
    },
    /// Unknown frame type — skip per RFC 9113 §4.1.
    Unknown {
        frame_type: u8,
        stream_id: u64,
        flags: u8,
        payload: &'a [u8],
    },
}

/// Decode a 9-byte frame header.
pub fn decode_frame_header(buf: &[u8]) -> Result<H2FrameHeader, Error> {
    if buf.len() < 9 {
        return Err(Error::BufferTooSmall { needed: 9 });
    }
    let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
    let frame_type = buf[3];
    let flags = buf[4];
    let stream_id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]) as u64;
    Ok(H2FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    })
}

/// Encode a 9-byte frame header into `buf`.
pub fn encode_frame_header(hdr: &H2FrameHeader, buf: &mut [u8]) -> Result<(), Error> {
    if buf.len() < 9 {
        return Err(Error::BufferTooSmall { needed: 9 });
    }
    if hdr.stream_id > 0x7fff_ffff {
        return Err(Error::InvalidState);
    }
    buf[0] = ((hdr.length >> 16) & 0xff) as u8;
    buf[1] = ((hdr.length >> 8) & 0xff) as u8;
    buf[2] = (hdr.length & 0xff) as u8;
    buf[3] = hdr.frame_type;
    buf[4] = hdr.flags;
    let id_bytes = (hdr.stream_id as u32).to_be_bytes();
    buf[5] = id_bytes[0] & 0x7f; // Clear reserved bit
    buf[6] = id_bytes[1];
    buf[7] = id_bytes[2];
    buf[8] = id_bytes[3];
    Ok(())
}

/// Decode a complete HTTP/2 frame from a buffer.
///
/// Returns `(frame, total_bytes_consumed)`.
/// The buffer must contain at least the full 9-byte header + payload.
pub fn decode_frame(buf: &[u8]) -> Result<(H2Frame<'_>, usize), Error> {
    let hdr = decode_frame_header(buf)?;
    let total = 9 + hdr.length as usize;
    if buf.len() < total {
        return Err(Error::BufferTooSmall { needed: total });
    }
    let payload = &buf[9..total];

    let frame = match hdr.frame_type {
        FRAME_DATA => {
            let (data, _pad_len) = strip_padding(payload, hdr.flags)?;
            H2Frame::Data {
                stream_id: hdr.stream_id,
                payload: data,
                end_stream: hdr.flags & FLAG_END_STREAM != 0,
            }
        }
        FRAME_HEADERS => {
            let (data, _pad_len) = strip_padding(payload, hdr.flags)?;
            let (priority, fragment) = if hdr.flags & FLAG_PRIORITY != 0 {
                if data.len() < 5 {
                    return Err(Error::BufferTooSmall { needed: 5 });
                }
                let exclusive = data[0] & 0x80 != 0;
                let dependency = u32::from_be_bytes([data[0] & 0x7f, data[1], data[2], data[3]]);
                let weight = data[4];
                (
                    Some(H2Priority {
                        exclusive,
                        dependency,
                        weight,
                    }),
                    &data[5..],
                )
            } else {
                (None, data)
            };
            H2Frame::Headers {
                stream_id: hdr.stream_id,
                fragment,
                end_stream: hdr.flags & FLAG_END_STREAM != 0,
                end_headers: hdr.flags & FLAG_END_HEADERS != 0,
                priority,
            }
        }
        FRAME_PRIORITY => {
            // RFC 9113 §6.3: PRIORITY must not be on stream 0
            if hdr.stream_id == 0 {
                return Err(Error::InvalidState);
            }
            if payload.len() != 5 {
                return Err(Error::InvalidState);
            }
            let exclusive = payload[0] & 0x80 != 0;
            let dependency =
                u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
            let weight = payload[4];
            H2Frame::Priority {
                stream_id: hdr.stream_id,
                priority: H2Priority {
                    exclusive,
                    dependency,
                    weight,
                },
            }
        }
        FRAME_RST_STREAM => {
            // RFC 9113 §6.4: RST_STREAM must not be on stream 0
            if hdr.stream_id == 0 {
                return Err(Error::InvalidState);
            }
            if payload.len() != 4 {
                return Err(Error::InvalidState);
            }
            let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            H2Frame::RstStream {
                stream_id: hdr.stream_id,
                error_code,
            }
        }
        FRAME_SETTINGS => {
            // RFC 9113 §6.5: SETTINGS must be on stream 0
            if hdr.stream_id != 0 {
                return Err(Error::InvalidState);
            }
            H2Frame::Settings {
                ack: hdr.flags & FLAG_ACK != 0,
                params: payload,
            }
        }
        FRAME_PUSH_PROMISE => {
            let (data, _pad_len) = strip_padding(payload, hdr.flags)?;
            if data.len() < 4 {
                return Err(Error::BufferTooSmall { needed: 4 });
            }
            let promised_id =
                u32::from_be_bytes([data[0] & 0x7f, data[1], data[2], data[3]]) as u64;
            H2Frame::PushPromise {
                stream_id: hdr.stream_id,
                promised_id,
                fragment: &data[4..],
                end_headers: hdr.flags & FLAG_END_HEADERS != 0,
            }
        }
        FRAME_PING => {
            // RFC 9113 §6.7: PING must be on stream 0
            if hdr.stream_id != 0 {
                return Err(Error::InvalidState);
            }
            if payload.len() != 8 {
                return Err(Error::InvalidState);
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(payload);
            H2Frame::Ping {
                data,
                ack: hdr.flags & FLAG_ACK != 0,
            }
        }
        FRAME_GOAWAY => {
            // RFC 9113 §6.8: GOAWAY must be on stream 0
            if hdr.stream_id != 0 {
                return Err(Error::InvalidState);
            }
            if payload.len() < 8 {
                return Err(Error::BufferTooSmall { needed: 8 });
            }
            let last_stream_id =
                u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]) as u64;
            let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            H2Frame::GoAway {
                last_stream_id,
                error_code,
                debug: &payload[8..],
            }
        }
        FRAME_WINDOW_UPDATE => {
            if payload.len() != 4 {
                return Err(Error::InvalidState);
            }
            let increment =
                u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
            H2Frame::WindowUpdate {
                stream_id: hdr.stream_id,
                increment,
            }
        }
        FRAME_CONTINUATION => H2Frame::Continuation {
            stream_id: hdr.stream_id,
            fragment: payload,
            end_headers: hdr.flags & FLAG_END_HEADERS != 0,
        },
        _ => H2Frame::Unknown {
            frame_type: hdr.frame_type,
            stream_id: hdr.stream_id,
            flags: hdr.flags,
            payload,
        },
    };

    Ok((frame, total))
}

/// Encode an HTTP/2 frame into a buffer.
///
/// Returns the total number of bytes written (header + payload).
pub fn encode_frame(frame: &H2Frame<'_>, buf: &mut [u8]) -> Result<usize, Error> {
    match frame {
        H2Frame::Data {
            stream_id,
            payload,
            end_stream,
        } => {
            let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
            let hdr = H2FrameHeader {
                length: payload.len() as u32,
                frame_type: FRAME_DATA,
                flags,
                stream_id: *stream_id,
            };
            let total = 9 + payload.len();
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..9 + payload.len()].copy_from_slice(payload);
            Ok(total)
        }
        H2Frame::Headers {
            stream_id,
            fragment,
            end_stream,
            end_headers,
            priority,
        } => {
            let mut flags = 0u8;
            if *end_stream {
                flags |= FLAG_END_STREAM;
            }
            if *end_headers {
                flags |= FLAG_END_HEADERS;
            }
            let priority_len = if priority.is_some() {
                flags |= FLAG_PRIORITY;
                5
            } else {
                0
            };
            let payload_len = priority_len + fragment.len();
            let hdr = H2FrameHeader {
                length: payload_len as u32,
                frame_type: FRAME_HEADERS,
                flags,
                stream_id: *stream_id,
            };
            let total = 9 + payload_len;
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            let mut off = 9;
            if let Some(p) = priority {
                let dep = if p.exclusive {
                    p.dependency | 0x8000_0000
                } else {
                    p.dependency
                };
                let dep_bytes = dep.to_be_bytes();
                buf[off..off + 4].copy_from_slice(&dep_bytes);
                buf[off + 4] = p.weight;
                off += 5;
            }
            buf[off..off + fragment.len()].copy_from_slice(fragment);
            Ok(total)
        }
        H2Frame::Priority {
            stream_id,
            priority,
        } => {
            let hdr = H2FrameHeader {
                length: 5,
                frame_type: FRAME_PRIORITY,
                flags: 0,
                stream_id: *stream_id,
            };
            let total = 14;
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            let dep = if priority.exclusive {
                priority.dependency | 0x8000_0000
            } else {
                priority.dependency
            };
            buf[9..13].copy_from_slice(&dep.to_be_bytes());
            buf[13] = priority.weight;
            Ok(total)
        }
        H2Frame::RstStream {
            stream_id,
            error_code,
        } => {
            let hdr = H2FrameHeader {
                length: 4,
                frame_type: FRAME_RST_STREAM,
                flags: 0,
                stream_id: *stream_id,
            };
            if buf.len() < 13 {
                return Err(Error::BufferTooSmall { needed: 13 });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..13].copy_from_slice(&error_code.to_be_bytes());
            Ok(13)
        }
        H2Frame::Settings { ack, params } => {
            let flags = if *ack { FLAG_ACK } else { 0 };
            let hdr = H2FrameHeader {
                length: params.len() as u32,
                frame_type: FRAME_SETTINGS,
                flags,
                stream_id: 0,
            };
            let total = 9 + params.len();
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..total].copy_from_slice(params);
            Ok(total)
        }
        H2Frame::PushPromise {
            stream_id,
            promised_id,
            fragment,
            end_headers,
        } => {
            let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
            let payload_len = 4 + fragment.len();
            let hdr = H2FrameHeader {
                length: payload_len as u32,
                frame_type: FRAME_PUSH_PROMISE,
                flags,
                stream_id: *stream_id,
            };
            let total = 9 + payload_len;
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..13].copy_from_slice(&((*promised_id as u32) & 0x7fff_ffff).to_be_bytes());
            buf[13..total].copy_from_slice(fragment);
            Ok(total)
        }
        H2Frame::Ping { data, ack } => {
            let flags = if *ack { FLAG_ACK } else { 0 };
            let hdr = H2FrameHeader {
                length: 8,
                frame_type: FRAME_PING,
                flags,
                stream_id: 0,
            };
            if buf.len() < 17 {
                return Err(Error::BufferTooSmall { needed: 17 });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..17].copy_from_slice(data);
            Ok(17)
        }
        H2Frame::GoAway {
            last_stream_id,
            error_code,
            debug,
        } => {
            let payload_len = 8 + debug.len();
            let hdr = H2FrameHeader {
                length: payload_len as u32,
                frame_type: FRAME_GOAWAY,
                flags: 0,
                stream_id: 0,
            };
            let total = 9 + payload_len;
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..13].copy_from_slice(&((*last_stream_id as u32) & 0x7fff_ffff).to_be_bytes());
            buf[13..17].copy_from_slice(&error_code.to_be_bytes());
            buf[17..total].copy_from_slice(debug);
            Ok(total)
        }
        H2Frame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let hdr = H2FrameHeader {
                length: 4,
                frame_type: FRAME_WINDOW_UPDATE,
                flags: 0,
                stream_id: *stream_id,
            };
            if buf.len() < 13 {
                return Err(Error::BufferTooSmall { needed: 13 });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..13].copy_from_slice(&(*increment & 0x7fff_ffff).to_be_bytes());
            Ok(13)
        }
        H2Frame::Continuation {
            stream_id,
            fragment,
            end_headers,
        } => {
            let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
            let hdr = H2FrameHeader {
                length: fragment.len() as u32,
                frame_type: FRAME_CONTINUATION,
                flags,
                stream_id: *stream_id,
            };
            let total = 9 + fragment.len();
            if buf.len() < total {
                return Err(Error::BufferTooSmall { needed: total });
            }
            encode_frame_header(&hdr, buf)?;
            buf[9..total].copy_from_slice(fragment);
            Ok(total)
        }
        H2Frame::Unknown { .. } => Ok(0),
    }
}

/// Strip PADDED framing if the PADDED flag is set.
/// Returns (unpadded_data, padding_length).
fn strip_padding(payload: &[u8], flags: u8) -> Result<(&[u8], usize), Error> {
    if flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(Error::BufferTooSmall { needed: 1 });
        }
        let pad_len = payload[0] as usize;
        if pad_len >= payload.len() {
            return Err(Error::InvalidState);
        }
        Ok((&payload[1..payload.len() - pad_len], pad_len))
    } else {
        Ok((payload, 0))
    }
}

// ---------------------------------------------------------------------------
// H2 Settings parameter helpers
// ---------------------------------------------------------------------------

/// HTTP/2 settings identifiers (RFC 9113 §6.5.2).
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// Encode a single settings parameter (6 bytes: u16 id + u32 value).
pub fn encode_setting(id: u16, value: u32, buf: &mut [u8]) -> Result<usize, Error> {
    if buf.len() < 6 {
        return Err(Error::BufferTooSmall { needed: 6 });
    }
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2..6].copy_from_slice(&value.to_be_bytes());
    Ok(6)
}

/// Decode settings parameters from a SETTINGS frame payload.
/// Calls `emit(id, value)` for each parameter.
pub fn decode_settings_params<F>(payload: &[u8], mut emit: F) -> Result<(), Error>
where
    F: FnMut(u16, u32) -> Result<(), Error>,
{
    if !payload.len().is_multiple_of(6) {
        return Err(Error::InvalidState);
    }
    let mut pos = 0;
    while pos + 6 <= payload.len() {
        let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let value = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);
        emit(id, value)?;
        pos += 6;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: &H2Frame<'_>) {
        let mut buf = [0u8; 1024];
        let written = encode_frame(frame, &mut buf).expect("encode failed");
        let (decoded, consumed) = decode_frame(&buf[..written]).expect("decode failed");
        assert_eq!(consumed, written, "consumed != written");
        assert_eq!(&decoded, frame, "roundtrip mismatch");
    }

    #[test]
    fn roundtrip_data() {
        roundtrip(&H2Frame::Data {
            stream_id: 1,
            payload: b"Hello, HTTP/2!",
            end_stream: false,
        });
    }

    #[test]
    fn roundtrip_data_end_stream() {
        roundtrip(&H2Frame::Data {
            stream_id: 3,
            payload: b"",
            end_stream: true,
        });
    }

    #[test]
    fn roundtrip_headers_simple() {
        roundtrip(&H2Frame::Headers {
            stream_id: 1,
            fragment: b"\x82\x86\x84",
            end_stream: true,
            end_headers: true,
            priority: None,
        });
    }

    #[test]
    fn roundtrip_headers_with_priority() {
        roundtrip(&H2Frame::Headers {
            stream_id: 5,
            fragment: b"\x82",
            end_stream: false,
            end_headers: true,
            priority: Some(H2Priority {
                exclusive: true,
                dependency: 0,
                weight: 255,
            }),
        });
    }

    #[test]
    fn roundtrip_priority() {
        roundtrip(&H2Frame::Priority {
            stream_id: 3,
            priority: H2Priority {
                exclusive: false,
                dependency: 1,
                weight: 16,
            },
        });
    }

    #[test]
    fn roundtrip_rst_stream() {
        roundtrip(&H2Frame::RstStream {
            stream_id: 1,
            error_code: 0x8, // CANCEL
        });
    }

    #[test]
    fn roundtrip_settings_empty() {
        roundtrip(&H2Frame::Settings {
            ack: false,
            params: &[],
        });
    }

    #[test]
    fn roundtrip_settings_ack() {
        roundtrip(&H2Frame::Settings {
            ack: true,
            params: &[],
        });
    }

    #[test]
    fn roundtrip_settings_with_params() {
        // One setting: INITIAL_WINDOW_SIZE = 65535
        let mut params = [0u8; 6];
        encode_setting(SETTINGS_INITIAL_WINDOW_SIZE, 65535, &mut params).unwrap();
        roundtrip(&H2Frame::Settings {
            ack: false,
            params: &params,
        });
    }

    #[test]
    fn roundtrip_push_promise() {
        roundtrip(&H2Frame::PushPromise {
            stream_id: 1,
            promised_id: 2,
            fragment: b"\x88",
            end_headers: true,
        });
    }

    #[test]
    fn roundtrip_ping() {
        roundtrip(&H2Frame::Ping {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
            ack: false,
        });
    }

    #[test]
    fn roundtrip_ping_ack() {
        roundtrip(&H2Frame::Ping {
            data: [0xff; 8],
            ack: true,
        });
    }

    #[test]
    fn roundtrip_goaway() {
        roundtrip(&H2Frame::GoAway {
            last_stream_id: 7,
            error_code: 0,
            debug: b"",
        });
    }

    #[test]
    fn roundtrip_goaway_with_debug() {
        roundtrip(&H2Frame::GoAway {
            last_stream_id: 100,
            error_code: 0x1,
            debug: b"protocol error",
        });
    }

    #[test]
    fn roundtrip_window_update() {
        roundtrip(&H2Frame::WindowUpdate {
            stream_id: 0,
            increment: 65535,
        });
    }

    #[test]
    fn roundtrip_window_update_stream() {
        roundtrip(&H2Frame::WindowUpdate {
            stream_id: 3,
            increment: 1024,
        });
    }

    #[test]
    fn roundtrip_continuation() {
        roundtrip(&H2Frame::Continuation {
            stream_id: 1,
            fragment: b"\x88\x82",
            end_headers: false,
        });
    }

    #[test]
    fn roundtrip_continuation_end() {
        roundtrip(&H2Frame::Continuation {
            stream_id: 1,
            fragment: b"\x86",
            end_headers: true,
        });
    }

    #[test]
    fn decode_unknown_frame_type() {
        // Frame type 0xFE with 3 bytes of payload
        let mut buf = [0u8; 12];
        let hdr = H2FrameHeader {
            length: 3,
            frame_type: 0xfe,
            flags: 0x42,
            stream_id: 5,
        };
        encode_frame_header(&hdr, &mut buf).unwrap();
        buf[9] = 0xAA;
        buf[10] = 0xBB;
        buf[11] = 0xCC;

        let (frame, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, 12);
        match frame {
            H2Frame::Unknown {
                frame_type,
                stream_id,
                flags,
                payload,
            } => {
                assert_eq!(frame_type, 0xfe);
                assert_eq!(stream_id, 5);
                assert_eq!(flags, 0x42);
                assert_eq!(payload, &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn frame_header_roundtrip() {
        let hdr = H2FrameHeader {
            length: 0x123456 & 0xFFFFFF,
            frame_type: 0x01,
            flags: 0x25,
            stream_id: 42,
        };
        let mut buf = [0u8; 9];
        encode_frame_header(&hdr, &mut buf).unwrap();
        let decoded = decode_frame_header(&buf).unwrap();
        // length is only 24 bits
        assert_eq!(decoded.length, hdr.length & 0xFFFFFF);
        assert_eq!(decoded.frame_type, hdr.frame_type);
        assert_eq!(decoded.flags, hdr.flags);
        assert_eq!(decoded.stream_id, hdr.stream_id);
    }

    #[test]
    fn decode_truncated_header() {
        let buf = [0u8; 5];
        assert!(decode_frame(&buf).is_err());
    }

    #[test]
    fn decode_truncated_payload() {
        let mut buf = [0u8; 12];
        let hdr = H2FrameHeader {
            length: 10,
            frame_type: FRAME_DATA,
            flags: 0,
            stream_id: 1,
        };
        encode_frame_header(&hdr, &mut buf).unwrap();
        // Only 3 bytes of payload instead of 10
        assert!(decode_frame(&buf).is_err());
    }

    #[test]
    fn encode_buffer_too_small() {
        let frame = H2Frame::Data {
            stream_id: 1,
            payload: b"hello",
            end_stream: false,
        };
        let mut buf = [0u8; 5];
        assert!(encode_frame(&frame, &mut buf).is_err());
    }

    #[test]
    fn settings_params_encode_decode() {
        let mut buf = [0u8; 18];
        let mut off = 0;
        off += encode_setting(SETTINGS_HEADER_TABLE_SIZE, 4096, &mut buf[off..]).unwrap();
        off += encode_setting(SETTINGS_MAX_CONCURRENT_STREAMS, 100, &mut buf[off..]).unwrap();
        off += encode_setting(SETTINGS_INITIAL_WINDOW_SIZE, 65535, &mut buf[off..]).unwrap();

        let mut params = heapless::Vec::<(u16, u32), 8>::new();
        decode_settings_params(&buf[..off], |id, val| {
            let _ = params.push((id, val));
            Ok(())
        })
        .unwrap();

        assert_eq!(params.len(), 3);
        assert_eq!(params[0], (SETTINGS_HEADER_TABLE_SIZE, 4096));
        assert_eq!(params[1], (SETTINGS_MAX_CONCURRENT_STREAMS, 100));
        assert_eq!(params[2], (SETTINGS_INITIAL_WINDOW_SIZE, 65535));
    }

    #[test]
    fn settings_params_odd_length_error() {
        let buf = [0u8; 5]; // Not a multiple of 6
        assert!(decode_settings_params(&buf, |_, _| Ok(())).is_err());
    }

    #[test]
    fn ping_frame_is_exactly_8_bytes_payload() {
        let frame = H2Frame::Ping {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
            ack: false,
        };
        let mut buf = [0u8; 17];
        let n = encode_frame(&frame, &mut buf).unwrap();
        assert_eq!(n, 17); // 9 header + 8 payload
    }

    #[test]
    fn rst_stream_wrong_length() {
        let mut buf = [0u8; 12];
        let hdr = H2FrameHeader {
            length: 3, // Should be 4
            frame_type: FRAME_RST_STREAM,
            flags: 0,
            stream_id: 1,
        };
        encode_frame_header(&hdr, &mut buf).unwrap();
        assert!(decode_frame(&buf).is_err());
    }

    #[test]
    fn window_update_wrong_length() {
        let mut buf = [0u8; 14];
        let hdr = H2FrameHeader {
            length: 5, // Should be 4
            frame_type: FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id: 0,
        };
        encode_frame_header(&hdr, &mut buf).unwrap();
        assert!(decode_frame(&buf).is_err());
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let f1 = H2Frame::Data {
            stream_id: 1,
            payload: b"hi",
            end_stream: false,
        };
        let f2 = H2Frame::Ping {
            data: [0; 8],
            ack: true,
        };
        let mut buf = [0u8; 64];
        let w1 = encode_frame(&f1, &mut buf).unwrap();
        let w2 = encode_frame(&f2, &mut buf[w1..]).unwrap();

        let (d1, c1) = decode_frame(&buf[..w1 + w2]).unwrap();
        assert_eq!(d1, f1);
        assert_eq!(c1, w1);

        let (d2, c2) = decode_frame(&buf[c1..w1 + w2]).unwrap();
        assert_eq!(d2, f2);
        assert_eq!(c2, w2);
    }

    #[test]
    fn large_data_frame() {
        let data = [0xABu8; 500];
        roundtrip(&H2Frame::Data {
            stream_id: 1,
            payload: &data,
            end_stream: true,
        });
    }

    #[test]
    fn goaway_max_stream_id() {
        roundtrip(&H2Frame::GoAway {
            last_stream_id: 0x7fff_ffff,
            error_code: 0,
            debug: b"",
        });
    }

    // ====== Wire-Format Decode Tests ======
    // Each test decodes hand-crafted byte sequences matching RFC 9113 wire format,
    // verifying our decoder against independently-constructed frames.

    #[test]
    fn wire_settings_frame_empty() {
        // Empty SETTINGS: length=0, type=4, flags=0, stream=0
        let wire: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(
            frame,
            H2Frame::Settings {
                ack: false,
                params: &[]
            }
        );
    }

    #[test]
    fn wire_settings_ack() {
        // SETTINGS ACK: length=0, type=4, flags=1, stream=0
        let wire: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(
            frame,
            H2Frame::Settings {
                ack: true,
                params: &[]
            }
        );
    }

    #[test]
    fn wire_settings_with_params() {
        // SETTINGS with INITIAL_WINDOW_SIZE(0x0004)=65535: length=6, type=4, flags=0, stream=0
        let wire: &[u8] = &[
            0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x00, 0x04, 0x00, 0x00, 0xff, 0xff, // setting: id=4, value=65535
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 15);
        assert_eq!(
            frame,
            H2Frame::Settings {
                ack: false,
                params: &[0x00, 0x04, 0x00, 0x00, 0xff, 0xff],
            }
        );
    }

    #[test]
    fn wire_data_frame() {
        // DATA on stream 1: length=5, type=0, flags=0, stream=1
        let wire: &[u8] = &[
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // header
            b'h', b'e', b'l', b'l', b'o', // payload
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 14);
        assert_eq!(
            frame,
            H2Frame::Data {
                stream_id: 1,
                payload: b"hello",
                end_stream: false,
            }
        );
    }

    #[test]
    fn wire_data_end_stream() {
        // DATA+END_STREAM on stream 1: length=5, type=0, flags=1, stream=1
        let wire: &[u8] = &[
            0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // header
            b'h', b'e', b'l', b'l', b'o', // payload
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 14);
        assert_eq!(
            frame,
            H2Frame::Data {
                stream_id: 1,
                payload: b"hello",
                end_stream: true,
            }
        );
    }

    #[test]
    fn wire_headers_end_stream_end_headers() {
        // HEADERS: length=3, type=1, flags=0x05 (END_STREAM|END_HEADERS), stream=1
        // Payload: HPACK-encoded :method GET, :scheme http, :path /
        let wire: &[u8] = &[
            0x00, 0x00, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, // header
            0x82, 0x86, 0x84, // HPACK fragment
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(
            frame,
            H2Frame::Headers {
                stream_id: 1,
                fragment: &[0x82, 0x86, 0x84],
                end_stream: true,
                end_headers: true,
                priority: None,
            }
        );
    }

    #[test]
    fn wire_goaway_no_error() {
        // GOAWAY: length=8, type=7, flags=0, stream=0
        // last_stream_id=0, error_code=0
        let wire: &[u8] = &[
            0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x00, 0x00, 0x00, 0x00, // last_stream_id
            0x00, 0x00, 0x00, 0x00, // error_code
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 17);
        assert_eq!(
            frame,
            H2Frame::GoAway {
                last_stream_id: 0,
                error_code: 0,
                debug: &[],
            }
        );
    }

    #[test]
    fn wire_window_update() {
        // WINDOW_UPDATE: length=4, type=8, flags=0, stream=0, increment=65535
        let wire: &[u8] = &[
            0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x00, 0x00, 0xff, 0xff, // increment
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 13);
        assert_eq!(
            frame,
            H2Frame::WindowUpdate {
                stream_id: 0,
                increment: 65535,
            }
        );
    }

    #[test]
    fn wire_ping() {
        // PING: length=8, type=6, flags=0, stream=0, data=[1..8]
        let wire: &[u8] = &[
            0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // ping data
        ];
        let (frame, consumed) = decode_frame(wire).unwrap();
        assert_eq!(consumed, 17);
        assert_eq!(
            frame,
            H2Frame::Ping {
                data: [1, 2, 3, 4, 5, 6, 7, 8],
                ack: false,
            }
        );
    }
}
