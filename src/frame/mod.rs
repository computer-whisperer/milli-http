//! QUIC frame codec (RFC 9000 sections 12.4, 19).
//!
//! Pure encode/decode -- no I/O, no state machines.  Frame data fields borrow
//! from the caller-provided buffer (zero-copy).

use crate::error::{Error, TransportError};
use crate::varint::{decode_varint, encode_varint};

// ---------------------------------------------------------------------------
// Sub-structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame<'a> {
    pub largest_ack: u64,
    pub ack_delay: u64,
    pub first_ack_range: u64,
    /// Raw remaining ACK range bytes (pairs of gap + range varints).
    pub ack_ranges: &'a [u8],
    pub ecn: Option<EcnCounts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ecn_ce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamFrame {
    pub stream_id: u64,
    pub error_code: u64,
    pub final_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSendingFrame {
    pub stream_id: u64,
    pub error_code: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFrame<'a> {
    pub offset: u64,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTokenFrame<'a> {
    pub token: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame<'a> {
    pub stream_id: u64,
    pub offset: u64,
    pub data: &'a [u8],
    pub fin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: u64,
    pub max_data: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamsFrame {
    pub bidirectional: bool,
    pub max_streams: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDataBlockedFrame {
    pub stream_id: u64,
    pub data_limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamsBlockedFrame {
    pub bidirectional: bool,
    pub max_streams: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConnectionIdFrame<'a> {
    pub sequence_number: u64,
    pub retire_prior_to: u64,
    pub connection_id: &'a [u8],
    pub stateless_reset_token: &'a [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCloseFrame<'a> {
    /// `true` for application close (0x1d), `false` for transport close (0x1c).
    pub is_application: bool,
    pub error_code: u64,
    /// Only meaningful for transport close (0x1c).
    pub frame_type: u64,
    pub reason: &'a [u8],
}

// ---------------------------------------------------------------------------
// Frame enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding,                                   // 0x00
    Ping,                                      // 0x01
    Ack(AckFrame<'a>),                         // 0x02-0x03
    ResetStream(ResetStreamFrame),             // 0x04
    StopSending(StopSendingFrame),             // 0x05
    Crypto(CryptoFrame<'a>),                   // 0x06
    NewToken(NewTokenFrame<'a>),               // 0x07
    Stream(StreamFrame<'a>),                   // 0x08-0x0f
    MaxData(u64),                              // 0x10
    MaxStreamData(MaxStreamDataFrame),         // 0x11
    MaxStreams(MaxStreamsFrame),               // 0x12-0x13
    DataBlocked(u64),                          // 0x14
    StreamDataBlocked(StreamDataBlockedFrame), // 0x15
    StreamsBlocked(StreamsBlockedFrame),       // 0x16-0x17
    NewConnectionId(NewConnectionIdFrame<'a>), // 0x18
    RetireConnectionId(u64),                   // 0x19
    PathChallenge([u8; 8]),                    // 0x1a
    PathResponse([u8; 8]),                     // 0x1b
    ConnectionClose(ConnectionCloseFrame<'a>), // 0x1c-0x1d
    HandshakeDone,                             // 0x1e
}

// ---------------------------------------------------------------------------
// ACK range iterator
// ---------------------------------------------------------------------------

/// Iterator over decoded ACK ranges stored as raw varint bytes.
///
/// Each call to `next()` returns `(gap, ack_range)`.
pub struct AckRangeIter<'a> {
    buf: &'a [u8],
}

impl<'a> AckRangeIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl Iterator for AckRangeIter<'_> {
    type Item = Result<(u64, u64), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let (gap, n1) = match decode_varint(self.buf) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        if self.buf.len() < n1 {
            return Some(Err(Error::BufferTooSmall { needed: n1 }));
        }
        self.buf = &self.buf[n1..];
        let (ack_range, n2) = match decode_varint(self.buf) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        self.buf = &self.buf[n2..];
        Some(Ok((gap, ack_range)))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Frame-encoding error for malformed wire data.
fn frame_encoding_error() -> Error {
    Error::Transport(TransportError::FrameEncodingError)
}

/// Decode a varint from `buf[pos..]`, advancing `pos`.
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, Error> {
    if *pos >= buf.len() {
        return Err(frame_encoding_error());
    }
    let (val, n) = decode_varint(&buf[*pos..]).map_err(|_| frame_encoding_error())?;
    *pos += n;
    Ok(val)
}

/// Write a varint into `buf[pos..]`, advancing `pos`.
fn write_varint(val: u64, buf: &mut [u8], pos: &mut usize) -> Result<(), Error> {
    let n = encode_varint(val, &mut buf[*pos..])?;
    *pos += n;
    Ok(())
}

/// Read exactly `len` bytes from `buf[pos..]`, advancing `pos`.
fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], Error> {
    if *pos > buf.len() || buf.len() - *pos < len {
        return Err(frame_encoding_error());
    }
    let slice = &buf[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

/// Write `data` into `buf[pos..]`, advancing `pos`.
fn write_bytes(data: &[u8], buf: &mut [u8], pos: &mut usize) -> Result<(), Error> {
    if *pos > buf.len() || buf.len() - *pos < data.len() {
        return Err(Error::BufferTooSmall {
            needed: *pos + data.len(),
        });
    }
    buf[*pos..*pos + data.len()].copy_from_slice(data);
    *pos += data.len();
    Ok(())
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode one QUIC frame from `buf`.
///
/// Returns the decoded frame and the number of bytes consumed.
pub fn decode(buf: &[u8]) -> Result<(Frame<'_>, usize), Error> {
    let mut pos = 0;
    let frame_type = read_varint(buf, &mut pos)?;

    let frame = match frame_type {
        // PADDING
        0x00 => Frame::Padding,

        // PING
        0x01 => Frame::Ping,

        // ACK (0x02 without ECN, 0x03 with ECN)
        0x02 | 0x03 => {
            let largest_ack = read_varint(buf, &mut pos)?;
            let ack_delay = read_varint(buf, &mut pos)?;
            let ack_range_count = read_varint(buf, &mut pos)?;
            let first_ack_range = read_varint(buf, &mut pos)?;

            // Capture the raw remaining ACK range bytes.
            let ranges_start = pos;
            for _ in 0..ack_range_count {
                // gap
                let _ = read_varint(buf, &mut pos)?;
                // ack range
                let _ = read_varint(buf, &mut pos)?;
            }
            let ack_ranges = &buf[ranges_start..pos];

            let ecn = if frame_type == 0x03 {
                let ect0 = read_varint(buf, &mut pos)?;
                let ect1 = read_varint(buf, &mut pos)?;
                let ecn_ce = read_varint(buf, &mut pos)?;
                Some(EcnCounts { ect0, ect1, ecn_ce })
            } else {
                None
            };

            Frame::Ack(AckFrame {
                largest_ack,
                ack_delay,
                first_ack_range,
                ack_ranges,
                ecn,
            })
        }

        // RESET_STREAM
        0x04 => {
            let stream_id = read_varint(buf, &mut pos)?;
            let error_code = read_varint(buf, &mut pos)?;
            let final_size = read_varint(buf, &mut pos)?;
            Frame::ResetStream(ResetStreamFrame {
                stream_id,
                error_code,
                final_size,
            })
        }

        // STOP_SENDING
        0x05 => {
            let stream_id = read_varint(buf, &mut pos)?;
            let error_code = read_varint(buf, &mut pos)?;
            Frame::StopSending(StopSendingFrame {
                stream_id,
                error_code,
            })
        }

        // CRYPTO
        0x06 => {
            let offset = read_varint(buf, &mut pos)?;
            let length = read_varint(buf, &mut pos)? as usize;
            let data = read_bytes(buf, &mut pos, length)?;
            Frame::Crypto(CryptoFrame { offset, data })
        }

        // NEW_TOKEN
        0x07 => {
            let length = read_varint(buf, &mut pos)? as usize;
            let token = read_bytes(buf, &mut pos, length)?;
            Frame::NewToken(NewTokenFrame { token })
        }

        // STREAM (0x08..=0x0f)
        0x08..=0x0f => {
            let has_offset = frame_type & 0x04 != 0;
            let has_length = frame_type & 0x02 != 0;
            let fin = frame_type & 0x01 != 0;

            let stream_id = read_varint(buf, &mut pos)?;
            let offset = if has_offset {
                read_varint(buf, &mut pos)?
            } else {
                0
            };
            let data = if has_length {
                let length = read_varint(buf, &mut pos)? as usize;
                read_bytes(buf, &mut pos, length)?
            } else {
                // Data extends to end of packet.
                let rest = &buf[pos..];
                pos = buf.len();
                rest
            };

            Frame::Stream(StreamFrame {
                stream_id,
                offset,
                data,
                fin,
            })
        }

        // MAX_DATA
        0x10 => {
            let max_data = read_varint(buf, &mut pos)?;
            Frame::MaxData(max_data)
        }

        // MAX_STREAM_DATA
        0x11 => {
            let stream_id = read_varint(buf, &mut pos)?;
            let max_data = read_varint(buf, &mut pos)?;
            Frame::MaxStreamData(MaxStreamDataFrame {
                stream_id,
                max_data,
            })
        }

        // MAX_STREAMS (0x12 = bidi, 0x13 = uni)
        0x12 | 0x13 => {
            let max_streams = read_varint(buf, &mut pos)?;
            Frame::MaxStreams(MaxStreamsFrame {
                bidirectional: frame_type == 0x12,
                max_streams,
            })
        }

        // DATA_BLOCKED
        0x14 => {
            let limit = read_varint(buf, &mut pos)?;
            Frame::DataBlocked(limit)
        }

        // STREAM_DATA_BLOCKED
        0x15 => {
            let stream_id = read_varint(buf, &mut pos)?;
            let data_limit = read_varint(buf, &mut pos)?;
            Frame::StreamDataBlocked(StreamDataBlockedFrame {
                stream_id,
                data_limit,
            })
        }

        // STREAMS_BLOCKED (0x16 = bidi, 0x17 = uni)
        0x16 | 0x17 => {
            let max_streams = read_varint(buf, &mut pos)?;
            Frame::StreamsBlocked(StreamsBlockedFrame {
                bidirectional: frame_type == 0x16,
                max_streams,
            })
        }

        // NEW_CONNECTION_ID
        0x18 => {
            let sequence_number = read_varint(buf, &mut pos)?;
            let retire_prior_to = read_varint(buf, &mut pos)?;
            let cid_len = read_varint(buf, &mut pos)? as usize;
            if cid_len > 20 {
                return Err(frame_encoding_error());
            }
            let connection_id = read_bytes(buf, &mut pos, cid_len)?;
            let token_bytes = read_bytes(buf, &mut pos, 16)?;
            // SAFETY: token_bytes is exactly 16 bytes, so try_into always succeeds.
            let stateless_reset_token: &[u8; 16] =
                token_bytes.try_into().map_err(|_| frame_encoding_error())?;
            Frame::NewConnectionId(NewConnectionIdFrame {
                sequence_number,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            })
        }

        // RETIRE_CONNECTION_ID
        0x19 => {
            let seq = read_varint(buf, &mut pos)?;
            Frame::RetireConnectionId(seq)
        }

        // PATH_CHALLENGE
        0x1a => {
            let bytes = read_bytes(buf, &mut pos, 8)?;
            let mut data = [0u8; 8];
            data.copy_from_slice(bytes);
            Frame::PathChallenge(data)
        }

        // PATH_RESPONSE
        0x1b => {
            let bytes = read_bytes(buf, &mut pos, 8)?;
            let mut data = [0u8; 8];
            data.copy_from_slice(bytes);
            Frame::PathResponse(data)
        }

        // CONNECTION_CLOSE (0x1c = transport, 0x1d = application)
        0x1c | 0x1d => {
            let is_application = frame_type == 0x1d;
            let error_code = read_varint(buf, &mut pos)?;
            let frame_type_field = if !is_application {
                read_varint(buf, &mut pos)?
            } else {
                0
            };
            let reason_len = read_varint(buf, &mut pos)? as usize;
            let reason = read_bytes(buf, &mut pos, reason_len)?;
            Frame::ConnectionClose(ConnectionCloseFrame {
                is_application,
                error_code,
                frame_type: frame_type_field,
                reason,
            })
        }

        // HANDSHAKE_DONE
        0x1e => Frame::HandshakeDone,

        // Unknown frame type
        _ => return Err(frame_encoding_error()),
    };

    Ok((frame, pos))
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode one QUIC frame into `buf`.
///
/// Returns the number of bytes written.
pub fn encode(frame: &Frame<'_>, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0;

    match frame {
        Frame::Padding => {
            write_bytes(&[0x00], buf, &mut pos)?;
        }

        Frame::Ping => {
            write_varint(0x01, buf, &mut pos)?;
        }

        Frame::Ack(ack) => {
            let type_byte: u64 = if ack.ecn.is_some() { 0x03 } else { 0x02 };
            write_varint(type_byte, buf, &mut pos)?;
            write_varint(ack.largest_ack, buf, &mut pos)?;
            write_varint(ack.ack_delay, buf, &mut pos)?;

            // Count how many range pairs are in ack_ranges by walking the varints.
            let mut count: u64 = 0;
            let mut tmp = ack.ack_ranges;
            while !tmp.is_empty() {
                let (_, n1) = decode_varint(tmp).map_err(|_| frame_encoding_error())?;
                tmp = &tmp[n1..];
                let (_, n2) = decode_varint(tmp).map_err(|_| frame_encoding_error())?;
                tmp = &tmp[n2..];
                count += 1;
            }

            write_varint(count, buf, &mut pos)?;
            write_varint(ack.first_ack_range, buf, &mut pos)?;
            write_bytes(ack.ack_ranges, buf, &mut pos)?;

            if let Some(ecn) = &ack.ecn {
                write_varint(ecn.ect0, buf, &mut pos)?;
                write_varint(ecn.ect1, buf, &mut pos)?;
                write_varint(ecn.ecn_ce, buf, &mut pos)?;
            }
        }

        Frame::ResetStream(f) => {
            write_varint(0x04, buf, &mut pos)?;
            write_varint(f.stream_id, buf, &mut pos)?;
            write_varint(f.error_code, buf, &mut pos)?;
            write_varint(f.final_size, buf, &mut pos)?;
        }

        Frame::StopSending(f) => {
            write_varint(0x05, buf, &mut pos)?;
            write_varint(f.stream_id, buf, &mut pos)?;
            write_varint(f.error_code, buf, &mut pos)?;
        }

        Frame::Crypto(f) => {
            write_varint(0x06, buf, &mut pos)?;
            write_varint(f.offset, buf, &mut pos)?;
            write_varint(f.data.len() as u64, buf, &mut pos)?;
            write_bytes(f.data, buf, &mut pos)?;
        }

        Frame::NewToken(f) => {
            write_varint(0x07, buf, &mut pos)?;
            write_varint(f.token.len() as u64, buf, &mut pos)?;
            write_bytes(f.token, buf, &mut pos)?;
        }

        Frame::Stream(f) => {
            let mut type_byte: u8 = 0x08;
            // Always set length bit for safety
            type_byte |= 0x02;
            if f.offset > 0 {
                type_byte |= 0x04;
            }
            if f.fin {
                type_byte |= 0x01;
            }

            write_varint(type_byte as u64, buf, &mut pos)?;
            write_varint(f.stream_id, buf, &mut pos)?;
            if f.offset > 0 {
                write_varint(f.offset, buf, &mut pos)?;
            }
            write_varint(f.data.len() as u64, buf, &mut pos)?;
            write_bytes(f.data, buf, &mut pos)?;
        }

        Frame::MaxData(v) => {
            write_varint(0x10, buf, &mut pos)?;
            write_varint(*v, buf, &mut pos)?;
        }

        Frame::MaxStreamData(f) => {
            write_varint(0x11, buf, &mut pos)?;
            write_varint(f.stream_id, buf, &mut pos)?;
            write_varint(f.max_data, buf, &mut pos)?;
        }

        Frame::MaxStreams(f) => {
            let ty: u64 = if f.bidirectional { 0x12 } else { 0x13 };
            write_varint(ty, buf, &mut pos)?;
            write_varint(f.max_streams, buf, &mut pos)?;
        }

        Frame::DataBlocked(v) => {
            write_varint(0x14, buf, &mut pos)?;
            write_varint(*v, buf, &mut pos)?;
        }

        Frame::StreamDataBlocked(f) => {
            write_varint(0x15, buf, &mut pos)?;
            write_varint(f.stream_id, buf, &mut pos)?;
            write_varint(f.data_limit, buf, &mut pos)?;
        }

        Frame::StreamsBlocked(f) => {
            let ty: u64 = if f.bidirectional { 0x16 } else { 0x17 };
            write_varint(ty, buf, &mut pos)?;
            write_varint(f.max_streams, buf, &mut pos)?;
        }

        Frame::NewConnectionId(f) => {
            write_varint(0x18, buf, &mut pos)?;
            write_varint(f.sequence_number, buf, &mut pos)?;
            write_varint(f.retire_prior_to, buf, &mut pos)?;
            write_varint(f.connection_id.len() as u64, buf, &mut pos)?;
            write_bytes(f.connection_id, buf, &mut pos)?;
            write_bytes(f.stateless_reset_token, buf, &mut pos)?;
        }

        Frame::RetireConnectionId(seq) => {
            write_varint(0x19, buf, &mut pos)?;
            write_varint(*seq, buf, &mut pos)?;
        }

        Frame::PathChallenge(data) => {
            write_varint(0x1a, buf, &mut pos)?;
            write_bytes(data, buf, &mut pos)?;
        }

        Frame::PathResponse(data) => {
            write_varint(0x1b, buf, &mut pos)?;
            write_bytes(data, buf, &mut pos)?;
        }

        Frame::ConnectionClose(f) => {
            let ty: u64 = if f.is_application { 0x1d } else { 0x1c };
            write_varint(ty, buf, &mut pos)?;
            write_varint(f.error_code, buf, &mut pos)?;
            if !f.is_application {
                write_varint(f.frame_type, buf, &mut pos)?;
            }
            write_varint(f.reason.len() as u64, buf, &mut pos)?;
            write_bytes(f.reason, buf, &mut pos)?;
        }

        Frame::HandshakeDone => {
            write_varint(0x1e, buf, &mut pos)?;
        }
    }

    Ok(pos)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a frame then decode and check equality.
    fn roundtrip(frame: &Frame<'_>) {
        let mut buf = [0u8; 512];
        let written = encode(frame, &mut buf).expect("encode");
        let (decoded, consumed) = decode(&buf[..written]).expect("decode");
        assert_eq!(consumed, written, "consumed != written for {frame:?}");
        // For Stream frames the roundtrip might normalize offset=0 to not set
        // the offset bit, so we compare the decoded frame's fields directly.
        assert_eq!(&decoded, frame, "roundtrip mismatch for {frame:?}");
    }

    // -- Padding & Ping -----------------------------------------------------

    #[test]
    fn roundtrip_padding() {
        roundtrip(&Frame::Padding);
    }

    #[test]
    fn roundtrip_ping() {
        roundtrip(&Frame::Ping);
    }

    // -- ACK ----------------------------------------------------------------

    #[test]
    fn roundtrip_ack_no_ranges_no_ecn() {
        let frame = Frame::Ack(AckFrame {
            largest_ack: 42,
            ack_delay: 10,
            first_ack_range: 5,
            ack_ranges: &[],
            ecn: None,
        });
        roundtrip(&frame);
    }

    #[test]
    fn roundtrip_ack_with_ranges() {
        // Build raw range bytes: one pair (gap=2, range=3).
        let mut range_buf = [0u8; 16];
        let mut off = 0;
        off += encode_varint(2, &mut range_buf[off..]).unwrap();
        off += encode_varint(3, &mut range_buf[off..]).unwrap();

        let frame = Frame::Ack(AckFrame {
            largest_ack: 100,
            ack_delay: 50,
            first_ack_range: 10,
            ack_ranges: &range_buf[..off],
            ecn: None,
        });
        roundtrip(&frame);
    }

    #[test]
    fn roundtrip_ack_with_ecn() {
        let frame = Frame::Ack(AckFrame {
            largest_ack: 200,
            ack_delay: 25,
            first_ack_range: 0,
            ack_ranges: &[],
            ecn: Some(EcnCounts {
                ect0: 10,
                ect1: 20,
                ecn_ce: 5,
            }),
        });
        roundtrip(&frame);
    }

    #[test]
    fn ack_range_iter_empty() {
        let iter = AckRangeIter::new(&[]);
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn ack_range_iter_multiple() {
        // Two pairs: (1,2) and (3,4)
        let mut buf = [0u8; 32];
        let mut off = 0;
        off += encode_varint(1, &mut buf[off..]).unwrap();
        off += encode_varint(2, &mut buf[off..]).unwrap();
        off += encode_varint(3, &mut buf[off..]).unwrap();
        off += encode_varint(4, &mut buf[off..]).unwrap();

        let mut iter = AckRangeIter::new(&buf[..off]);
        assert_eq!(iter.next().unwrap().unwrap(), (1, 2));
        assert_eq!(iter.next().unwrap().unwrap(), (3, 4));
        assert!(iter.next().is_none());
    }

    // -- RESET_STREAM -------------------------------------------------------

    #[test]
    fn roundtrip_reset_stream() {
        roundtrip(&Frame::ResetStream(ResetStreamFrame {
            stream_id: 4,
            error_code: 0x0c,
            final_size: 1024,
        }));
    }

    // -- STOP_SENDING -------------------------------------------------------

    #[test]
    fn roundtrip_stop_sending() {
        roundtrip(&Frame::StopSending(StopSendingFrame {
            stream_id: 8,
            error_code: 0x05,
        }));
    }

    // -- CRYPTO -------------------------------------------------------------

    #[test]
    fn roundtrip_crypto() {
        roundtrip(&Frame::Crypto(CryptoFrame {
            offset: 0,
            data: b"client hello",
        }));
    }

    #[test]
    fn roundtrip_crypto_empty() {
        roundtrip(&Frame::Crypto(CryptoFrame {
            offset: 100,
            data: &[],
        }));
    }

    // -- NEW_TOKEN ----------------------------------------------------------

    #[test]
    fn roundtrip_new_token() {
        roundtrip(&Frame::NewToken(NewTokenFrame {
            token: b"my-token-data",
        }));
    }

    #[test]
    fn roundtrip_new_token_empty() {
        roundtrip(&Frame::NewToken(NewTokenFrame { token: &[] }));
    }

    // -- STREAM -------------------------------------------------------------

    #[test]
    fn roundtrip_stream_basic() {
        roundtrip(&Frame::Stream(StreamFrame {
            stream_id: 0,
            offset: 0,
            data: b"hello",
            fin: false,
        }));
    }

    #[test]
    fn roundtrip_stream_with_offset() {
        roundtrip(&Frame::Stream(StreamFrame {
            stream_id: 4,
            offset: 100,
            data: b"world",
            fin: false,
        }));
    }

    #[test]
    fn roundtrip_stream_fin() {
        roundtrip(&Frame::Stream(StreamFrame {
            stream_id: 4,
            offset: 0,
            data: b"done",
            fin: true,
        }));
    }

    #[test]
    fn roundtrip_stream_offset_fin_empty() {
        roundtrip(&Frame::Stream(StreamFrame {
            stream_id: 8,
            offset: 500,
            data: &[],
            fin: true,
        }));
    }

    #[test]
    fn stream_flag_bits() {
        // Verify the encoded type byte flags for various combinations.
        let cases = [
            // (offset, fin, expected lowest nibble)
            // base = 0x08, always set length (0x02)
            (0u64, false, 0x0a_u8), // 0x08 | 0x02
            (0, true, 0x0b),        // 0x08 | 0x02 | 0x01
            (1, false, 0x0e),       // 0x08 | 0x04 | 0x02
            (1, true, 0x0f),        // 0x08 | 0x04 | 0x02 | 0x01
        ];
        for (offset, fin, expected_type) in cases {
            let frame = Frame::Stream(StreamFrame {
                stream_id: 0,
                offset,
                data: b"x",
                fin,
            });
            let mut buf = [0u8; 64];
            let _ = encode(&frame, &mut buf).unwrap();
            assert_eq!(
                buf[0], expected_type,
                "offset={offset} fin={fin}: expected type 0x{expected_type:02x}, got 0x{:02x}",
                buf[0]
            );
        }
    }

    #[test]
    fn decode_stream_no_length_bit() {
        // Manually encode a STREAM frame without the length bit.
        // type=0x08 (no offset, no length, no fin) + stream_id=0 + data
        let mut buf = [0u8; 32];
        let mut pos = 0;
        buf[pos] = 0x08; // type byte: base, no flags
        pos += 1;
        pos += encode_varint(5, &mut buf[pos..]).unwrap(); // stream_id = 5
        buf[pos..pos + 3].copy_from_slice(b"abc");
        pos += 3;

        let (frame, consumed) = decode(&buf[..pos]).unwrap();
        assert_eq!(consumed, pos);
        match frame {
            Frame::Stream(sf) => {
                assert_eq!(sf.stream_id, 5);
                assert_eq!(sf.offset, 0);
                assert_eq!(sf.data, b"abc");
                assert!(!sf.fin);
            }
            _ => panic!("expected Stream"),
        }
    }

    // -- MAX_DATA -----------------------------------------------------------

    #[test]
    fn roundtrip_max_data() {
        roundtrip(&Frame::MaxData(999_999));
    }

    // -- MAX_STREAM_DATA ----------------------------------------------------

    #[test]
    fn roundtrip_max_stream_data() {
        roundtrip(&Frame::MaxStreamData(MaxStreamDataFrame {
            stream_id: 12,
            max_data: 65536,
        }));
    }

    // -- MAX_STREAMS --------------------------------------------------------

    #[test]
    fn roundtrip_max_streams_bidi() {
        roundtrip(&Frame::MaxStreams(MaxStreamsFrame {
            bidirectional: true,
            max_streams: 100,
        }));
    }

    #[test]
    fn roundtrip_max_streams_uni() {
        roundtrip(&Frame::MaxStreams(MaxStreamsFrame {
            bidirectional: false,
            max_streams: 50,
        }));
    }

    // -- DATA_BLOCKED -------------------------------------------------------

    #[test]
    fn roundtrip_data_blocked() {
        roundtrip(&Frame::DataBlocked(4096));
    }

    // -- STREAM_DATA_BLOCKED ------------------------------------------------

    #[test]
    fn roundtrip_stream_data_blocked() {
        roundtrip(&Frame::StreamDataBlocked(StreamDataBlockedFrame {
            stream_id: 4,
            data_limit: 8192,
        }));
    }

    // -- STREAMS_BLOCKED ----------------------------------------------------

    #[test]
    fn roundtrip_streams_blocked_bidi() {
        roundtrip(&Frame::StreamsBlocked(StreamsBlockedFrame {
            bidirectional: true,
            max_streams: 10,
        }));
    }

    #[test]
    fn roundtrip_streams_blocked_uni() {
        roundtrip(&Frame::StreamsBlocked(StreamsBlockedFrame {
            bidirectional: false,
            max_streams: 20,
        }));
    }

    // -- NEW_CONNECTION_ID --------------------------------------------------

    #[test]
    fn roundtrip_new_connection_id() {
        let token = &[0xaa; 16];
        roundtrip(&Frame::NewConnectionId(NewConnectionIdFrame {
            sequence_number: 1,
            retire_prior_to: 0,
            connection_id: &[0x01, 0x02, 0x03, 0x04],
            stateless_reset_token: token,
        }));
    }

    // -- RETIRE_CONNECTION_ID -----------------------------------------------

    #[test]
    fn roundtrip_retire_connection_id() {
        roundtrip(&Frame::RetireConnectionId(7));
    }

    // -- PATH_CHALLENGE / PATH_RESPONSE -------------------------------------

    #[test]
    fn roundtrip_path_challenge() {
        roundtrip(&Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn roundtrip_path_response() {
        roundtrip(&Frame::PathResponse([8, 7, 6, 5, 4, 3, 2, 1]));
    }

    // -- CONNECTION_CLOSE ---------------------------------------------------

    #[test]
    fn roundtrip_connection_close_transport() {
        roundtrip(&Frame::ConnectionClose(ConnectionCloseFrame {
            is_application: false,
            error_code: 0x0a,
            frame_type: 0x06,
            reason: b"crypto failure",
        }));
    }

    #[test]
    fn roundtrip_connection_close_application() {
        roundtrip(&Frame::ConnectionClose(ConnectionCloseFrame {
            is_application: true,
            error_code: 0x0100,
            frame_type: 0,
            reason: b"app shutdown",
        }));
    }

    #[test]
    fn roundtrip_connection_close_empty_reason() {
        roundtrip(&Frame::ConnectionClose(ConnectionCloseFrame {
            is_application: false,
            error_code: 0x01,
            frame_type: 0,
            reason: &[],
        }));
    }

    // -- HANDSHAKE_DONE -----------------------------------------------------

    #[test]
    fn roundtrip_handshake_done() {
        roundtrip(&Frame::HandshakeDone);
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn decode_empty_buffer() {
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn decode_unknown_frame_type() {
        // 0x1f is not a known frame type
        let mut buf = [0u8; 8];
        let n = encode_varint(0x1f, &mut buf).unwrap();
        assert!(decode(&buf[..n]).is_err());
    }

    #[test]
    fn decode_truncated_reset_stream() {
        // Only type byte, no payload
        let mut buf = [0u8; 8];
        let n = encode_varint(0x04, &mut buf).unwrap();
        assert!(decode(&buf[..n]).is_err());
    }

    #[test]
    fn encode_buffer_too_small() {
        let frame = Frame::Stream(StreamFrame {
            stream_id: 0,
            offset: 0,
            data: b"hello",
            fin: false,
        });
        let mut buf = [0u8; 2]; // too small
        assert!(encode(&frame, &mut buf).is_err());
    }

    #[test]
    fn roundtrip_large_varint_values() {
        roundtrip(&Frame::MaxData(crate::varint::MAX_VARINT));
        roundtrip(&Frame::RetireConnectionId(crate::varint::MAX_VARINT));
        roundtrip(&Frame::DataBlocked(crate::varint::MAX_VARINT));
    }

    #[test]
    fn decode_multiple_frames_sequentially() {
        let mut buf = [0u8; 256];
        let mut total = 0;

        let f1 = Frame::Ping;
        total += encode(&f1, &mut buf[total..]).unwrap();

        let f2 = Frame::MaxData(42);
        total += encode(&f2, &mut buf[total..]).unwrap();

        let f3 = Frame::HandshakeDone;
        total += encode(&f3, &mut buf[total..]).unwrap();

        let mut pos = 0;
        let (d1, n1) = decode(&buf[pos..total]).unwrap();
        pos += n1;
        assert_eq!(d1, f1);

        let (d2, n2) = decode(&buf[pos..total]).unwrap();
        pos += n2;
        assert_eq!(d2, f2);

        let (d3, n3) = decode(&buf[pos..total]).unwrap();
        pos += n3;
        assert_eq!(d3, f3);

        assert_eq!(pos, total);
    }

    #[test]
    fn ack_range_iter_on_roundtripped_frame() {
        // Build raw ranges: (gap=1, range=5), (gap=0, range=10)
        let mut range_buf = [0u8; 32];
        let mut off = 0;
        off += encode_varint(1, &mut range_buf[off..]).unwrap();
        off += encode_varint(5, &mut range_buf[off..]).unwrap();
        off += encode_varint(0, &mut range_buf[off..]).unwrap();
        off += encode_varint(10, &mut range_buf[off..]).unwrap();

        let frame = Frame::Ack(AckFrame {
            largest_ack: 50,
            ack_delay: 0,
            first_ack_range: 3,
            ack_ranges: &range_buf[..off],
            ecn: None,
        });

        // Encode and decode
        let mut buf = [0u8; 256];
        let written = encode(&frame, &mut buf).unwrap();
        let (decoded, _) = decode(&buf[..written]).unwrap();

        if let Frame::Ack(ack) = decoded {
            let mut iter = AckRangeIter::new(ack.ack_ranges);
            assert_eq!(iter.next().unwrap().unwrap(), (1, 5));
            assert_eq!(iter.next().unwrap().unwrap(), (0, 10));
            assert!(iter.next().is_none());
        } else {
            panic!("expected Ack frame");
        }
    }

    // -----------------------------------------------------------------------
    // Phase 13: Edge case hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn zero_length_data_stream_frame() {
        roundtrip(&Frame::Stream(StreamFrame {
            stream_id: 0,
            offset: 0,
            data: &[],
            fin: false,
        }));
    }

    #[test]
    fn maximum_stream_id_values() {
        let max_stream_id = crate::varint::MAX_VARINT;
        roundtrip(&Frame::Stream(StreamFrame {
            stream_id: max_stream_id,
            offset: 0,
            data: b"x",
            fin: false,
        }));
        roundtrip(&Frame::MaxStreamData(MaxStreamDataFrame {
            stream_id: max_stream_id,
            max_data: crate::varint::MAX_VARINT,
        }));
    }

    #[test]
    fn stream_all_flag_combinations() {
        // All 8 combinations: FIN (0/1), LEN (always set by encoder), OFF (0/nonzero)
        for &fin in &[false, true] {
            for &offset in &[0u64, 1, 100] {
                for &data in &[b"" as &[u8], b"hello"] {
                    let frame = Frame::Stream(StreamFrame {
                        stream_id: 4,
                        offset,
                        data,
                        fin,
                    });
                    roundtrip(&frame);
                }
            }
        }
    }

    #[test]
    fn ack_with_many_ranges() {
        // Build max-capacity ACK ranges: 8 pairs
        let mut range_buf = [0u8; 128];
        let mut off = 0;
        for i in 0u64..8 {
            off += encode_varint(i + 1, &mut range_buf[off..]).unwrap(); // gap
            off += encode_varint(i + 2, &mut range_buf[off..]).unwrap(); // range
        }

        let frame = Frame::Ack(AckFrame {
            largest_ack: 1000,
            ack_delay: 100,
            first_ack_range: 50,
            ack_ranges: &range_buf[..off],
            ecn: None,
        });
        roundtrip(&frame);
    }

    #[test]
    fn connection_close_max_reason_length() {
        let reason = [0x41u8; 256]; // 256 bytes of 'A'
        let frame = Frame::ConnectionClose(ConnectionCloseFrame {
            is_application: false,
            error_code: 0x0a,
            frame_type: 0x06,
            reason: &reason,
        });
        let mut buf = [0u8; 512];
        let written = encode(&frame, &mut buf).expect("encode");
        let (decoded, consumed) = decode(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        if let Frame::ConnectionClose(cc) = decoded {
            assert_eq!(cc.reason, &reason[..]);
        } else {
            panic!("expected ConnectionClose");
        }
    }

    #[test]
    fn connection_close_application_with_reason() {
        let frame = Frame::ConnectionClose(ConnectionCloseFrame {
            is_application: true,
            error_code: 0x0100,
            frame_type: 0,
            reason: b"application error occurred",
        });
        roundtrip(&frame);
    }

    #[test]
    fn unknown_frame_type_large_varint() {
        // Use a large unknown frame type (0xff)
        let mut buf = [0u8; 16];
        let n = encode_varint(0xff, &mut buf).unwrap();
        assert!(decode(&buf[..n]).is_err());
    }

    #[test]
    fn unknown_frame_type_2byte_varint() {
        // Unknown frame type requiring 2-byte varint
        let mut buf = [0u8; 16];
        let n = encode_varint(0x1000, &mut buf).unwrap();
        assert!(decode(&buf[..n]).is_err());
    }

    #[test]
    fn new_connection_id_cid_too_long() {
        // Manually encode a NEW_CONNECTION_ID with cid_len=21 (> 20 limit)
        let mut buf = [0u8; 128];
        let mut pos = 0;
        pos += encode_varint(0x18, &mut buf[pos..]).unwrap();
        pos += encode_varint(0, &mut buf[pos..]).unwrap(); // seq
        pos += encode_varint(0, &mut buf[pos..]).unwrap(); // retire
        pos += encode_varint(21, &mut buf[pos..]).unwrap(); // cid_len = 21
        // Don't need actual data - should fail at length check
        assert!(decode(&buf[..pos]).is_err());
    }
}
