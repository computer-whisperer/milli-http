//! QUIC transport parameters (RFC 9000 section 18).
//!
//! Encoded as a sequence of (id: varint, length: varint, value: bytes)
//! where integer values are varint-encoded.

use crate::error::Error;
use crate::varint::{decode_varint, encode_varint, varint_len};

/// QUIC transport parameters exchanged during the TLS handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParams {
    /// Maximum idle timeout in milliseconds (0 = disabled).
    pub max_idle_timeout: u64,
    /// Maximum UDP payload size (default 65527).
    pub max_udp_payload_size: u64,
    /// Maximum total data the peer may send (flow control).
    pub initial_max_data: u64,
    /// Initial max data on locally-initiated bidi streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial max data on remotely-initiated bidi streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial max data on unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Maximum number of bidi streams the peer may open.
    pub initial_max_streams_bidi: u64,
    /// Maximum number of uni streams the peer may open.
    pub initial_max_streams_uni: u64,
    /// ACK delay exponent (default 3).
    pub ack_delay_exponent: u64,
    /// Maximum ACK delay in milliseconds (default 25).
    pub max_ack_delay: u64,
    /// Active connection ID limit (default 2).
    pub active_connection_id_limit: u64,
    /// original_destination_connection_id (param 0x00, server-only, RFC 9000 §18.2).
    pub original_dcid: [u8; 20],
    /// Length of `original_dcid` in bytes (0 = not present).
    pub original_dcid_len: u8,
    /// initial_source_connection_id (param 0x0f, RFC 9000 §18.2).
    pub initial_scid: [u8; 20],
    /// Length of `initial_scid` in bytes (0 = not present).
    pub initial_scid_len: u8,
}

// Parameter IDs
const PARAM_ORIGINAL_DCID: u64 = 0x00;
const PARAM_MAX_IDLE_TIMEOUT: u64 = 0x01;
const PARAM_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const PARAM_INITIAL_MAX_DATA: u64 = 0x04;
const PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const PARAM_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const PARAM_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const PARAM_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const PARAM_ACK_DELAY_EXPONENT: u64 = 0x0a;
const PARAM_MAX_ACK_DELAY: u64 = 0x0b;
const PARAM_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const PARAM_INITIAL_SCID: u64 = 0x0f;

impl TransportParams {
    /// Create transport parameters with sensible defaults.
    pub fn default_params() -> Self {
        Self {
            max_idle_timeout: 30_000,
            max_udp_payload_size: 65527,
            initial_max_data: 1_048_576,
            initial_max_stream_data_bidi_local: 262_144,
            initial_max_stream_data_bidi_remote: 262_144,
            initial_max_stream_data_uni: 262_144,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            active_connection_id_limit: 2,
            original_dcid: [0u8; 20],
            original_dcid_len: 0,
            initial_scid: [0u8; 20],
            initial_scid_len: 0,
        }
    }

    /// Encode a single parameter: id (varint) + length (varint) + value (varint).
    fn encode_param(id: u64, value: u64, buf: &mut [u8], offset: &mut usize) -> Result<(), Error> {
        let val_len = varint_len(value);
        let needed = varint_len(id) + varint_len(val_len as u64) + val_len;
        if buf.len() < *offset + needed {
            return Err(Error::BufferTooSmall {
                needed: *offset + needed,
            });
        }
        *offset += encode_varint(id, &mut buf[*offset..])?;
        *offset += encode_varint(val_len as u64, &mut buf[*offset..])?;
        *offset += encode_varint(value, &mut buf[*offset..])?;
        Ok(())
    }

    /// Encode a raw-bytes parameter: id (varint) + length (varint) + raw bytes.
    /// Used for connection-ID params like original_destination_connection_id
    /// and initial_source_connection_id, which are NOT varint-encoded values.
    fn encode_bytes_param(
        id: u64,
        data: &[u8],
        buf: &mut [u8],
        offset: &mut usize,
    ) -> Result<(), Error> {
        let data_len = data.len();
        let needed = varint_len(id) + varint_len(data_len as u64) + data_len;
        if buf.len() < *offset + needed {
            return Err(Error::BufferTooSmall {
                needed: *offset + needed,
            });
        }
        *offset += encode_varint(id, &mut buf[*offset..])?;
        *offset += encode_varint(data_len as u64, &mut buf[*offset..])?;
        buf[*offset..*offset + data_len].copy_from_slice(data);
        *offset += data_len;
        Ok(())
    }

    /// Encode transport parameters into `buf`.
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut off = 0;

        // Encode CID params first (they have lower param IDs).
        // original_destination_connection_id (0x00) — only when set.
        if self.original_dcid_len > 0 {
            Self::encode_bytes_param(
                PARAM_ORIGINAL_DCID,
                &self.original_dcid[..self.original_dcid_len as usize],
                buf,
                &mut off,
            )?;
        }

        Self::encode_param(PARAM_MAX_IDLE_TIMEOUT, self.max_idle_timeout, buf, &mut off)?;
        Self::encode_param(
            PARAM_MAX_UDP_PAYLOAD_SIZE,
            self.max_udp_payload_size,
            buf,
            &mut off,
        )?;
        Self::encode_param(PARAM_INITIAL_MAX_DATA, self.initial_max_data, buf, &mut off)?;
        Self::encode_param(
            PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
            buf,
            &mut off,
        )?;
        Self::encode_param(
            PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
            buf,
            &mut off,
        )?;
        Self::encode_param(
            PARAM_INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
            buf,
            &mut off,
        )?;
        Self::encode_param(
            PARAM_INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
            buf,
            &mut off,
        )?;
        Self::encode_param(
            PARAM_INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
            buf,
            &mut off,
        )?;
        Self::encode_param(
            PARAM_ACK_DELAY_EXPONENT,
            self.ack_delay_exponent,
            buf,
            &mut off,
        )?;
        Self::encode_param(PARAM_MAX_ACK_DELAY, self.max_ack_delay, buf, &mut off)?;
        Self::encode_param(
            PARAM_ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
            buf,
            &mut off,
        )?;

        // initial_source_connection_id (0x0f) — only when set.
        if self.initial_scid_len > 0 {
            Self::encode_bytes_param(
                PARAM_INITIAL_SCID,
                &self.initial_scid[..self.initial_scid_len as usize],
                buf,
                &mut off,
            )?;
        }

        Ok(off)
    }

    /// Decode transport parameters from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut params = Self {
            max_idle_timeout: 0,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            active_connection_id_limit: 2,
            original_dcid: [0u8; 20],
            original_dcid_len: 0,
            initial_scid: [0u8; 20],
            initial_scid_len: 0,
        };

        let mut off = 0;
        while off < buf.len() {
            let (id, id_len) = decode_varint(&buf[off..])?;
            off += id_len;

            let (param_len, len_len) = decode_varint(&buf[off..])?;
            off += len_len;

            if off + param_len as usize > buf.len() {
                return Err(Error::Tls);
            }

            let param_data = &buf[off..off + param_len as usize];

            match id {
                PARAM_ORIGINAL_DCID => {
                    let copy_len = param_data.len().min(20);
                    params.original_dcid[..copy_len].copy_from_slice(&param_data[..copy_len]);
                    params.original_dcid_len = copy_len as u8;
                }
                PARAM_INITIAL_SCID => {
                    let copy_len = param_data.len().min(20);
                    params.initial_scid[..copy_len].copy_from_slice(&param_data[..copy_len]);
                    params.initial_scid_len = copy_len as u8;
                }
                PARAM_MAX_IDLE_TIMEOUT
                | PARAM_MAX_UDP_PAYLOAD_SIZE
                | PARAM_INITIAL_MAX_DATA
                | PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
                | PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
                | PARAM_INITIAL_MAX_STREAM_DATA_UNI
                | PARAM_INITIAL_MAX_STREAMS_BIDI
                | PARAM_INITIAL_MAX_STREAMS_UNI
                | PARAM_ACK_DELAY_EXPONENT
                | PARAM_MAX_ACK_DELAY
                | PARAM_ACTIVE_CONNECTION_ID_LIMIT => {
                    let (value, _) = decode_varint(param_data)?;
                    match id {
                        PARAM_MAX_IDLE_TIMEOUT => params.max_idle_timeout = value,
                        PARAM_MAX_UDP_PAYLOAD_SIZE => params.max_udp_payload_size = value,
                        PARAM_INITIAL_MAX_DATA => params.initial_max_data = value,
                        PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                            params.initial_max_stream_data_bidi_local = value
                        }
                        PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                            params.initial_max_stream_data_bidi_remote = value
                        }
                        PARAM_INITIAL_MAX_STREAM_DATA_UNI => {
                            params.initial_max_stream_data_uni = value
                        }
                        PARAM_INITIAL_MAX_STREAMS_BIDI => params.initial_max_streams_bidi = value,
                        PARAM_INITIAL_MAX_STREAMS_UNI => params.initial_max_streams_uni = value,
                        PARAM_ACK_DELAY_EXPONENT => params.ack_delay_exponent = value,
                        PARAM_MAX_ACK_DELAY => params.max_ack_delay = value,
                        PARAM_ACTIVE_CONNECTION_ID_LIMIT => {
                            params.active_connection_id_limit = value
                        }
                        _ => unreachable!(),
                    }
                }
                // Unknown parameters are ignored per spec.
                _ => {}
            }

            off += param_len as usize;
        }

        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default_params() {
        let params = TransportParams::default_params();
        let mut buf = [0u8; 256];
        let len = params.encode(&mut buf).unwrap();
        let decoded = TransportParams::decode(&buf[..len]).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn roundtrip_custom_params() {
        let params = TransportParams {
            max_idle_timeout: 60_000,
            max_udp_payload_size: 1200,
            initial_max_data: 500_000,
            initial_max_stream_data_bidi_local: 100_000,
            initial_max_stream_data_bidi_remote: 100_000,
            initial_max_stream_data_uni: 50_000,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ack_delay_exponent: 4,
            max_ack_delay: 50,
            active_connection_id_limit: 4,
            original_dcid: [0u8; 20],
            original_dcid_len: 0,
            initial_scid: [0u8; 20],
            initial_scid_len: 0,
        };
        let mut buf = [0u8; 256];
        let len = params.encode(&mut buf).unwrap();
        let decoded = TransportParams::decode(&buf[..len]).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn roundtrip_zero_values() {
        let params = TransportParams {
            max_idle_timeout: 0,
            max_udp_payload_size: 0,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 0,
            max_ack_delay: 0,
            active_connection_id_limit: 0,
            original_dcid: [0u8; 20],
            original_dcid_len: 0,
            initial_scid: [0u8; 20],
            initial_scid_len: 0,
        };
        let mut buf = [0u8; 256];
        let len = params.encode(&mut buf).unwrap();
        let decoded = TransportParams::decode(&buf[..len]).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn roundtrip_with_cid_params() {
        let mut params = TransportParams::default_params();
        // Set original_dcid
        params.original_dcid[..8]
            .copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        params.original_dcid_len = 8;
        // Set initial_scid
        params.initial_scid[..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        params.initial_scid_len = 4;

        let mut buf = [0u8; 256];
        let len = params.encode(&mut buf).unwrap();
        let decoded = TransportParams::decode(&buf[..len]).unwrap();
        assert_eq!(params, decoded);
        assert_eq!(decoded.original_dcid_len, 8);
        assert_eq!(
            &decoded.original_dcid[..8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(decoded.initial_scid_len, 4);
        assert_eq!(&decoded.initial_scid[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn roundtrip_zero_length_cid() {
        // When CID lengths are 0, they should not be encoded and should decode as 0
        let params = TransportParams::default_params();
        let mut buf = [0u8; 256];
        let len = params.encode(&mut buf).unwrap();
        let decoded = TransportParams::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.original_dcid_len, 0);
        assert_eq!(decoded.initial_scid_len, 0);
    }

    #[test]
    fn unknown_params_ignored() {
        // Encode a known param followed by an unknown one
        let mut buf = [0u8; 64];
        let mut off = 0;
        // max_idle_timeout = 1000
        off += encode_varint(0x01, &mut buf[off..]).unwrap();
        off += encode_varint(2, &mut buf[off..]).unwrap(); // length = 2 bytes for varint 1000
        off += encode_varint(1000, &mut buf[off..]).unwrap();
        // unknown param id = 0xFF, value = 0x42
        off += encode_varint(0xFF, &mut buf[off..]).unwrap();
        off += encode_varint(1, &mut buf[off..]).unwrap(); // length = 1
        buf[off] = 0x42;
        off += 1;

        let params = TransportParams::decode(&buf[..off]).unwrap();
        assert_eq!(params.max_idle_timeout, 1000);
    }

    #[test]
    fn encode_buffer_too_small() {
        let params = TransportParams::default_params();
        let mut buf = [0u8; 2];
        assert!(params.encode(&mut buf).is_err());
    }
}
