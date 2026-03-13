//! QUIC packet header types and codec.
//!
//! This module handles parsing and constructing the outer QUIC packet structure:
//! headers, packet numbers, and coalescing. It does NOT handle encryption or
//! decryption -- the crypto layer handles that separately.

pub mod coalesce;
pub mod decode_dcid;
pub mod long_header;
pub mod number;
pub mod short_header;

pub use coalesce::CoalescedPackets;
pub use decode_dcid::decode_dcid;
pub use long_header::{
    encode_handshake_header, encode_initial_header, parse_handshake_header, parse_initial_header,
    parse_long_header,
};
pub use number::{decode_pn, encode_pn, pn_length};
pub use short_header::{encode_short_header, parse_short_header};

/// QUIC v1 version number (RFC 9000).
pub const QUIC_VERSION_1: u32 = 0x00000001;

/// Maximum connection ID length (RFC 9000).
pub const MAX_CID_LEN: usize = 20;

/// Minimum Initial packet size (anti-amplification, RFC 9000 section 14.1).
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// A parsed QUIC packet header.
#[derive(Debug)]
pub enum PacketHeader<'a> {
    Long(LongHeader<'a>),
    Short(ShortHeader<'a>),
    /// Version Negotiation -- parsed but not generated.
    VersionNegotiation(VersionNegotiationHeader<'a>),
}

/// Common long header fields.
#[derive(Debug)]
pub struct LongHeader<'a> {
    pub packet_type: LongPacketType,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    /// Type-specific bits from the first byte (lower 4 bits after removing form+fixed+type).
    /// Contains reserved bits and packet number length (after header protection removal).
    pub type_specific_bits: u8,
}

/// Long header packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,   // 0b00
    ZeroRtt,   // 0b01
    Handshake, // 0b10
    Retry,     // 0b11
}

/// Short header (1-RTT) packet.
#[derive(Debug)]
pub struct ShortHeader<'a> {
    pub dcid: &'a [u8],
    /// First byte with header protection still applied (or removed).
    /// Contains spin bit, reserved bits, key phase, packet number length.
    pub first_byte: u8,
}

/// Version Negotiation packet header.
#[derive(Debug)]
pub struct VersionNegotiationHeader<'a> {
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    /// Raw bytes of supported versions (each version is 4 bytes).
    pub supported_versions: &'a [u8],
}

/// Parsed Initial packet header (pre-decryption).
#[derive(Debug)]
pub struct InitialHeader<'a> {
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub token: &'a [u8],
    /// Offset into the original buffer where the packet number begins.
    pub pn_offset: usize,
    /// Total length of packet number + encrypted payload (from the Length field).
    pub payload_length: usize,
}

/// Parsed Handshake packet header (pre-decryption).
#[derive(Debug)]
pub struct HandshakeHeader<'a> {
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub pn_offset: usize,
    pub payload_length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Long header roundtrip: Initial
    // ---------------------------------------------------------------
    #[test]
    fn initial_header_roundtrip() {
        let dcid = b"\x01\x02\x03\x04";
        let scid = b"\x0a\x0b";
        let token = b"\xff\xfe";
        let pn_len = 2;
        let payload_len = 100; // pn + encrypted payload

        let mut buf = [0u8; 256];
        let written =
            encode_initial_header(dcid, scid, token, pn_len, payload_len, &mut buf).unwrap();

        let (hdr, consumed) = parse_initial_header(&buf[..written]).unwrap();
        assert_eq!(hdr.version, QUIC_VERSION_1);
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(hdr.scid, scid);
        assert_eq!(hdr.token, token);
        assert_eq!(hdr.payload_length, payload_len);
        assert_eq!(hdr.pn_offset, consumed);
    }

    // ---------------------------------------------------------------
    // Handshake header roundtrip
    // ---------------------------------------------------------------
    #[test]
    fn handshake_header_roundtrip() {
        let dcid = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let scid = b"\x0a\x0b\x0c\x0d";
        let pn_len = 4;
        let payload_len = 500;

        let mut buf = [0u8; 256];
        let written = encode_handshake_header(dcid, scid, pn_len, payload_len, &mut buf).unwrap();

        let (hdr, consumed) = parse_handshake_header(&buf[..written]).unwrap();
        assert_eq!(hdr.version, QUIC_VERSION_1);
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(hdr.scid, scid);
        assert_eq!(hdr.payload_length, payload_len);
        assert_eq!(hdr.pn_offset, consumed);
    }

    // ---------------------------------------------------------------
    // Short header roundtrip
    // ---------------------------------------------------------------
    #[test]
    fn short_header_roundtrip() {
        let dcid = b"\x01\x02\x03\x04";
        // form=0, fixed=1, spin=0, reserved=00, key_phase=0, pn_len=01 => 0b0100_0001
        let first_byte = 0x41;

        let mut buf = [0u8; 64];
        let written = encode_short_header(dcid, first_byte, &mut buf).unwrap();

        let (hdr, consumed) = parse_short_header(&buf[..written], dcid.len()).unwrap();
        assert_eq!(hdr.first_byte, first_byte);
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(consumed, written);
    }

    // ---------------------------------------------------------------
    // Packet number encoding: RFC 9000 section A.2/A.3 style tests
    // ---------------------------------------------------------------
    #[test]
    fn pn_encode_decode_basic() {
        // full_pn=0, largest_acked=0 => 1-byte encoding
        let mut buf = [0u8; 4];
        let len = encode_pn(0, 0, &mut buf).unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0);
        assert_eq!(decode_pn(0, 1, 0), 0);
    }

    #[test]
    fn pn_encode_decode_small_gap() {
        // full_pn=10, largest_acked=5 => gap is 5, fits in 1 byte
        let mut buf = [0u8; 4];
        let len = encode_pn(10, 5, &mut buf).unwrap();
        assert_eq!(len, 1);
        let truncated = buf[0] as u32;
        assert_eq!(decode_pn(truncated, 1, 5), 10);
    }

    #[test]
    fn pn_encode_decode_medium_gap() {
        // full_pn=256, largest_acked=0 => gap is 256, needs 2 bytes
        let mut buf = [0u8; 4];
        let len = encode_pn(256, 0, &mut buf).unwrap();
        assert_eq!(len, 2);
        let truncated = u16::from_be_bytes([buf[0], buf[1]]) as u32;
        assert_eq!(decode_pn(truncated, 2, 0), 256);
    }

    #[test]
    fn pn_encode_decode_large_gap() {
        // full_pn=0x1_0000, largest_acked=0 => gap is 65536, needs 3 bytes
        let mut buf = [0u8; 4];
        let len = encode_pn(0x1_0000, 0, &mut buf).unwrap();
        assert_eq!(len, 3);
        let truncated = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
        assert_eq!(decode_pn(truncated, 3, 0), 0x1_0000);
    }

    // ---------------------------------------------------------------
    // Packet number reconstruction (RFC 9000 section A.3 examples)
    // ---------------------------------------------------------------
    #[test]
    fn pn_decode_rfc_examples() {
        // Appendix A.3: largest_pn = 0xa82f30ea, truncated = 0x9b32, pn_len=2
        // Expected: 0xa82f9b32
        assert_eq!(decode_pn(0x9b32, 2, 0xa82f30ea), 0xa82f9b32);
    }

    #[test]
    fn pn_decode_wraparound() {
        // Truncated value wraps around: largest=0xff, truncated=0x02, 1-byte
        // Expected range is around 0x100, closest to 0x100 with low byte 0x02 => 0x102
        assert_eq!(decode_pn(0x02, 1, 0xff), 0x102);
    }

    #[test]
    fn pn_decode_no_wraparound() {
        // No wraparound: largest=0x00, truncated=0x01, 1-byte => just 1
        assert_eq!(decode_pn(0x01, 1, 0x00), 0x01);
    }

    // ---------------------------------------------------------------
    // Coalesced packets
    // ---------------------------------------------------------------
    #[test]
    fn coalesced_initial_plus_handshake() {
        // Build a coalesced datagram: Initial + Handshake
        let dcid = b"\x01\x02\x03\x04";
        let scid = b"\x0a\x0b";
        let token = b"";

        // Fake payload sizes (pn + encrypted payload)
        let initial_payload_len = 20;
        let handshake_payload_len = 30;

        let mut datagram = [0u8; 512];
        let mut offset = 0;

        // Encode Initial header
        let hdr_len = encode_initial_header(
            dcid,
            scid,
            token,
            2,
            initial_payload_len,
            &mut datagram[offset..],
        )
        .unwrap();
        offset += hdr_len;
        // Fill fake payload (pn + encrypted data)
        offset += initial_payload_len;

        // Encode Handshake header
        let hdr_len = encode_handshake_header(
            dcid,
            scid,
            2,
            handshake_payload_len,
            &mut datagram[offset..],
        )
        .unwrap();
        offset += hdr_len;
        // Fill fake payload
        offset += handshake_payload_len;

        let datagram = &datagram[..offset];

        let mut iter = CoalescedPackets::new(datagram);

        // First packet should parse as Initial
        let pkt0 = iter.next().unwrap().unwrap();
        let (hdr, _) = parse_initial_header(pkt0).unwrap();
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(hdr.version, QUIC_VERSION_1);

        // Second packet should parse as Handshake
        let pkt1 = iter.next().unwrap().unwrap();
        let (hdr, _) = parse_handshake_header(pkt1).unwrap();
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(hdr.version, QUIC_VERSION_1);

        // No more packets
        assert!(iter.next().is_none());
    }

    // ---------------------------------------------------------------
    // DCID extraction
    // ---------------------------------------------------------------
    #[test]
    fn decode_dcid_long_header() {
        let dcid = b"\x01\x02\x03\x04";
        let scid = b"\x0a\x0b";
        let mut buf = [0u8; 256];
        let _written = encode_initial_header(dcid, scid, b"", 1, 10, &mut buf).unwrap();

        let extracted = decode_dcid(&buf, 4).unwrap();
        assert_eq!(extracted, dcid);
    }

    #[test]
    fn decode_dcid_short_header() {
        let dcid = b"\x01\x02\x03\x04";
        let first_byte = 0x40; // form=0, fixed=1
        let mut buf = [0u8; 64];
        let _written = encode_short_header(dcid, first_byte, &mut buf).unwrap();

        let extracted = decode_dcid(&buf, 4).unwrap();
        assert_eq!(extracted, dcid);
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------
    #[test]
    fn zero_length_cids() {
        let dcid = b"";
        let scid = b"";
        let token = b"";

        let mut buf = [0u8; 256];
        let written = encode_initial_header(dcid, scid, token, 1, 10, &mut buf).unwrap();

        let (hdr, _) = parse_initial_header(&buf[..written]).unwrap();
        assert_eq!(hdr.dcid.len(), 0);
        assert_eq!(hdr.scid.len(), 0);
        assert_eq!(hdr.token.len(), 0);
    }

    #[test]
    fn max_cid_length() {
        let dcid = [0xAA; MAX_CID_LEN];
        let scid = [0xBB; MAX_CID_LEN];
        let token = b"";

        let mut buf = [0u8; 256];
        let written = encode_initial_header(&dcid, &scid, token, 1, 10, &mut buf).unwrap();

        let (hdr, _) = parse_initial_header(&buf[..written]).unwrap();
        assert_eq!(hdr.dcid, &dcid[..]);
        assert_eq!(hdr.scid, &scid[..]);
    }

    #[test]
    fn zero_length_token() {
        let dcid = b"\x01\x02";
        let scid = b"\x03\x04";
        let token = b"";

        let mut buf = [0u8; 256];
        let written = encode_initial_header(dcid, scid, token, 1, 10, &mut buf).unwrap();

        let (hdr, _) = parse_initial_header(&buf[..written]).unwrap();
        assert_eq!(hdr.token.len(), 0);
    }

    // ---------------------------------------------------------------
    // Error cases
    // ---------------------------------------------------------------
    #[test]
    fn truncated_long_header() {
        // A buffer too short to hold even the version field
        let buf = [0xC0, 0x00]; // long header form bit set, but only 2 bytes
        assert!(parse_long_header(&buf).is_err());
    }

    #[test]
    fn truncated_initial_header() {
        // Just a first byte and partial version
        let buf = [0xC0, 0x00, 0x00];
        assert!(parse_initial_header(&buf).is_err());
    }

    #[test]
    fn version_negotiation_detection() {
        // Version Negotiation: long header form bit set, version = 0
        let mut buf = [0u8; 30];
        buf[0] = 0x80; // long header form bit
        // version = 0
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        // DCID len = 4
        buf[5] = 4;
        // DCID
        buf[6] = 0x01;
        buf[7] = 0x02;
        buf[8] = 0x03;
        buf[9] = 0x04;
        // SCID len = 2
        buf[10] = 2;
        // SCID
        buf[11] = 0x0a;
        buf[12] = 0x0b;
        // Supported versions (at least one)
        buf[13] = 0x00;
        buf[14] = 0x00;
        buf[15] = 0x00;
        buf[16] = 0x01;

        let (hdr, consumed) = parse_long_header(&buf[..17]).unwrap();
        assert_eq!(consumed, 17);
        match hdr {
            PacketHeader::VersionNegotiation(vn) => {
                assert_eq!(vn.dcid, &[0x01, 0x02, 0x03, 0x04]);
                assert_eq!(vn.scid, &[0x0a, 0x0b]);
                assert_eq!(vn.supported_versions.len(), 4);
            }
            _ => panic!("expected VersionNegotiation"),
        }
    }

    #[test]
    fn parse_long_header_identifies_type() {
        let dcid = b"\x01\x02";
        let scid = b"\x03";
        let mut buf = [0u8; 256];

        // Initial
        let written = encode_initial_header(dcid, scid, b"", 1, 10, &mut buf).unwrap();
        let (hdr, _) = parse_long_header(&buf[..written]).unwrap();
        match hdr {
            PacketHeader::Long(lh) => assert_eq!(lh.packet_type, LongPacketType::Initial),
            _ => panic!("expected Long header"),
        }

        // Handshake
        let written = encode_handshake_header(dcid, scid, 1, 10, &mut buf).unwrap();
        let (hdr, _) = parse_long_header(&buf[..written]).unwrap();
        match hdr {
            PacketHeader::Long(lh) => assert_eq!(lh.packet_type, LongPacketType::Handshake),
            _ => panic!("expected Long header"),
        }
    }

    #[test]
    fn short_header_too_small() {
        let buf = [0x40]; // just the first byte, no DCID
        assert!(parse_short_header(&buf, 4).is_err());
    }

    #[test]
    fn encode_initial_buffer_too_small() {
        let mut buf = [0u8; 5]; // way too small
        let result = encode_initial_header(b"\x01\x02\x03\x04", b"\x0a\x0b", b"", 1, 10, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn pn_length_boundaries() {
        // Gap fits in 1 byte (< 128)
        assert_eq!(pn_length(10, 5), 1);
        assert_eq!(pn_length(127, 0), 1);
        // Gap fits in 2 bytes (128..32767)
        assert_eq!(pn_length(128, 0), 2);
        assert_eq!(pn_length(200, 0), 2);
        assert_eq!(pn_length(32767, 0), 2);
        // Gap fits in 3 bytes (32768..8388607)
        assert_eq!(pn_length(32768, 0), 3);
        assert_eq!(pn_length(8388607, 0), 3);
        // Gap fits in 4 bytes (>= 8388608)
        assert_eq!(pn_length(8388608, 0), 4);
    }

    // -----------------------------------------------------------------------
    // Phase 13: Edge case hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn minimum_size_initial_packet() {
        // Minimum viable Initial: zero-length CIDs, no token, minimal payload
        let dcid = b"";
        let scid = b"";
        let token = b"";
        let mut buf = [0u8; 256];
        let written = encode_initial_header(dcid, scid, token, 1, 1, &mut buf).unwrap();
        let (hdr, _) = parse_initial_header(&buf[..written]).unwrap();
        assert_eq!(hdr.dcid.len(), 0);
        assert_eq!(hdr.scid.len(), 0);
        assert_eq!(hdr.token.len(), 0);
        assert_eq!(hdr.payload_length, 1);
    }

    #[test]
    fn maximum_dcid_scid_lengths() {
        // MAX_CID_LEN = 20 for both DCID and SCID
        let dcid = [0xAA; MAX_CID_LEN];
        let scid = [0xBB; MAX_CID_LEN];
        let mut buf = [0u8; 256];
        let written = encode_initial_header(&dcid, &scid, b"", 1, 10, &mut buf).unwrap();
        let (hdr, _) = parse_initial_header(&buf[..written]).unwrap();
        assert_eq!(hdr.dcid.len(), MAX_CID_LEN);
        assert_eq!(hdr.scid.len(), MAX_CID_LEN);

        // Also test handshake header with max CID lengths
        let written = encode_handshake_header(&dcid, &scid, 1, 10, &mut buf).unwrap();
        let (hdr, _) = parse_handshake_header(&buf[..written]).unwrap();
        assert_eq!(hdr.dcid.len(), MAX_CID_LEN);
        assert_eq!(hdr.scid.len(), MAX_CID_LEN);
    }

    #[test]
    fn version_negotiation_empty_versions() {
        // Version Negotiation with version = 0 and no supported versions
        let mut buf = [0u8; 30];
        buf[0] = 0x80; // long header form bit
        // version = 0
        buf[1..5].copy_from_slice(&[0, 0, 0, 0]);
        // DCID len = 0
        buf[5] = 0;
        // SCID len = 0
        buf[6] = 0;

        let (hdr, consumed) = parse_long_header(&buf[..7]).unwrap();
        assert_eq!(consumed, 7);
        match hdr {
            PacketHeader::VersionNegotiation(vn) => {
                assert_eq!(vn.dcid.len(), 0);
                assert_eq!(vn.scid.len(), 0);
                assert_eq!(vn.supported_versions.len(), 0);
            }
            _ => panic!("expected VersionNegotiation"),
        }
    }

    #[test]
    fn version_negotiation_multiple_versions() {
        let mut buf = [0u8; 64];
        buf[0] = 0x80;
        buf[1..5].copy_from_slice(&[0, 0, 0, 0]); // version = 0
        buf[5] = 2; // DCID len
        buf[6] = 0x01;
        buf[7] = 0x02;
        buf[8] = 1; // SCID len
        buf[9] = 0x0a;
        // Two supported versions
        buf[10..14].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // v1
        buf[14..18].copy_from_slice(&[0xff, 0x00, 0x00, 0x1d]); // draft-29

        let (hdr, consumed) = parse_long_header(&buf[..18]).unwrap();
        assert_eq!(consumed, 18);
        match hdr {
            PacketHeader::VersionNegotiation(vn) => {
                assert_eq!(vn.dcid, &[0x01, 0x02]);
                assert_eq!(vn.scid, &[0x0a]);
                assert_eq!(vn.supported_versions.len(), 8); // 2 * 4 bytes
            }
            _ => panic!("expected VersionNegotiation"),
        }
    }

    #[test]
    fn truncated_headers_all_sizes() {
        // Empty buffer
        assert!(parse_long_header(&[]).is_err());
        assert!(parse_initial_header(&[]).is_err());
        assert!(parse_handshake_header(&[]).is_err());

        // Just first byte
        assert!(parse_long_header(&[0xC0]).is_err());
        assert!(parse_initial_header(&[0xC0]).is_err());
        assert!(parse_handshake_header(&[0xE0]).is_err());

        // First byte + partial version
        assert!(parse_long_header(&[0xC0, 0x00, 0x00]).is_err());
        assert!(parse_initial_header(&[0xC0, 0x00, 0x00]).is_err());
    }

    #[test]
    fn short_header_zero_dcid() {
        let first_byte = 0x40; // form=0, fixed=1
        let mut buf = [0u8; 4];
        let written = encode_short_header(b"", first_byte, &mut buf).unwrap();
        assert_eq!(written, 1); // just the first byte

        let (hdr, consumed) = parse_short_header(&buf[..written], 0).unwrap();
        assert_eq!(hdr.dcid.len(), 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn short_header_max_dcid() {
        let dcid = [0xFF; MAX_CID_LEN];
        let first_byte = 0x41;
        let mut buf = [0u8; 32];
        let written = encode_short_header(&dcid, first_byte, &mut buf).unwrap();
        assert_eq!(written, 1 + MAX_CID_LEN);

        let (hdr, consumed) = parse_short_header(&buf[..written], MAX_CID_LEN).unwrap();
        assert_eq!(hdr.dcid, &dcid[..]);
        assert_eq!(consumed, written);
    }

    #[test]
    fn coalesced_single_short_header() {
        // A short header packet consumes the rest of the datagram
        let dcid = b"\x01\x02\x03\x04";
        let first_byte = 0x40;
        let mut datagram = [0u8; 64];
        let hdr_len = encode_short_header(dcid, first_byte, &mut datagram).unwrap();
        // Add some fake payload after
        let total_len = hdr_len + 20;

        let mut iter = CoalescedPackets::new(&datagram[..total_len]);
        let pkt = iter.next().unwrap().unwrap();
        assert_eq!(pkt.len(), total_len);
        assert!(iter.next().is_none());
    }
}
