//! Attacker-surface robustness: drive every wire decoder with adversarial
//! input and assert it never panics, never loops forever, and (for the
//! frame/H3 decoders) always advances on success.
//!
//! This is a portable, CI-runnable counterpart to the cargo-fuzz targets in
//! `fuzz/` — exhaustive over all 1- and 2-byte inputs plus a large batch of
//! deterministic pseudo-random inputs, so panics surface as test failures
//! without needing the libFuzzer toolchain. A panic here = a remotely
//! triggerable DoS on malformed input.

extern crate std;

use std::vec::Vec;

/// Tiny deterministic PRNG (xorshift64*) so failures are reproducible.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn fill(&mut self, buf: &mut Vec<u8>, max_len: usize) {
        let len = (self.next_u64() as usize) % (max_len + 1);
        buf.clear();
        for _ in 0..len {
            buf.push((self.next_u64() & 0xff) as u8);
        }
    }
}

/// Feed one input through every decoder. Must never panic.
fn drive(data: &[u8]) {
    // --- QUIC varint ---
    if let Ok((value, consumed)) = milli_http::varint::decode_varint(data) {
        assert!(consumed >= 1, "varint Ok must consume >=1 byte");
        let mut buf = [0u8; 8];
        if let Ok(written) = milli_http::varint::encode_varint(value, &mut buf) {
            let (value2, _) = milli_http::varint::decode_varint(&buf[..written]).unwrap();
            assert_eq!(value, value2, "varint roundtrip mismatch");
        }
    }

    // --- QUIC frame decode (single + sequential, with no-progress guard) ---
    let _ = milli_http::frame::decode(data);
    let mut pos = 0;
    let mut steps = 0;
    while pos < data.len() {
        match milli_http::frame::decode(&data[pos..]) {
            Ok((_f, consumed)) => {
                assert!(
                    consumed >= 1,
                    "frame::decode Ok must advance (no infinite loop)"
                );
                pos += consumed;
            }
            Err(_) => break,
        }
        steps += 1;
        assert!(steps <= data.len() + 1, "frame decode made too many steps");
    }

    // --- QUIC packet headers ---
    if !data.is_empty() {
        if data[0] & 0x80 != 0 {
            let _ = milli_http::packet::parse_long_header(data);
            let _ = milli_http::packet::parse_initial_header(data);
            let _ = milli_http::packet::parse_handshake_header(data);
        } else {
            for dcid_len in 0..=20 {
                let _ = milli_http::packet::parse_short_header(data, dcid_len);
            }
        }
        for dcid_len in 0..=20 {
            let _ = milli_http::packet::decode_dcid(data, dcid_len);
        }
    }
    let mut iter = milli_http::packet::CoalescedPackets::new(data);
    let mut coalesced_steps = 0;
    while let Some(result) = iter.next() {
        if result.is_err() {
            break;
        }
        coalesced_steps += 1;
        assert!(
            coalesced_steps <= data.len() + 1,
            "coalesce made too many steps"
        );
    }

    // --- HTTP/3 frame decode (single + sequential) ---
    let _ = milli_http::h3::decode_h3_frame(data);
    let mut pos = 0;
    let mut steps = 0;
    while pos < data.len() {
        match milli_http::h3::decode_h3_frame(&data[pos..]) {
            Ok((_f, consumed)) => {
                assert!(
                    consumed >= 1,
                    "decode_h3_frame Ok must advance (no infinite loop)"
                );
                pos += consumed;
            }
            Err(_) => break,
        }
        steps += 1;
        assert!(
            steps <= data.len() + 1,
            "h3 frame decode made too many steps"
        );
    }

    // --- QPACK field section ---
    let decoder = milli_http::h3::QpackDecoder::new();
    let _ = decoder.decode_field_section(data, |_n, _v| {});

    // --- TLS handshake messages ---
    use milli_http::tls::messages;
    if let Ok((msg_type, body_len)) = messages::read_handshake_header(data)
        && data.len() >= 4 + body_len
    {
        let body = &data[4..4 + body_len];
        match messages::HandshakeType::from_u8(msg_type) {
            Some(messages::HandshakeType::ClientHello) => {
                let _ = messages::parse_client_hello(body);
            }
            Some(messages::HandshakeType::ServerHello) => {
                let _ = messages::parse_server_hello(body);
            }
            Some(messages::HandshakeType::EncryptedExtensions) => {
                let _ = messages::parse_encrypted_extensions(body);
            }
            Some(messages::HandshakeType::Certificate) => {
                if let Ok(cert) = messages::parse_certificate(body) {
                    for entry in messages::iter_certificate_entries(cert.entries) {
                        let _ = entry;
                    }
                }
            }
            Some(messages::HandshakeType::CertificateVerify) => {
                let _ = messages::parse_certificate_verify(body);
            }
            Some(messages::HandshakeType::Finished) => {
                let _ = messages::parse_finished(body);
            }
            _ => {}
        }
    }
    let _ = messages::parse_client_hello(data);
    let _ = messages::parse_server_hello(data);
    let _ = messages::parse_encrypted_extensions(data);
    let _ = messages::parse_certificate(data);
    let _ = messages::parse_certificate_verify(data);
    let _ = messages::parse_finished(data);
}

#[test]
fn decoders_never_panic_on_exhaustive_short_inputs() {
    // All 0-, 1-, and 2-byte inputs.
    drive(&[]);
    for a in 0u16..=255 {
        drive(&[a as u8]);
    }
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            drive(&[a as u8, b as u8]);
        }
    }
}

#[test]
fn decoders_never_panic_on_random_inputs() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut buf = Vec::new();
    for _ in 0..200_000 {
        rng.fill(&mut buf, 64);
        drive(&buf);
    }
}

#[test]
fn decoders_never_panic_on_structured_inputs() {
    // Bias the first byte toward valid frame/packet/handshake type tags so the
    // random tail reaches deeper parsing paths.
    let mut rng = Rng(0xfeed_face_dead_beef);
    let mut buf = Vec::new();
    let tags: [u8; 12] = [
        0x00, 0x02, 0x06, 0x08, 0x0f, 0x1c, 0x80, 0xc0, 0xe0, 0x01, 0x04, 0x0b,
    ];
    for _ in 0..200_000 {
        rng.fill(&mut buf, 96);
        if !buf.is_empty() {
            buf[0] = tags[(rng.next_u64() as usize) % tags.len()];
        }
        drive(&buf);
    }
}
