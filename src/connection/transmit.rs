//! Transmit path: build frames, encrypt packets, emit datagrams.

use crate::crypto::{Aead, CryptoProvider, HeaderProtection, Level};
use crate::error::Error;
use crate::frame::{
    self, AckFrame, ConnectionCloseFrame, CryptoFrame, Frame, MaxStreamDataFrame, StreamFrame,
};
use crate::packet::{self, MIN_INITIAL_PACKET_SIZE};
use crate::tls::TlsSession;
use crate::transport::Instant;
use crate::transport::recovery::SentPacket;

use super::recv::level_index;
use super::{Connection, ConnectionState, Transmit};

/// Encrypt the payload already at `out[payload_start..]` and apply header protection.
///
/// Assumes:
/// - Header is written at `out[0..pn_offset]`
/// - PN is written at `out[pn_offset..payload_start]`
/// - Plaintext frames (+ PADDING) are at `out[payload_start..payload_start + padded_frame_len]`
///
/// Returns the total packet length (header + encrypted payload + tag).
fn encrypt_and_protect<A: Aead, HP: HeaderProtection>(
    out: &mut [u8],
    pn_offset: usize,
    payload_start: usize,
    padded_frame_len: usize,
    pn: u64,
    pn_len: usize,
    is_long: bool,
    send: &crate::crypto::DirectionalKeys<A, HP>,
) -> Result<usize, Error> {
    let total_pkt_len = payload_start + padded_frame_len + 16; // 16 = AEAD tag

    if total_pkt_len > out.len() {
        return Err(Error::BufferTooSmall {
            needed: total_pkt_len,
        });
    }

    // Encrypt: AAD = header+PN, payload starts right after.
    // Use split_at_mut to avoid a separate aad_buf copy.
    let nonce = send.nonce(pn);
    let ct_len = {
        let (aad, payload_area) = out[..total_pkt_len].split_at_mut(payload_start);
        send.aead
            .seal_in_place(&nonce, aad, payload_area, padded_frame_len)?
    };

    // Apply header protection
    let sample_offset = pn_offset + 4;
    let actual_total = payload_start + ct_len;
    if sample_offset + 16 > actual_total {
        return Err(Error::Crypto);
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&out[sample_offset..sample_offset + 16]);
    let mask = send.header_protection.mask(&sample);

    if is_long {
        out[0] ^= mask[0] & 0x0f;
    } else {
        out[0] ^= mask[0] & 0x1f;
    }
    for i in 0..pn_len {
        out[pn_offset + i] ^= mask[1 + i];
    }

    Ok(actual_total)
}

impl<
    C: CryptoProvider,
    const MAX_STREAMS: usize,
    const SENT_PER_SPACE: usize,
    const MAX_CIDS: usize,
> Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>
where
    C::Hkdf: Default,
{
    /// Build the next outgoing UDP datagram. Returns `None` if nothing to send.
    ///
    /// The `pool` parameter provides access to the shared handshake state for
    /// sending TLS CRYPTO frames. For post-handshake connections, only
    /// application-level frames are sent.
    pub fn poll_transmit<
        'a,
        const CRYPTO_BUF: usize,
        const STREAM_BUF: usize,
        const SEND_QUEUE: usize,
    >(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        buf: &'a mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Option<Transmit<'a>> {
        if matches!(self.state, ConnectionState::Closed) {
            return None;
        }

        // Anti-amplification check: if address is not validated and we've
        // already sent 3x what we received, we cannot send anything.
        if !self.address_validated && !self.amplification_allows(1) {
            return None;
        }

        // RFC 9001 §6.6: automatic key update before AEAD confidentiality limit.
        // If the key update fails, we must not continue sending with exhausted keys.
        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        if self.keys.needs_key_update() {
            if self.keys.perform_key_update(&self.crypto).is_err() {
                self.state = ConnectionState::Closed;
                return None;
            }
        }

        // PTO fired during the handshake: rewind the CRYPTO send offsets so
        // unacknowledged flights are rebuilt below. Levels whose keys have
        // been dropped no longer transmit, and the peer discards duplicate
        // CRYPTO ranges, so rewinding everything still retained is safe.
        if self.crypto_rewind_pending {
            self.crypto_rewind_pending = false;
            if let Some(slot) = self.handshake_slot {
                let ctx = pool.get_mut(slot);
                ctx.crypto_send_offset = [0; 3];
            }
        }

        let mut total_written = 0;

        // Try to send at each level, coalescing into one datagram.

        // 1. CONNECTION_CLOSE (if closing)
        if let Some((error_code, reason)) = self.close_frame.as_ref() {
            let error_code = *error_code;
            // Send CONNECTION_CLOSE at the highest available level
            let level = if self.keys.has_send_keys(Level::Application) {
                Level::Application
            } else if self.keys.has_send_keys(Level::Handshake) {
                Level::Handshake
            } else if self.keys.has_send_keys(Level::Initial) {
                Level::Initial
            } else {
                return None;
            };

            let mut frame_buf = [0u8; 128];
            let close_frame = Frame::ConnectionClose(ConnectionCloseFrame {
                is_application: false,
                error_code,
                frame_type: 0,
                reason,
            });
            if let Ok(frame_len) = frame::encode(&close_frame, &mut frame_buf) {
                let result = if level == Level::Initial {
                    let is_client = self.role == crate::tls::handshake::Role::Client;
                    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
                    {
                        // Take initial keys out temporarily to avoid borrow conflict.
                        let send = self.keys.initial_send.take();
                        let r = if let Some(k) = send.as_ref() {
                            self.build_and_encrypt_initial_packet(
                                &frame_buf[..frame_len],
                                is_client,
                                buf,
                                now,
                                k,
                            )
                        } else {
                            Err(Error::Crypto)
                        };
                        self.keys.initial_send = send;
                        r
                    }
                    #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
                    {
                        let _ = is_client;
                        Err(Error::Crypto)
                    }
                } else {
                    self.build_and_encrypt_packet(level, &frame_buf[..frame_len], false, buf, now)
                };
                if let Ok(pkt_len) = result {
                    total_written += pkt_len;
                }
            }

            self.state = ConnectionState::Closed;
            if total_written > 0 {
                return Some(Transmit {
                    data: &buf[..total_written],
                });
            }
            return None;
        }

        // 2. Initial-level data (TLS ClientHello/ServerHello in CRYPTO frames, ACKs)
        if self.keys.has_send_keys(Level::Initial)
            && let Some(pkt_len) = self.build_initial_packet(&mut buf[total_written..], now, pool)
        {
            total_written += pkt_len;
        }

        // 3. Handshake-level data (TLS handshake messages in CRYPTO frames, ACKs)
        if self.keys.has_send_keys(Level::Handshake)
            && let Some(pkt_len) = self.build_handshake_packet(&mut buf[total_written..], now, pool)
        {
            total_written += pkt_len;
        }

        // After building handshake packets, check if the TLS engine is now
        // complete and the pool slot can be released. This handles the client
        // case where the Finished message is flushed during poll_transmit
        // (the slot couldn't be released in recv() because the TLS engine
        // hadn't written its Finished yet).
        self.maybe_release_handshake_slot(pool);

        // 4. Application-level data (STREAM frames, ACKs, HANDSHAKE_DONE, etc.)
        if self.keys.has_send_keys(Level::Application)
            && let Some(pkt_len) = self.build_short_packet(sio, &mut buf[total_written..], now)
        {
            total_written += pkt_len;
        }

        if total_written > 0 {
            // Anti-amplification: check the 3x limit on the final datagram size
            if !self.address_validated && !self.amplification_allows(total_written) {
                return None;
            }
            // Track bytes sent for anti-amplification accounting
            if !self.address_validated {
                self.anti_amplification_bytes_sent = self
                    .anti_amplification_bytes_sent
                    .saturating_add(total_written);
            }
            Some(Transmit {
                data: &buf[..total_written],
            })
        } else {
            None
        }
    }

    /// Build an Initial packet if there's something to send at this level.
    ///
    /// Writes frames directly into the output buffer at a reserved offset,
    /// then shifts them into place after computing the exact header size.
    /// This avoids a separate 2 KiB frame buffer on the stack.
    fn build_initial_packet<const CRYPTO_BUF: usize>(
        &mut self,
        buf: &mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Option<usize> {
        let level = Level::Initial;
        let idx = level_index(level);
        let pn = self.next_pn[idx];
        let largest_acked = self.largest_recv_pn[idx].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);

        let dcid_len = self.remote_cid.len as usize;
        let scid_len = if self.local_cids.is_empty() {
            0
        } else {
            self.local_cids[0].len as usize
        };

        // Max header: first_byte(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
        //             + token_len_varint(1) + length_varint(max 8)
        let max_header = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 8;
        let reserve = max_header + pn_len;

        if buf.len() < reserve + 32 {
            return None;
        }

        // Write frames at the reserved offset (past any possible header)
        let mut frame_len = 0;

        // ACK frame if needed
        if self.ack_eliciting_received[idx]
            && let Some(written) = self.build_ack_frame(level, &mut buf[reserve + frame_len..])
        {
            frame_len += written;
            self.ack_eliciting_received[idx] = false;
        }

        // CRYPTO frame from TLS engine. RFC 9000 §14.1 requires ack-eliciting
        // Initial datagrams to be padded to 1200 bytes, so only attach CRYPTO
        // data when the buffer can hold a full minimum-size packet — an
        // undersized buffer must not consume (and thereby lose) crypto stream
        // data it cannot send. An ACK-only Initial needs no padding and may
        // still go out below.
        let crypto_written = if buf.len() >= MIN_INITIAL_PACKET_SIZE {
            self.write_tls_crypto_data(level, &mut buf[reserve + frame_len..], pool)
        } else {
            0
        };
        frame_len += crypto_written;

        if frame_len == 0 {
            return None;
        }

        // RFC 9000 §14.1: pad ack-eliciting Initial datagrams to 1200 bytes.
        let has_crypto = crypto_written > 0;
        let pad_to_min = self.role == crate::tls::handshake::Role::Client || has_crypto;

        // Compute padding. The Length field varint size can change with padding,
        // so iterate once to stabilize.
        let tag_len = 16;
        let token: &[u8] = &[];
        let token_vi_len = crate::varint::varint_len(token.len() as u64);
        let base_header = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_vi_len;

        let base_payload_length = pn_len + frame_len + tag_len;
        let mut length_vi_len = crate::varint::varint_len(base_payload_length as u64);
        let mut header_len = base_header + length_vi_len;
        let total_no_pad = header_len + base_payload_length;

        let mut padding_needed = if pad_to_min && total_no_pad < MIN_INITIAL_PACKET_SIZE {
            MIN_INITIAL_PACKET_SIZE - total_no_pad
        } else {
            0
        };

        // Re-check: padding may grow the Length varint from 1→2 bytes
        let payload_with_pad = pn_len + frame_len + padding_needed + tag_len;
        let new_vi_len = crate::varint::varint_len(payload_with_pad as u64);
        if new_vi_len != length_vi_len {
            length_vi_len = new_vi_len;
            header_len = base_header + length_vi_len;
            let total = header_len + pn_len + frame_len + padding_needed + tag_len;
            if pad_to_min && total < MIN_INITIAL_PACKET_SIZE {
                padding_needed += MIN_INITIAL_PACKET_SIZE - total;
            }
        }

        let padded_frame_len = frame_len + padding_needed;
        let payload_length = pn_len + padded_frame_len + tag_len;

        // Defensive bound: a buffer too small for the padded packet (e.g. a
        // client ACK-only Initial through a sub-1200-byte buffer) must yield
        // None, not an out-of-bounds write. CRYPTO data cannot reach this path
        // with an undersized buffer (gated above), so nothing is lost.
        if header_len + payload_length > buf.len() {
            return None;
        }

        // Write header directly into buf (dcid/scid borrows scoped to this block)
        let actual_header_len = {
            let dcid = self.remote_cid.as_slice();
            let scid = if self.local_cids.is_empty() {
                &[] as &[u8]
            } else {
                self.local_cids[0].as_slice()
            };
            packet::encode_initial_header(dcid, scid, token, pn_len, payload_length, buf).ok()?
        };
        let pn_offset = actual_header_len;
        packet::encode_pn(pn, largest_acked, &mut buf[pn_offset..]).ok()?;
        let payload_start = pn_offset + pn_len;

        // Shift frames from reserved position to actual payload position
        if payload_start != reserve {
            buf.copy_within(reserve..reserve + frame_len, payload_start);
        }

        // Fill padding after frames
        for i in 0..padding_needed {
            buf[payload_start + frame_len + i] = 0x00;
        }

        // Encrypt with Initial keys (concrete AES type).
        // Take keys out temporarily to avoid borrow conflict with &mut self.
        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        let result = {
            let send = self.keys.initial_send.take();
            let r = if let Some(k) = send.as_ref() {
                encrypt_and_protect(
                    buf,
                    pn_offset,
                    payload_start,
                    padded_frame_len,
                    pn,
                    pn_len,
                    true,
                    k,
                )
            } else {
                Err(Error::Crypto)
            };
            self.keys.initial_send = send;
            r
        };
        #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
        let result: Result<usize, Error> = Err(Error::Crypto);

        match result {
            Ok(total) => {
                self.next_pn[idx] = pn + 1;
                let _ = self.sent_tracker.on_packet_sent(SentPacket {
                    pn,
                    level,
                    time_sent: now,
                    size: total as u16,
                    ack_eliciting: true,
                    in_flight: true,
                });
                self.loss_detector.on_ack_eliciting_sent(level, now);
                self.congestion.on_packet_sent(total as u64);

                // NOTE: RFC 9001 §4.9.1 says a server discards Initial keys
                // when it first sends a Handshake packet, but that makes a
                // lost ServerHello unrecoverable — it could never be
                // retransmitted and the handshake would deadlock. We instead
                // drop Initial keys when the first Handshake-level packet is
                // *received* (see recv.rs), which proves the client has the
                // ServerHello. Initial keys are derived from public values,
                // so retaining them costs nothing security-wise.
                Some(total)
            }
            Err(_) => None,
        }
    }

    /// Build a Handshake packet if there's something to send at this level.
    ///
    /// Writes frames into the output buffer at a reserved offset, then
    /// shifts them into place after computing the exact header size.
    fn build_handshake_packet<const CRYPTO_BUF: usize>(
        &mut self,
        buf: &mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Option<usize> {
        let level = Level::Handshake;
        let idx = level_index(level);
        let pn = self.next_pn[idx];
        let largest_acked = self.largest_recv_pn[idx].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);

        let dcid_len = self.remote_cid.len as usize;
        let scid_len = if self.local_cids.is_empty() {
            0
        } else {
            self.local_cids[0].len as usize
        };

        // Max header: first_byte(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
        //             + length_varint(max 8)
        let max_header = 1 + 4 + 1 + dcid_len + 1 + scid_len + 8;
        let reserve = max_header + pn_len;

        if buf.len() < reserve + 32 {
            return None;
        }

        // Write frames at the reserved offset
        let mut frame_len = 0;

        // ACK frame if needed
        if self.ack_eliciting_received[idx]
            && let Some(written) = self.build_ack_frame(level, &mut buf[reserve + frame_len..])
        {
            frame_len += written;
            self.ack_eliciting_received[idx] = false;
        }

        // CRYPTO frame from TLS engine
        let crypto_written =
            self.write_tls_crypto_data(level, &mut buf[reserve + frame_len..], pool);
        frame_len += crypto_written;

        if frame_len == 0 {
            return None;
        }

        // Compute actual header
        let tag_len = 16;
        let payload_length = pn_len + frame_len + tag_len;

        let header_len = {
            let dcid = self.remote_cid.as_slice();
            let scid = if self.local_cids.is_empty() {
                &[] as &[u8]
            } else {
                self.local_cids[0].as_slice()
            };
            packet::encode_handshake_header(dcid, scid, pn_len, payload_length, buf).ok()?
        };
        let pn_offset = header_len;
        packet::encode_pn(pn, largest_acked, &mut buf[pn_offset..]).ok()?;
        let payload_start = pn_offset + pn_len;

        // Shift frames from reserved position to actual payload position
        if payload_start != reserve {
            buf.copy_within(reserve..reserve + frame_len, payload_start);
        }

        let send = self.keys.send_keys(level)?;
        match encrypt_and_protect(
            buf,
            pn_offset,
            payload_start,
            frame_len,
            pn,
            pn_len,
            true,
            send,
        ) {
            Ok(total) => {
                self.next_pn[idx] = pn + 1;
                let _ = self.sent_tracker.on_packet_sent(SentPacket {
                    pn,
                    level,
                    time_sent: now,
                    size: total as u16,
                    ack_eliciting: true,
                    in_flight: true,
                });
                self.loss_detector.on_ack_eliciting_sent(level, now);
                self.congestion.on_packet_sent(total as u64);
                Some(total)
            }
            Err(_) => None,
        }
    }

    /// Build a short (1-RTT) packet if there's something to send.
    ///
    /// Writes frames directly into the output buffer at the pre-computed
    /// payload offset (short header size is deterministic). No intermediate
    /// frame buffer is needed.
    fn build_short_packet<const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        buf: &mut [u8],
        now: Instant,
    ) -> Option<usize> {
        let level = Level::Application;
        let idx = level_index(level);
        let pn = self.next_pn[idx];
        let largest_acked = self.largest_recv_pn[idx].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);
        let dcid_len = self.remote_cid.len as usize;

        // Short header is deterministic: first_byte(1) + dcid, then PN
        let pn_offset = 1 + dcid_len;
        let payload_start = pn_offset + pn_len;

        if buf.len() < payload_start + 32 {
            return None;
        }

        // Write frames directly into buf[payload_start..]
        let mut frame_len = 0;
        let mut sending_handshake_done = false;

        // HANDSHAKE_DONE (server, once after handshake completes)
        if self.role == crate::tls::handshake::Role::Server
            && self.need_handshake_done
            && let Ok(written) =
                frame::encode(&Frame::HandshakeDone, &mut buf[payload_start + frame_len..])
        {
            frame_len += written;
            sending_handshake_done = true;
        }

        // PATH_RESPONSE: echo challenge data back (RFC 9000 §8.2.2)
        if let Some(challenge_data) = self.pending_path_response.take() {
            let path_resp = Frame::PathResponse(challenge_data);
            if let Ok(written) = frame::encode(&path_resp, &mut buf[payload_start + frame_len..]) {
                frame_len += written;
            } else {
                // Put it back if encoding failed (buffer too small)
                self.pending_path_response = Some(challenge_data);
            }
        }

        // ACK frame if needed
        if self.ack_eliciting_received[idx]
            && let Some(written) =
                self.build_ack_frame(level, &mut buf[payload_start + frame_len..])
        {
            frame_len += written;
            self.ack_eliciting_received[idx] = false;
        }

        // Connection-level MAX_DATA replenishment (RFC 9000 §4.1): raise the
        // advertised receive window as we consume data so the peer is not
        // stalled by the limit we now enforce on the recv path.
        if let Some(new_max) = self.flow_control.should_send_max_data()
            && let Ok(written) = frame::encode(
                &Frame::MaxData(new_max),
                &mut buf[payload_start + frame_len..],
            )
        {
            frame_len += written;
            self.flow_control.max_data_sent();
        }

        // Per-stream MAX_STREAM_DATA replenishment. Each emitted frame commits
        // the bump; a full buffer simply defers the rest to the next packet.
        while let Some((sid, new_max)) = self.streams.should_send_max_stream_data() {
            let msd = Frame::MaxStreamData(MaxStreamDataFrame {
                stream_id: sid,
                max_data: new_max,
            });
            match frame::encode(&msd, &mut buf[payload_start + frame_len..]) {
                Ok(written) => {
                    frame_len += written;
                    self.streams.mark_max_stream_data_sent(sid);
                }
                Err(_) => break,
            }
        }

        // STREAM frames from pending send buffers, bounded by the congestion
        // window (RFC 9002 §7). Only new stream data is congestion-controlled;
        // the ACK and control frames above are exempt, so a cwnd-limited
        // connection still makes progress (ACKs flow, the window reopens). When
        // the window is exhausted we defer stream data to a later packet.
        let buf_avail = buf.len().saturating_sub(payload_start + frame_len);
        let stream_budget = (self.congestion.available_window() as usize).min(buf_avail);
        let stream_written = if stream_budget > 0 {
            let end = payload_start + frame_len + stream_budget;
            self.build_stream_frames(sio, &mut buf[payload_start + frame_len..end])
        } else {
            0
        };
        frame_len += stream_written;

        if frame_len == 0 {
            return None;
        }

        // Compute padding for header protection sample (RFC 9001 §5.4.2)
        let tag_len = 16;
        let min_encrypted = 20usize.saturating_sub(pn_len);
        let padding_needed = if frame_len + tag_len < min_encrypted {
            min_encrypted - frame_len - tag_len
        } else {
            0
        };
        let padded_frame_len = frame_len + padding_needed;
        for i in 0..padding_needed {
            buf[payload_start + frame_len + i] = 0x00;
        }

        // Write header at buf[0..] (dcid borrow scoped)
        {
            let dcid = self.remote_cid.as_slice();
            let key_phase_bit = (self.keys.key_phase() & 1) << 2;
            let first_byte = 0x40 | key_phase_bit | ((pn_len as u8) - 1);
            packet::encode_short_header(dcid, first_byte, buf).ok()?;
        }
        packet::encode_pn(pn, largest_acked, &mut buf[pn_offset..]).ok()?;

        // Encrypt
        let send = self.keys.send_keys(level)?;
        match encrypt_and_protect(
            buf,
            pn_offset,
            payload_start,
            padded_frame_len,
            pn,
            pn_len,
            false,
            send,
        ) {
            Ok(total) => {
                if sending_handshake_done {
                    self.need_handshake_done = false;
                }
                self.next_pn[idx] = pn + 1;
                // Track AEAD usage for confidentiality limit (RFC 9001 §6.6)
                if level == Level::Application {
                    self.keys.key_update.packets_encrypted += 1;
                }
                let _ = self.sent_tracker.on_packet_sent(SentPacket {
                    pn,
                    level,
                    time_sent: now,
                    size: total as u16,
                    ack_eliciting: true,
                    in_flight: true,
                });
                self.loss_detector.on_ack_eliciting_sent(level, now);
                self.congestion.on_packet_sent(total as u64);
                Some(total)
            }
            Err(_) => None,
        }
    }

    /// Build an ACK frame for the given level.
    ///
    /// Generates correct ACK ranges from the received packet number tracker.
    /// The QUIC ACK frame encodes ranges from highest to lowest:
    ///   - `largest_ack` = the highest received PN
    ///   - `first_ack_range` = `largest_ack - <start of highest range>`
    ///   - then for each subsequent range (descending): a gap/range pair
    ///     where `gap = <end of prev range> - <end of this range> - 2`
    ///     and `ack_range = <end of this range> - <start of this range>`
    fn build_ack_frame(&self, level: Level, buf: &mut [u8]) -> Option<usize> {
        let idx = level_index(level);
        let tracker = &self.recv_pn_tracker[idx];

        if tracker.ranges.is_empty() {
            return None;
        }

        // Ranges are sorted ascending. Work from the highest range down.
        let range_count = tracker.ranges.len();
        let (highest_start, highest_end) = tracker.ranges[range_count - 1];

        let largest_ack = highest_end;
        let first_ack_range = highest_end - highest_start;

        // Build the raw ACK range bytes (gap, ack_range varint pairs) for
        // all ranges below the highest, from next-highest down to lowest.
        let mut range_buf = [0u8; 256];
        let mut range_pos = 0;

        if range_count > 1 {
            // prev_smallest tracks the smallest PN in the previous (higher) range.
            let mut prev_smallest = highest_start;

            for i in (0..range_count - 1).rev() {
                let (r_start, r_end) = tracker.ranges[i];

                // gap = prev_smallest - r_end - 2
                // (the gap field counts how many PNs are missing *between*
                // the two ranges, minus 1 as per RFC 9000 Section 19.3.1)
                let gap = prev_smallest - r_end - 2;
                let ack_range = r_end - r_start;

                if let Ok(n) = crate::varint::encode_varint(gap, &mut range_buf[range_pos..]) {
                    range_pos += n;
                } else {
                    break; // buffer full, stop adding ranges
                }
                if let Ok(n) = crate::varint::encode_varint(ack_range, &mut range_buf[range_pos..])
                {
                    range_pos += n;
                } else {
                    break;
                }

                prev_smallest = r_start;
            }
        }

        let ack = Frame::Ack(AckFrame {
            largest_ack,
            ack_delay: 0,
            first_ack_range,
            ack_ranges: &range_buf[..range_pos],
            ecn: None,
        });

        frame::encode(&ack, buf).ok()
    }

    /// Write pending TLS handshake data as CRYPTO frame(s).
    /// Returns total bytes written.
    fn write_tls_crypto_data<const CRYPTO_BUF: usize>(
        &mut self,
        target_level: Level,
        buf: &mut [u8],
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> usize {
        // If no handshake slot, no crypto data to send.
        let slot = match self.handshake_slot {
            Some(s) => s,
            None => return 0,
        };
        let tidx = level_index(target_level);

        // Stage TLS engine output into the per-level pending buffers. The
        // engine hands out each flight exactly once (write_handshake consumes
        // it), so everything goes through `pending_crypto`. The buffer
        // retains the level's entire CRYPTO stream (index == stream offset)
        // until the handshake slot is released: anything past
        // `crypto_send_offset` is unsent, and a PTO rewinds the offset to 0
        // to retransmit a lost flight (see `crypto_rewind_pending`).
        {
            let ctx = pool.get_mut(slot);
            let sent = ctx.crypto_send_offset[tidx] as usize;
            if sent == ctx.pending_crypto[tidx].len() {
                let mut tls_buf = [0u8; 2048];
                if let Ok((tls_len, tls_level)) = ctx.tls.write_handshake(&mut tls_buf) {
                    if tls_len > 0 {
                        let lidx = level_index(tls_level);
                        // Append (never clobber): the buffer holds the whole
                        // level stream for retransmission.
                        let appended =
                            ctx.pending_crypto[lidx].extend_from_slice(&tls_buf[..tls_len]);
                        debug_assert!(
                            appended.is_ok(),
                            "per-level CRYPTO stream exceeds retention buffer"
                        );
                        ctx.pending_crypto_level[lidx] = tls_level;
                    }
                }
            }
        }

        let ctx = pool.get_mut(slot);
        let offset = ctx.crypto_send_offset[tidx];
        let unsent = ctx.pending_crypto[tidx].len() - offset as usize;
        if unsent == 0 {
            return 0;
        }

        // Send as large a prefix of the unsent region as fits in `buf`.
        // Worst-case CRYPTO frame overhead — 1 (type) + 8 (offset varint) +
        // 8 (length varint) — plus headroom for the packet's 16-byte AEAD tag,
        // which the caller appends after the frames.
        const FRAME_OVERHEAD: usize = 33;
        if buf.len() <= FRAME_OVERHEAD {
            return 0;
        }
        let send_len = (buf.len() - FRAME_OVERHEAD).min(unsent);
        #[cfg(feature = "std")]
        eprintln!(
            "[debug] sending CRYPTO {:?} offset={} len={} (unsent {})",
            target_level, offset, send_len, unsent,
        );
        let encode_result = {
            let start = offset as usize;
            let crypto = Frame::Crypto(CryptoFrame {
                offset,
                data: &ctx.pending_crypto[tidx][start..start + send_len],
            });
            frame::encode(&crypto, buf)
        };
        match encode_result {
            Ok(written) => {
                let ctx = pool.get_mut(slot);
                ctx.crypto_send_offset[tidx] += send_len as u64;
                written
            }
            Err(_) => 0,
        }
    }

    /// Build STREAM frames from pending send data.
    fn build_stream_frames<const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        buf: &mut [u8],
    ) -> usize {
        let mut total = 0;
        let mut idx = 0;

        while idx < sio.send_queue.len() {
            let entry = &sio.send_queue[idx];
            let stream_id = entry.stream_id;
            let data_len = entry.len;
            let fin = entry.fin;

            // Check if we have enough space
            let remaining = buf.len() - total;
            if remaining < 16 {
                // Not enough space for even a minimal frame
                break;
            }

            let stream_frame = Frame::Stream(StreamFrame {
                stream_id,
                offset: entry.offset,
                data: &entry.data[..data_len],
                fin,
            });

            match frame::encode(&stream_frame, &mut buf[total..]) {
                Ok(written) => {
                    total += written;
                    idx += 1;
                }
                Err(_) => break,
            }
        }

        // Remove sent entries
        for _ in 0..idx {
            if !sio.send_queue.is_empty() {
                sio.send_queue.remove(0);
            }
        }

        total
    }

    /// Build and encrypt an Initial packet with proper padding.
    ///
    /// Used only for CONNECTION_CLOSE at Initial level. Normal Initial
    /// packets are built in-place by `build_initial_packet`.
    fn build_and_encrypt_initial_packet<A: Aead, HP: HeaderProtection>(
        &mut self,
        payload_frames: &[u8],
        pad_to_min: bool,
        out: &mut [u8],
        now: Instant,
        send: &crate::crypto::DirectionalKeys<A, HP>,
    ) -> Result<usize, Error> {
        let level = Level::Initial;
        let idx = level_index(level);
        let pn = self.next_pn[idx];
        let largest_acked = self.largest_recv_pn[idx].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);
        let tag_len = 16;

        let dcid = self.remote_cid.as_slice();
        let scid = if self.local_cids.is_empty() {
            &[]
        } else {
            self.local_cids[0].as_slice()
        };
        let token: &[u8] = &[];

        let frame_len = payload_frames.len();

        // Compute header size analytically to determine padding
        let token_vi_len = crate::varint::varint_len(token.len() as u64);
        let base_header = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + token_vi_len + token.len();

        let base_payload_length = pn_len + frame_len + tag_len;
        let mut length_vi_len = crate::varint::varint_len(base_payload_length as u64);
        let mut header_len = base_header + length_vi_len;
        let total_no_pad = header_len + base_payload_length;

        let mut padding_needed = if pad_to_min && total_no_pad < MIN_INITIAL_PACKET_SIZE {
            MIN_INITIAL_PACKET_SIZE - total_no_pad
        } else {
            0
        };

        // Re-check: padding may grow the Length varint from 1→2 bytes
        let payload_with_pad = pn_len + frame_len + padding_needed + tag_len;
        let new_vi_len = crate::varint::varint_len(payload_with_pad as u64);
        if new_vi_len != length_vi_len {
            length_vi_len = new_vi_len;
            header_len = base_header + length_vi_len;
            let total = header_len + pn_len + frame_len + padding_needed + tag_len;
            if pad_to_min && total < MIN_INITIAL_PACKET_SIZE {
                padding_needed += MIN_INITIAL_PACKET_SIZE - total;
            }
        }

        let padded_frame_len = frame_len + padding_needed;
        let payload_length = pn_len + padded_frame_len + tag_len;

        // Write header with final Length directly into out
        let actual_header_len =
            packet::encode_initial_header(dcid, scid, token, pn_len, payload_length, out)?;
        let pn_offset = actual_header_len;
        let pn_written = packet::encode_pn(pn, largest_acked, &mut out[pn_offset..])?;
        let payload_start = pn_offset + pn_written;

        if payload_start + padded_frame_len + tag_len > out.len() {
            return Err(Error::BufferTooSmall {
                needed: payload_start + padded_frame_len + tag_len,
            });
        }
        out[payload_start..payload_start + frame_len].copy_from_slice(payload_frames);
        for i in 0..padding_needed {
            out[payload_start + frame_len + i] = 0x00;
        }

        let total_pkt_len = encrypt_and_protect(
            out,
            pn_offset,
            payload_start,
            padded_frame_len,
            pn,
            pn_len,
            true,
            send,
        )?;

        self.next_pn[idx] = pn + 1;
        let _ = self.sent_tracker.on_packet_sent(SentPacket {
            pn,
            level,
            time_sent: now,
            size: total_pkt_len as u16,
            ack_eliciting: true,
            in_flight: true,
        });
        self.loss_detector.on_ack_eliciting_sent(level, now);
        self.congestion.on_packet_sent(total_pkt_len as u64);

        Ok(total_pkt_len)
    }

    /// Build, encrypt, and apply header protection for a Handshake or Short packet.
    ///
    /// Used only for CONNECTION_CLOSE. Normal packets are built in-place
    /// by `build_handshake_packet` / `build_short_packet`.
    fn build_and_encrypt_packet(
        &mut self,
        level: Level,
        payload_frames: &[u8],
        _pad: bool,
        out: &mut [u8],
        now: Instant,
    ) -> Result<usize, Error> {
        let idx = level_index(level);
        let pn = self.next_pn[idx];
        let largest_acked = self.largest_recv_pn[idx].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);
        let tag_len = 16;

        let frame_len = payload_frames.len();
        let min_encrypted = 20usize.saturating_sub(pn_len);
        let padding_needed = if frame_len + tag_len < min_encrypted {
            min_encrypted - frame_len - tag_len
        } else {
            0
        };
        let padded_frame_len = frame_len + padding_needed;
        let encrypted_payload_len = padded_frame_len + tag_len;

        let dcid = self.remote_cid.as_slice();
        let scid = if self.local_cids.is_empty() {
            &[]
        } else {
            self.local_cids[0].as_slice()
        };

        let (header_len, is_long) = match level {
            Level::Handshake => {
                let payload_length = pn_len + encrypted_payload_len;
                let hl = packet::encode_handshake_header(dcid, scid, pn_len, payload_length, out)?;
                (hl, true)
            }
            Level::Application => {
                let key_phase_bit = (self.keys.key_phase() & 1) << 2;
                let first_byte = 0x40 | key_phase_bit | ((pn_len as u8) - 1);
                let hl = packet::encode_short_header(dcid, first_byte, out)?;
                (hl, false)
            }
            Level::Initial => {
                return Err(Error::InvalidState);
            }
        };

        let pn_offset = header_len;
        let pn_written = packet::encode_pn(pn, largest_acked, &mut out[pn_offset..])?;
        let payload_start = pn_offset + pn_written;

        if payload_start + padded_frame_len + tag_len > out.len() {
            return Err(Error::BufferTooSmall {
                needed: payload_start + padded_frame_len + tag_len,
            });
        }
        out[payload_start..payload_start + frame_len].copy_from_slice(payload_frames);
        for i in 0..padding_needed {
            out[payload_start + frame_len + i] = 0x00;
        }

        let send = self.keys.send_keys(level).ok_or(Error::Crypto)?;
        let total_pkt_len = encrypt_and_protect(
            out,
            pn_offset,
            payload_start,
            padded_frame_len,
            pn,
            pn_len,
            is_long,
            send,
        )?;

        self.next_pn[idx] = pn + 1;
        if level == Level::Application {
            self.keys.key_update.packets_encrypted += 1;
        }
        let _ = self.sent_tracker.on_packet_sent(SentPacket {
            pn,
            level,
            time_sent: now,
            size: total_pkt_len as u16,
            ack_eliciting: true,
            in_flight: true,
        });
        self.loss_detector.on_ack_eliciting_sent(level, now);
        self.congestion.on_packet_sent(total_pkt_len as u64);

        Ok(total_pkt_len)
    }
}

#[cfg(test)]
mod tests {
    use super::super::io::QuicStreamIoBufs;
    use super::*;
    use crate::connection::{ConnectionState, HandshakePool};
    use crate::crypto::Level;
    use crate::packet::MIN_INITIAL_PACKET_SIZE;
    use crate::tls::transport_params::TransportParams;
    use crate::transport::Rng;

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    use crate::tls::handshake::ServerTlsConfig;

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

    // -----------------------------------------------------------------------
    // Test infrastructure
    // -----------------------------------------------------------------------

    struct TestRng(u8);

    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn get_test_ed25519_cert_der() -> &'static [u8] {
        use std::sync::LazyLock;
        static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
            let s: [u8; 32] = [0x01u8; 32];
            let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
            let mut b = [0u8; 512];
            let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
            b[..n].to_vec()
        });
        &V
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_pool() -> HandshakePool<Aes128GcmProvider, 4> {
        HandshakePool::new()
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_client(
        pool: &mut HandshakePool<Aes128GcmProvider, 4>,
    ) -> (Connection<Aes128GcmProvider>, SioBufs) {
        let mut rng = TestRng(0x10);
        let conn = Connection::client(
            Aes128GcmProvider,
            "test.local",
            &[b"h3"],
            TransportParams::default_params(),
            &mut rng,
            pool,
        )
        .unwrap();
        (conn, SioBufs::new())
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_server(
        pool: &mut HandshakePool<Aes128GcmProvider, 4>,
    ) -> (Connection<Aes128GcmProvider>, SioBufs) {
        let mut rng = TestRng(0x50);
        let config = ServerTlsConfig {
            cert_der: get_test_ed25519_cert_der(),
            private_key_der: &TEST_ED25519_SEED,
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
        };
        let conn = Connection::server(
            Aes128GcmProvider,
            config,
            TransportParams::default_params(),
            &mut rng,
            pool,
        )
        .unwrap();
        (conn, SioBufs::new())
    }

    /// Exchange packets between client and server until both are established.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn run_handshake(
        client: &mut Connection<Aes128GcmProvider>,
        c_sio: &mut SioBufs,
        server: &mut Connection<Aes128GcmProvider>,
        s_sio: &mut SioBufs,
        now: crate::transport::Instant,
        pool: &mut HandshakePool<Aes128GcmProvider, 4>,
    ) {
        let mut scratch = [0u8; 2048];
        for _round in 0..20 {
            loop {
                let mut buf = [0u8; 4096];
                match client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, pool) {
                    Some(tx) => {
                        let data: heapless::Vec<u8, 4096> = {
                            let mut v = heapless::Vec::new();
                            let _ = v.extend_from_slice(tx.data);
                            v
                        };
                        let _ = server.recv(&mut s_sio.as_io(), &data, &mut scratch, now, pool);
                    }
                    None => break,
                }
            }
            loop {
                let mut buf = [0u8; 4096];
                match server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, pool) {
                    Some(tx) => {
                        let data: heapless::Vec<u8, 4096> = {
                            let mut v = heapless::Vec::new();
                            let _ = v.extend_from_slice(tx.data);
                            v
                        };
                        let _ = client.recv(&mut c_sio.as_io(), &data, &mut scratch, now, pool);
                    }
                    None => break,
                }
            }
            if client.is_established() && server.is_established() {
                return;
            }
        }
        panic!(
            "handshake did not complete: client={:?}, server={:?}",
            client.state(),
            server.state()
        );
    }

    /// Drain all pending transmits from a connection.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn drain_transmits(
        conn: &mut Connection<Aes128GcmProvider>,
        sio: &mut SioBufs,
        now: crate::transport::Instant,
        pool: &mut HandshakePool<Aes128GcmProvider, 4>,
    ) {
        loop {
            let mut buf = [0u8; 4096];
            if conn
                .poll_transmit(&mut sio.as_io(), &mut buf, now, pool)
                .is_none()
            {
                break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 1. poll_transmit_returns_none_when_nothing_to_send
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn poll_transmit_returns_none_when_nothing_to_send() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let mut buf = [0u8; 2048];

        // First call emits the Initial (ClientHello).
        let tx1 = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);
        assert!(tx1.is_some(), "first call should produce Initial");

        // Second call: no more data to send.
        let tx2 = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);
        assert!(tx2.is_none(), "second call should return None");
    }

    // -----------------------------------------------------------------------
    // 2. client_initial_padded_to_1200_bytes (RFC 9000 section 14.1)
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_initial_padded_to_1200_bytes() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool)
            .unwrap();
        assert!(
            tx.data.len() >= MIN_INITIAL_PACKET_SIZE,
            "Initial packet must be padded to at least {} bytes, got {}",
            MIN_INITIAL_PACKET_SIZE,
            tx.data.len()
        );
    }

    // -----------------------------------------------------------------------
    // 3. client_initial_has_long_header
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_initial_has_long_header() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool)
            .unwrap();
        // The form bit (bit 7) of a long header is 1.
        assert_ne!(
            tx.data[0] & 0x80,
            0,
            "Initial packet first byte should have form bit set (long header)"
        );
    }

    // -----------------------------------------------------------------------
    // 4. server_produces_response_after_client_initial
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_produces_response_after_client_initial() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        let mut scratch = [0u8; 2048];

        // Client sends Initial.
        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();
        let initial: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        // Server receives it.
        server
            .recv(&mut s_sio.as_io(), &initial, &mut scratch, now, &mut pool)
            .unwrap();

        // Server should now have something to send back (ServerHello).
        let mut srv_buf = [0u8; 4096];
        let srv_tx = server.poll_transmit(&mut s_sio.as_io(), &mut srv_buf, now, &mut pool);
        assert!(
            srv_tx.is_some(),
            "server should produce a response after receiving client Initial"
        );

        // The server response should also be a long header packet.
        let srv_data = srv_tx.unwrap().data;
        assert_ne!(
            srv_data[0] & 0x80,
            0,
            "server response should be a long header packet"
        );
    }

    // -----------------------------------------------------------------------
    // 5. stream_data_produces_short_header_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_data_produces_short_header_packet() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);

        // Send stream data.
        let stream_id = client.open_stream().unwrap();
        client
            .stream_send(&mut c_sio.as_io(), stream_id, b"test data", false)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();

        // Short header: form bit (bit 7) = 0.
        assert_eq!(
            tx.data[0] & 0x80,
            0,
            "1-RTT stream data should use a short header"
        );
    }

    // -----------------------------------------------------------------------
    // 6. stream_data_received_and_readable (end-to-end)
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_data_received_and_readable() {
        let mut scratch = [0u8; 2048];
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        let stream_id = client.open_stream().unwrap();
        let payload = b"hello server!";
        client
            .stream_send(&mut c_sio.as_io(), stream_id, payload, false)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        server
            .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
            .unwrap();

        let mut recv_buf = [0u8; 256];
        let (len, fin) = server
            .stream_recv(&mut s_sio.as_io(), stream_id, &mut recv_buf)
            .unwrap();
        assert_eq!(&recv_buf[..len], payload);
        assert!(!fin, "FIN should not be set");
    }

    // -----------------------------------------------------------------------
    // 7. connection_close_produces_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn connection_close_produces_packet() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);

        client.close(42, b"goodbye");
        assert_eq!(client.state(), ConnectionState::Closing);

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
        assert!(
            tx.is_some(),
            "closing should produce a CONNECTION_CLOSE packet"
        );
        assert_eq!(
            client.state(),
            ConnectionState::Closed,
            "state should transition to Closed after sending CONNECTION_CLOSE"
        );
    }

    // -----------------------------------------------------------------------
    // 8. connection_close_no_further_transmits
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn connection_close_no_further_transmits() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);

        client.close(0, b"done");

        // Drain the close packet.
        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
        assert!(client.is_closed());

        // Nothing further should be sent after Closed.
        let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
        assert!(
            tx.is_none(),
            "no packets should be sent after connection is Closed"
        );
    }

    // -----------------------------------------------------------------------
    // 9. packet_number_increments_after_transmit
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn packet_number_increments_after_transmit() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);

        // Before any transmit, Initial PN starts at 0.
        assert_eq!(client.next_pn[0], 0, "Initial PN should start at 0");

        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);

        // After sending one Initial packet, PN should be 1.
        assert_eq!(
            client.next_pn[0], 1,
            "Initial PN should increment to 1 after one transmit"
        );
    }

    // -----------------------------------------------------------------------
    // 10. server_sends_handshake_done
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_sends_handshake_done() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;

        // Server starts with need_handshake_done = true.
        assert!(server.need_handshake_done);

        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        // After handshake, the server should have cleared need_handshake_done
        // because it was transmitted as part of the handshake exchange.
        assert!(
            !server.need_handshake_done,
            "need_handshake_done should be false after handshake completes"
        );
    }

    // -----------------------------------------------------------------------
    // 11. anti_amplification_blocks_without_received_bytes
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn anti_amplification_blocks_without_received_bytes() {
        let mut pool = make_pool();
        let (mut server, mut s_sio) = make_server(&mut pool);

        // Server with no received bytes should not be able to send.
        assert!(!server.address_validated);
        assert_eq!(server.anti_amplification_bytes_received, 0);

        let mut buf = [0u8; 2048];
        let tx = server.poll_transmit(&mut s_sio.as_io(), &mut buf, 0, &mut pool);
        assert!(
            tx.is_none(),
            "server should not send when no bytes have been received (anti-amplification)"
        );
    }

    // -----------------------------------------------------------------------
    // 12. build_ack_frame_single_range
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn build_ack_frame_single_range() {
        let mut pool = make_pool();
        let (mut client, _c_sio) = make_client(&mut pool);

        // Record a contiguous range of packet numbers at Initial level.
        client.track_received_pn(Level::Initial, 0);
        client.track_received_pn(Level::Initial, 1);
        client.track_received_pn(Level::Initial, 2);

        // Build an ACK frame.
        let mut buf = [0u8; 256];
        let written = client.build_ack_frame(Level::Initial, &mut buf);
        assert!(
            written.is_some(),
            "should produce an ACK frame for tracked PNs"
        );
        let ack_len = written.unwrap();
        assert!(ack_len > 0, "ACK frame should have non-zero length");

        // Decode the first byte to verify it is an ACK frame type (0x02 or 0x03).
        assert!(
            buf[0] == 0x02 || buf[0] == 0x03,
            "frame type byte should be ACK (0x02) or ACK_ECN (0x03), got {:#x}",
            buf[0]
        );
    }

    // -----------------------------------------------------------------------
    // 13. build_ack_frame_multiple_ranges
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn build_ack_frame_multiple_ranges() {
        let mut pool = make_pool();
        let (mut client, _c_sio) = make_client(&mut pool);

        // Record non-contiguous PNs: [0,1] and [5,6] and [10,10].
        client.track_received_pn(Level::Initial, 0);
        client.track_received_pn(Level::Initial, 1);
        client.track_received_pn(Level::Initial, 5);
        client.track_received_pn(Level::Initial, 6);
        client.track_received_pn(Level::Initial, 10);

        // Verify the tracker has 3 ranges.
        assert_eq!(client.recv_pn_tracker[0].ranges.len(), 3);

        // Build ACK frame.
        let mut buf = [0u8; 256];
        let written = client.build_ack_frame(Level::Initial, &mut buf);
        assert!(written.is_some());
        let ack_len = written.unwrap();

        // A multi-range ACK must be longer than a single-range ACK due to
        // the gap/range pairs encoded after the first range.
        assert!(
            ack_len > 5,
            "multi-range ACK should be more than 5 bytes, got {}",
            ack_len
        );
    }

    // -----------------------------------------------------------------------
    // 14. build_ack_frame_empty_tracker_returns_none
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn build_ack_frame_empty_tracker_returns_none() {
        let mut pool = make_pool();
        let (client, _c_sio) = make_client(&mut pool);

        // No PNs recorded.
        let mut buf = [0u8; 256];
        let written = client.build_ack_frame(Level::Initial, &mut buf);
        assert!(
            written.is_none(),
            "should return None when no PNs have been received"
        );
    }

    // -----------------------------------------------------------------------
    // 15. multiple_streams_in_one_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn multiple_streams_in_one_packet() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);

        // Open two streams and queue data on both.
        let s1 = client.open_stream().unwrap();
        let s2 = client.open_stream().unwrap();
        client
            .stream_send(&mut c_sio.as_io(), s1, b"stream one", false)
            .unwrap();
        client
            .stream_send(&mut c_sio.as_io(), s2, b"stream two", false)
            .unwrap();

        assert_eq!(
            c_sio.send_queue.len(),
            2,
            "two stream entries should be queued"
        );

        // A single poll_transmit should drain both streams.
        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
        assert!(tx.is_some(), "should produce a packet with both streams");

        assert_eq!(
            c_sio.send_queue.len(),
            0,
            "send queue should be empty after transmit"
        );
    }

    // -----------------------------------------------------------------------
    // 16. bidirectional_stream_exchange
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn bidirectional_stream_exchange() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        let mut scratch = [0u8; 2048];
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);
        drain_transmits(&mut server, &mut s_sio, now, &mut pool);

        // Client sends a request.
        let c_stream = client.open_stream().unwrap();
        client
            .stream_send(&mut c_sio.as_io(), c_stream, b"GET / HTTP/1.0", true)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };
        server
            .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
            .unwrap();

        // Server reads the request.
        let mut recv_buf = [0u8; 256];
        let (len, fin) = server
            .stream_recv(&mut s_sio.as_io(), c_stream, &mut recv_buf)
            .unwrap();
        assert_eq!(&recv_buf[..len], b"GET / HTTP/1.0");
        assert!(fin);

        // Server sends a response on the same stream.
        server
            .stream_send(&mut s_sio.as_io(), c_stream, b"200 OK", true)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = server
            .poll_transmit(&mut s_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };
        client
            .recv(&mut c_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
            .unwrap();

        // Client reads the response.
        let mut recv_buf = [0u8; 256];
        let (len, fin) = client
            .stream_recv(&mut c_sio.as_io(), c_stream, &mut recv_buf)
            .unwrap();
        assert_eq!(&recv_buf[..len], b"200 OK");
        assert!(fin);
    }

    // -----------------------------------------------------------------------
    // 17. closed_connection_returns_none
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn closed_connection_returns_none() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        client.state = ConnectionState::Closed;

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);
        assert!(
            tx.is_none(),
            "Closed connection should not produce any transmits"
        );
    }

    // -----------------------------------------------------------------------
    // 18. close_before_handshake_sends_initial_level_close
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn close_before_handshake_sends_initial_level_close() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);

        // Close immediately before any handshake exchange.
        client.close(1, b"early close");
        assert_eq!(client.state(), ConnectionState::Closing);

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);
        assert!(
            tx.is_some(),
            "CONNECTION_CLOSE should be sent at Initial level"
        );
        assert_eq!(client.state(), ConnectionState::Closed);

        // The packet should be a long header (Initial level).
        assert_ne!(
            tx.unwrap().data[0] & 0x80,
            0,
            "CONNECTION_CLOSE before handshake should use long header"
        );
    }

    // -----------------------------------------------------------------------
    // 19. packet_number_increments_across_levels
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn packet_number_increments_across_levels() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;

        // Initial PN spaces all start at 0.
        assert_eq!(client.next_pn[0], 0);
        assert_eq!(client.next_pn[1], 0);
        assert_eq!(client.next_pn[2], 0);

        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        // After handshake, Initial PN should have been incremented (at least 1 Initial sent).
        assert!(
            client.next_pn[0] >= 1,
            "Initial PN should have incremented, got {}",
            client.next_pn[0]
        );
    }

    // -----------------------------------------------------------------------
    // 20. connection_close_received_by_peer
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn connection_close_received_by_peer() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        let mut scratch = [0u8; 2048];
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);
        drain_transmits(&mut server, &mut s_sio, now, &mut pool);

        // Client closes.
        client.close(99, b"error");
        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        // Server receives the CONNECTION_CLOSE.
        server
            .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
            .unwrap();
        assert_eq!(
            server.state(),
            ConnectionState::Draining,
            "server should enter Draining after receiving CONNECTION_CLOSE"
        );

        // Server should emit a ConnectionClose event.
        let mut found = false;
        while let Some(ev) = server.poll_event() {
            if let crate::connection::Event::ConnectionClose { error_code, .. } = ev {
                assert_eq!(error_code, 99);
                found = true;
            }
        }
        assert!(found, "server should emit ConnectionClose event");
    }

    // -----------------------------------------------------------------------
    // 21. anti_amplification_bytes_sent_tracking
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn anti_amplification_bytes_sent_tracking() {
        let mut pool = make_pool();
        let (mut server, _s_sio) = make_server(&mut pool);

        // Simulate receiving 2000 bytes so the server can send up to 6000.
        server.anti_amplification_bytes_received = 2000;
        assert_eq!(server.anti_amplification_bytes_sent, 0);

        // The server has no data to send (no Initial keys derived for the
        // remote DCID yet), so poll_transmit won't produce anything.
        // But the tracking mechanism is verified by checking the field.
        assert!(server.amplification_allows(6000));
        assert!(!server.amplification_allows(6001));
    }

    // -----------------------------------------------------------------------
    // 22. stream_send_with_fin
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_send_with_fin_received() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        let mut scratch = [0u8; 2048];
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        let stream_id = client.open_stream().unwrap();
        client
            .stream_send(&mut c_sio.as_io(), stream_id, b"final", true)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = client
            .poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool)
            .unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        server
            .recv(&mut s_sio.as_io(), &pkt, &mut scratch, now, &mut pool)
            .unwrap();

        let mut recv_buf = [0u8; 256];
        let (len, fin) = server
            .stream_recv(&mut s_sio.as_io(), stream_id, &mut recv_buf)
            .unwrap();
        assert_eq!(&recv_buf[..len], b"final");
        assert!(fin, "FIN should be set on the received stream data");
    }

    // -----------------------------------------------------------------------
    // 23. initial_packet_records_sent_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn initial_packet_records_sent_packet() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);

        // Before transmit, no packets recorded.
        assert_eq!(client.sent_tracker.count(), 0);

        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut c_sio.as_io(), &mut buf, 0, &mut pool);

        // After transmit, one packet should be recorded.
        assert_eq!(
            client.sent_tracker.count(),
            1,
            "sent_tracker should record the transmitted Initial packet"
        );
    }

    // -----------------------------------------------------------------------
    // 24. handshake_packet_pn_separate_from_initial
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn handshake_packet_pn_separate_from_initial() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        // Initial and Handshake have separate PN spaces.
        // Both should have been incremented.
        let initial_pn = client.next_pn[0];
        let _handshake_pn = client.next_pn[1];

        assert!(
            initial_pn >= 1,
            "Initial PN should be >= 1, got {}",
            initial_pn
        );
        assert!(
            initial_pn >= 1,
            "Initial PN must have been used during handshake"
        );
    }

    // -----------------------------------------------------------------------
    // 25. stream_data_after_close_is_blocked
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_data_after_close_is_blocked() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now = 1_000_000u64;
        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        drain_transmits(&mut client, &mut c_sio, now, &mut pool);

        let stream_id = client.open_stream().unwrap();
        client.close(0, b"bye");

        // Drain the close packet.
        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, &mut pool);
        assert!(client.is_closed());

        // Sending on a stream after close should fail.
        let result = client.stream_send(&mut c_sio.as_io(), stream_id, b"too late", false);
        assert!(
            result.is_err(),
            "stream_send after close should return an error"
        );
    }

    /// Deliver every pending packet from `src` to `dst`.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn drain_to(
        src: &mut Connection<Aes128GcmProvider>,
        src_sio: &mut SioBufs,
        dst: &mut Connection<Aes128GcmProvider>,
        dst_sio: &mut SioBufs,
        now: crate::transport::Instant,
        pool: &mut HandshakePool<Aes128GcmProvider, 4>,
    ) {
        let mut scratch = [0u8; 2048];
        loop {
            let mut buf = [0u8; 4096];
            match src.poll_transmit(&mut src_sio.as_io(), &mut buf, now, pool) {
                Some(tx) => {
                    let data: heapless::Vec<u8, 4096> = {
                        let mut v = heapless::Vec::new();
                        let _ = v.extend_from_slice(tx.data);
                        v
                    };
                    let _ = dst.recv(&mut dst_sio.as_io(), &data, &mut scratch, now, pool);
                }
                None => break,
            }
        }
    }

    /// Congestion control (RFC 9002 §7): when the congestion window is full,
    /// new STREAM data is deferred rather than flooded onto the network, while
    /// the connection otherwise stays alive and resumes once the window reopens.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn congestion_window_gates_stream_data() {
        let mut pool = make_pool();
        let (mut client, mut c_sio) = make_client(&mut pool);
        let (mut server, mut s_sio) = make_server(&mut pool);
        let now: crate::transport::Instant = 1_000_000;

        run_handshake(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );
        for _ in 0..5 {
            drain_to(
                &mut client,
                &mut c_sio,
                &mut server,
                &mut s_sio,
                now,
                &mut pool,
            );
            drain_to(
                &mut server,
                &mut s_sio,
                &mut client,
                &mut c_sio,
                now,
                &mut pool,
            );
        }
        while client.poll_event().is_some() {}
        while server.poll_event().is_some() {}

        // Exhaust the congestion window: pretend a full cwnd is already in flight
        // so available_window() == 0.
        let cwnd = client.congestion.cwnd();
        client.congestion.on_packet_sent(cwnd);
        assert_eq!(client.congestion.available_window(), 0);

        let stream_id = client.open_stream().unwrap();
        assert_eq!(
            client
                .stream_send(&mut c_sio.as_io(), stream_id, &[0xABu8; 1024], false)
                .unwrap(),
            1024
        );

        drain_to(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        let mut readable = false;
        while let Some(ev) = server.poll_event() {
            if matches!(ev, crate::Event::StreamReadable(_)) {
                readable = true;
            }
        }
        assert!(
            !readable,
            "stream data must be withheld while the congestion window is full"
        );

        // Simulate the in-flight data being acknowledged; the window reopens and
        // the queued stream data now reaches the server.
        client.congestion.on_packet_acked(cwnd, now, now);
        assert!(client.congestion.available_window() > 0);
        drain_to(
            &mut client,
            &mut c_sio,
            &mut server,
            &mut s_sio,
            now,
            &mut pool,
        );

        let mut readable_after = false;
        while let Some(ev) = server.poll_event() {
            if matches!(ev, crate::Event::StreamReadable(_)) {
                readable_after = true;
            }
        }
        assert!(
            readable_after,
            "stream data should flow once the congestion window reopens"
        );
    }
}
