//! Receive path: decrypt incoming packets and dispatch frames.

use crate::crypto::{Aead, CryptoProvider, HeaderProtection, Level};
use crate::error::Error;
use crate::frame::{self, AckRangeIter, Frame};
use crate::packet::{self, CoalescedPackets};
use crate::tls::TlsSession;
use crate::transport::Instant;

use super::{Connection, ConnectionState, Event};

// ---------------------------------------------------------------------------
// CRYPTO frame reassembly buffer
// ---------------------------------------------------------------------------

/// Reassembly buffer for out-of-order CRYPTO frames (one per encryption level).
///
/// CRYPTO frames in QUIC form a reliable, ordered byte stream for TLS data.
/// Frames may arrive out of order within a packet or across packets. This
/// buffer stores bytes at arbitrary offsets and only delivers contiguous,
/// complete TLS handshake messages to the TLS engine.
///
/// The const generic `N` controls the buffer size (default: 4096).
pub(crate) struct CryptoReassemblyBuf<const N: usize = 4096> {
    /// Raw byte buffer. Index `i` corresponds to absolute CRYPTO stream
    /// offset `delivered + i`.
    #[cfg(not(feature = "alloc"))]
    buf: [u8; N],
    #[cfg(feature = "alloc")]
    buf: alloc::vec::Vec<u8>,
    /// Absolute offset of bytes already delivered to TLS.
    pub(crate) delivered: u64,
    /// Received byte ranges relative to `delivered`, stored as `(start, end)`
    /// pairs. Always sorted by `start` and non-overlapping.
    ranges: heapless::Vec<(usize, usize), 16>,
}

impl<const N: usize> CryptoReassemblyBuf<N> {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            buf: [0u8; N],
            #[cfg(feature = "alloc")]
            buf: alloc::vec![0u8; N],
            delivered: 0,
            ranges: heapless::Vec::new(),
        }
    }

    /// Insert data from a CRYPTO frame at the given absolute stream offset.
    pub fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }

        let end = offset + data.len() as u64;

        // Entirely before the delivery frontier — retransmit, ignore.
        if end <= self.delivered {
            return Ok(());
        }

        // Trim overlap with already-delivered prefix.
        let (data, offset) = if offset < self.delivered {
            let skip = (self.delivered - offset) as usize;
            (&data[skip..], self.delivered)
        } else {
            (data, offset)
        };

        let rel_start = (offset - self.delivered) as usize;
        let rel_end = rel_start + data.len();

        if rel_end > self.buf.len() {
            return Err(Error::Transport(
                crate::error::TransportError::CryptoBufferExceeded,
            ));
        }

        // Copy data into the buffer at the correct position.
        self.buf[rel_start..rel_end].copy_from_slice(data);

        // Merge the new range into our range list.
        self.merge_range(rel_start, rel_end);

        Ok(())
    }

    /// Returns the length of contiguous data available from the delivery
    /// frontier (i.e. starting at relative offset 0).
    pub fn contiguous_len(&self) -> usize {
        match self.ranges.first() {
            Some(&(0, end)) => end,
            _ => 0,
        }
    }

    /// Returns a slice of contiguous data available from the delivery frontier.
    pub fn contiguous_data(&self) -> &[u8] {
        let len = self.contiguous_len();
        &self.buf[..len]
    }

    /// Mark the first `n` bytes as delivered and shift the buffer contents.
    pub fn advance(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        self.delivered += n as u64;

        // Shift buffer contents left by n bytes.
        self.buf.copy_within(n.., 0);
        let buf_len = self.buf.len();
        // Zero the vacated tail.
        for b in &mut self.buf[buf_len - n..] {
            *b = 0;
        }

        // Adjust all tracked ranges.
        let mut i = 0;
        while i < self.ranges.len() {
            let (s, e) = self.ranges[i];
            if e <= n {
                // Entirely consumed.
                self.ranges.remove(i);
            } else if s < n {
                // Partially consumed — starts at 0 after shift.
                self.ranges[i] = (0, e - n);
                i += 1;
            } else {
                self.ranges[i] = (s - n, e - n);
                i += 1;
            }
        }
    }

    /// Merge a new `(start, end)` range into the sorted, non-overlapping list.
    fn merge_range(&mut self, start: usize, end: usize) {
        let mut new_start = start;
        let mut new_end = end;

        // Remove any ranges that overlap or are adjacent, merging them.
        let mut i = 0;
        while i < self.ranges.len() {
            let (s, e) = self.ranges[i];
            if s > new_end {
                // Past our range — stop scanning.
                break;
            }
            if e < new_start {
                // Before our range — skip.
                i += 1;
                continue;
            }
            // Overlapping or adjacent — absorb it.
            new_start = new_start.min(s);
            new_end = new_end.max(e);
            self.ranges.remove(i);
        }

        // Insert the merged range at position i (maintains sort order).
        if self.ranges.len() < self.ranges.capacity() {
            let _ = self.ranges.insert(i, (new_start, new_end));
        }
        // If the range list is full, the data is still in the buffer;
        // we just lose gap-tracking precision. This should not happen
        // in practice with 16 slots.
    }
}

/// Result of processing a single decrypted packet.
struct PacketResult {
    ack_eliciting: bool,
    level: Level,
    pn: u64,
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
    /// Process an incoming UDP datagram. May contain coalesced packets.
    ///
    /// `scratch` is a caller-provided mutable buffer used for in-place
    /// decryption, avoiding internal stack allocations. It must be at
    /// least as large as the biggest packet in the datagram (typically
    /// MTU-sized, e.g. 1500 bytes).
    pub fn recv<const CRYPTO_BUF: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        datagram: &[u8],
        scratch: &mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        if matches!(self.state, ConnectionState::Closed) {
            return Err(Error::Closed);
        }

        self.last_activity = now;

        // Anti-amplification: track bytes received (RFC 9000 section 8.1)
        if !self.address_validated {
            self.anti_amplification_bytes_received = self
                .anti_amplification_bytes_received
                .saturating_add(datagram.len());
        }

        // Iterate over coalesced packets in the datagram.
        let iter = CoalescedPackets::new(datagram);
        for pkt_result in iter {
            let pkt_data = match pkt_result {
                Ok(data) => data,
                Err(_) => break, // malformed coalescing, stop
            };

            if pkt_data.is_empty() {
                continue;
            }

            let first_byte = pkt_data[0];
            let is_long = first_byte & 0x80 != 0;

            let result = if is_long {
                let pkt_type = (first_byte & 0x30) >> 4;
                match pkt_type {
                    0b00 => self.recv_initial(sio, pkt_data, scratch, now, pool),
                    0b10 => self.recv_handshake(sio, pkt_data, scratch, now, pool),
                    _ => {
                        // 0-RTT, Retry, Version Negotiation: skip for now
                        continue;
                    }
                }
            } else {
                self.recv_short(sio, pkt_data, scratch, now, pool)
            };

            match result {
                Ok(pr) => {
                    #[cfg(feature = "std")]
                    eprintln!(
                        "[debug] processed {:?} pkt pn={} ack_eliciting={}",
                        pr.level, pr.pn, pr.ack_eliciting
                    );
                    if pr.ack_eliciting {
                        let idx = level_index(pr.level);
                        self.ack_eliciting_received[idx] = true;
                    }
                    // Update largest received PN for this space
                    let idx = level_index(pr.level);
                    match self.largest_recv_pn[idx] {
                        None => self.largest_recv_pn[idx] = Some(pr.pn),
                        Some(prev) if pr.pn > prev => {
                            self.largest_recv_pn[idx] = Some(pr.pn);
                        }
                        _ => {}
                    }
                    // Track received PNs for ACK generation
                    self.track_received_pn(pr.level, pr.pn);
                }
                Err(_e) => {
                    // Decryption failure or parse error: silently discard this packet
                    // per RFC 9000 Section 12.2
                    #[cfg(feature = "std")]
                    eprintln!(
                        "[debug] packet error: {:?} (first_byte=0x{:02x}, len={})",
                        _e,
                        pkt_data[0],
                        pkt_data.len()
                    );
                    continue;
                }
            }
        }

        // After processing, check for TLS-derived keys
        self.check_tls_keys(pool)?;

        Ok(())
    }

    /// Process an Initial packet.
    fn recv_initial<const CRYPTO_BUF: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        pkt_data: &[u8],
        scratch: &mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<PacketResult, Error> {
        let (hdr, _consumed) = packet::parse_initial_header(pkt_data)?;

        // If we are server and this is the first Initial, derive Initial keys from DCID
        // and record the original DCID + initial SCID in the TLS transport params
        // so they appear in the server's EncryptedExtensions (RFC 9000 §18.2).
        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        if !self.keys.has_recv_keys(Level::Initial) {
            // Server receiving first client Initial
            self.keys.derive_initial(
                &self.crypto,
                hdr.dcid,
                self.role == crate::tls::handshake::Role::Client,
            )?;

            // For the server: set original_destination_connection_id (the DCID from
            // the client's first Initial) and initial_source_connection_id (our own
            // CID) on the TLS engine's transport params before the ClientHello is
            // processed, so they are included in EncryptedExtensions.
            if self.role == crate::tls::handshake::Role::Server {
                if let Some(slot) = self.handshake_slot {
                    let local_scid = if self.local_cids.is_empty() {
                        &[]
                    } else {
                        self.local_cids[0].as_slice()
                    };
                    pool.get_mut(slot)
                        .tls
                        .set_transport_param_cids(hdr.dcid, local_scid);
                }
            }
        }

        // Update remote CID from the peer's SCID (RFC 9000 §7.2):
        // - Server: learns client SCID from the first Initial.
        // - Client: switches DCID from the random initial_dcid to the server's
        //   actual SCID upon receiving the server's first Initial.
        if !hdr.scid.is_empty() {
            if self.remote_cid.len == 0
                || (self.role == crate::tls::handshake::Role::Client
                    && matches!(self.state, ConnectionState::Handshaking))
            {
                self.remote_cid = ConnectionId::from_slice(hdr.scid);
            }
        }

        // Initial keys are concrete AES types, so use the type-specific accessor.
        // We scope the key borrow so it ends before dispatch_frames borrows &mut self.
        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        {
            let level = Level::Initial;
            let (payload_offset, pt_len, pn) = {
                let largest_pn = self.largest_recv_pn[level_index(level)].unwrap_or(0);
                let recv = self.keys.initial_recv_keys().ok_or(Error::Crypto)?;
                decrypt_long_packet(
                    pkt_data,
                    hdr.pn_offset,
                    hdr.payload_length,
                    largest_pn,
                    recv,
                    scratch,
                )?
            };
            // RFC 9000 §12.3: discard duplicate packet numbers
            if self.recv_pn_tracker[level_index(level)].contains(pn) {
                return Ok(PacketResult {
                    ack_eliciting: false,
                    level,
                    pn,
                });
            }
            let ack_eliciting = self.dispatch_frames(
                sio,
                &scratch[payload_offset..payload_offset + pt_len],
                level,
                now,
                pool,
            )?;
            Ok(PacketResult {
                ack_eliciting,
                level,
                pn,
            })
        }
        #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
        {
            let _ = pool;
            Err(Error::Crypto)
        }
    }

    /// Process a Handshake packet.
    fn recv_handshake<const CRYPTO_BUF: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        pkt_data: &[u8],
        scratch: &mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<PacketResult, Error> {
        let (hdr, _consumed) = packet::parse_handshake_header(pkt_data)?;

        let level = Level::Handshake;
        let (payload_offset, pt_len, pn) = {
            let largest_pn = self.largest_recv_pn[level_index(level)].unwrap_or(0);
            let recv = self.keys.recv_keys(Level::Handshake).ok_or(Error::Crypto)?;
            decrypt_long_packet(
                pkt_data,
                hdr.pn_offset,
                hdr.payload_length,
                largest_pn,
                recv,
                scratch,
            )?
        };
        // RFC 9000 §12.3: discard duplicate packet numbers
        if self.recv_pn_tracker[level_index(level)].contains(pn) {
            return Ok(PacketResult {
                ack_eliciting: false,
                level,
                pn,
            });
        }
        let ack_eliciting = self.dispatch_frames(
            sio,
            &scratch[payload_offset..payload_offset + pt_len],
            level,
            now,
            pool,
        )?;

        // Server: a Handshake-level packet from the client proves it has the
        // ServerHello, so the Initial space is done. (We deliberately defer
        // this past RFC 9001 §4.9.1's "on first Handshake packet sent" —
        // dropping then would make a lost ServerHello unretransmittable and
        // deadlock the handshake.)
        if self.role == crate::tls::handshake::Role::Server
            && self.keys.has_send_keys(Level::Initial)
        {
            self.keys.drop_initial();
            self.sent_tracker.drop_space(Level::Initial);
            self.loss_detector.drop_space(Level::Initial);
        }

        Ok(PacketResult {
            ack_eliciting,
            level,
            pn,
        })
    }

    /// Process a short (1-RTT) packet with key phase handling (RFC 9001 section 6).
    fn recv_short<const CRYPTO_BUF: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        pkt_data: &[u8],
        scratch: &mut [u8],
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<PacketResult, Error> {
        let dcid_len = if self.local_cids.is_empty() {
            0
        } else {
            self.local_cids[0].len as usize
        };

        let (_hdr, hdr_len) = packet::parse_short_header(pkt_data, dcid_len)?;

        // For short header, pn_offset = hdr_len (1 + dcid_len)
        let pn_offset = hdr_len;

        // Need recv keys for Application level (for header protection removal)
        let recv = self
            .keys
            .recv_keys(Level::Application)
            .ok_or(Error::Crypto)?;

        // Copy packet data into caller-provided scratch for in-place decryption
        let pkt_len = pkt_data.len();
        if pkt_len > scratch.len() {
            return Err(Error::BufferTooSmall { needed: pkt_len });
        }
        scratch[..pkt_len].copy_from_slice(pkt_data);

        // Remove header protection
        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > pkt_len {
            return Err(Error::Crypto);
        }
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&scratch[sample_offset..sample_offset + 16]);
        let mask = recv.header_protection.mask(&sample);

        // For short headers: first_byte ^= mask[0] & 0x1f
        scratch[0] ^= mask[0] & 0x1f;
        let pn_len = ((scratch[0] & 0x03) + 1) as usize;

        // Extract key_phase bit from the unprotected first byte (bit 2 = 0x04)
        let received_key_phase = (scratch[0] >> 2) & 1;

        // Unmask PN bytes
        for i in 0..pn_len {
            scratch[pn_offset + i] ^= mask[1 + i];
        }

        // Decode packet number
        let mut truncated_pn: u32 = 0;
        for i in 0..pn_len {
            truncated_pn = (truncated_pn << 8) | scratch[pn_offset + i] as u32;
        }
        let largest_pn = self.largest_recv_pn[level_index(Level::Application)].unwrap_or(0);
        let pn = packet::decode_pn(truncated_pn, pn_len, largest_pn);

        // Reject unreasonably large packet numbers (> 2^62)
        if pn > crate::varint::MAX_VARINT {
            return Err(Error::Transport(
                crate::error::TransportError::ProtocolViolation,
            ));
        }

        // RFC 9000 §12.3: discard duplicate packet numbers (saves AEAD cost)
        if self.recv_pn_tracker[level_index(Level::Application)].contains(pn) {
            return Ok(PacketResult {
                ack_eliciting: false,
                level: Level::Application,
                pn,
            });
        }

        // Decrypt payload — key phase aware (RFC 9001 section 6)
        let payload_offset = pn_offset + pn_len;
        let payload_len = pkt_len - payload_offset;

        let current_key_phase = self.keys.key_phase();

        if received_key_phase == current_key_phase {
            // Key phase matches: decrypt with current key
            let recv = self
                .keys
                .recv_keys(Level::Application)
                .ok_or(Error::Crypto)?;
            let nonce = recv.nonce(pn);

            // Use split_at_mut for zero-copy AAD
            let pt_result = {
                let (aad, payload_area) = scratch[..pkt_len].split_at_mut(payload_offset);
                recv.aead
                    .open_in_place(&nonce, &*aad, payload_area, payload_len)
            };

            match pt_result {
                Ok(pt_len) => {
                    // Track AEAD usage for confidentiality limit (RFC 9001 §6.6)
                    self.keys.key_update.packets_decrypted += 1;

                    // If we initiated a key update and peer responds with our new phase,
                    // that confirms our key update.
                    if !self.keys.key_update.update_confirmed {
                        self.keys.key_update.update_confirmed = true;
                    }

                    let ack_eliciting = self.dispatch_frames(
                        sio,
                        &scratch[payload_offset..payload_offset + pt_len],
                        Level::Application,
                        now,
                        pool,
                    )?;
                    Ok(PacketResult {
                        ack_eliciting,
                        level: Level::Application,
                        pn,
                    })
                }
                Err(_) => {
                    // Decryption with current key failed. Try previous key
                    // (for delayed packets from before a key update we initiated).
                    // Header (AAD) at scratch[..payload_offset] is still intact;
                    // only restore the payload portion from the original packet.
                    scratch[payload_offset..pkt_len]
                        .copy_from_slice(&pkt_data[payload_offset..pkt_len]);

                    if let Some(prev) = self.keys.prev_recv_keys() {
                        let nonce = prev.nonce(pn);
                        let pt_len = {
                            let (aad, payload_area) =
                                scratch[..pkt_len].split_at_mut(payload_offset);
                            prev.aead
                                .open_in_place(&nonce, &*aad, payload_area, payload_len)?
                        };

                        let ack_eliciting = self.dispatch_frames(
                            sio,
                            &scratch[payload_offset..payload_offset + pt_len],
                            Level::Application,
                            now,
                            pool,
                        )?;
                        return Ok(PacketResult {
                            ack_eliciting,
                            level: Level::Application,
                            pn,
                        });
                    }

                    Err(Error::Crypto)
                }
            }
        } else {
            // Key phase differs: peer has initiated a key update.
            // Derive next-generation recv keys and try decryption.
            #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
            {
                let next_recv_keys = self.keys.derive_next_recv_keys(&self.crypto)?;
                let nonce = next_recv_keys.nonce(pn);
                let pt_len = {
                    let (aad, payload_area) = scratch[..pkt_len].split_at_mut(payload_offset);
                    next_recv_keys
                        .aead
                        .open_in_place(&nonce, &*aad, payload_area, payload_len)?
                };

                // Decryption succeeded: confirm the peer key update and rotate keys.
                self.keys
                    .confirm_peer_key_update(&self.crypto, next_recv_keys)?;

                let ack_eliciting = self.dispatch_frames(
                    sio,
                    &scratch[payload_offset..payload_offset + pt_len],
                    Level::Application,
                    now,
                    pool,
                )?;
                Ok(PacketResult {
                    ack_eliciting,
                    level: Level::Application,
                    pn,
                })
            }
            #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
            {
                Err(Error::Crypto)
            }
        }
    }

    // decrypt_and_process_long is replaced by the standalone decrypt_long_packet
    // function below, which separates decryption from frame dispatch to avoid
    // borrow conflicts when Initial and Handshake keys have different types.

    /// Parse and dispatch all frames from decrypted payload.
    /// Returns true if any frame was ack-eliciting.
    fn dispatch_frames<
        const CRYPTO_BUF: usize,
        const STREAM_BUF: usize,
        const SEND_QUEUE: usize,
    >(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        payload: &[u8],
        level: Level,
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<bool, Error> {
        let mut ack_eliciting = false;
        let mut pos = 0;

        while pos < payload.len() {
            let (frame, consumed) = frame::decode(&payload[pos..])?;
            pos += consumed;

            // All frames except PADDING and ACK are ack-eliciting
            match &frame {
                Frame::Padding | Frame::Ack(_) => {}
                _ => {
                    ack_eliciting = true;
                }
            }

            self.dispatch_frame(sio, frame, level, now, pool)?;
        }

        Ok(ack_eliciting)
    }

    /// Dispatch a single frame.
    pub(crate) fn dispatch_frame<
        const CRYPTO_BUF: usize,
        const STREAM_BUF: usize,
        const SEND_QUEUE: usize,
    >(
        &mut self,
        sio: &mut super::io::QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,
        frame: Frame<'_>,
        level: Level,
        now: Instant,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        match frame {
            Frame::Padding => {}

            Frame::Ping => {
                // Ack-eliciting, nothing else to do
            }

            Frame::Ack(ack) => {
                // Parse additional ranges
                let mut ranges: heapless::Vec<(u64, u64), 16> = heapless::Vec::new();
                let iter = AckRangeIter::new(ack.ack_ranges);
                for range_result in iter {
                    let (gap, ack_range) = range_result?;
                    let _ = ranges.push((gap, ack_range));
                }

                // Process ACK through the sent packet tracker
                let ack_result = self.sent_tracker.on_ack_received(
                    level,
                    ack.largest_ack,
                    ack.first_ack_range,
                    &ranges,
                );

                // Update loss detector
                self.loss_detector.on_ack_received(level, ack.largest_ack);

                // Update RTT if we have a newly acked packet
                if let Some(largest) = ack_result.largest_newly_acked {
                    if largest.time_sent > 0 && now >= largest.time_sent {
                        let latest_rtt = now - largest.time_sent;
                        let ack_delay = ack.ack_delay; // in microseconds (simplified)
                        let handshake_confirmed = matches!(self.state, ConnectionState::Active);
                        self.loss_detector
                            .update_rtt(latest_rtt, ack_delay, handshake_confirmed);
                    }
                    self.loss_detector.reset_pto_count();
                }

                // Update congestion controller for acked packets
                for pkt in &ack_result.newly_acked {
                    self.congestion
                        .on_packet_acked(pkt.size as u64, pkt.time_sent, now);
                }

                // Detect lost packets
                let (lost_pns, _loss_timer) =
                    self.loss_detector
                        .detect_lost_packets(level, &self.sent_tracker, now);
                for lost_pn in &lost_pns {
                    if let Some(lost) = self.sent_tracker.remove(level, *lost_pn) {
                        self.congestion
                            .on_packet_lost(lost.size as u64, lost.time_sent, now);
                    }
                }
            }

            Frame::Crypto(crypto) => {
                #[cfg(feature = "std")]
                eprintln!(
                    "[debug] CRYPTO frame at {:?} offset={} len={}",
                    level,
                    crypto.offset,
                    crypto.data.len()
                );
                self.handle_crypto_frame(level, crypto.offset, crypto.data, pool)?;
            }

            Frame::Stream(stream) => {
                let is_client = self.role == crate::tls::handshake::Role::Client;

                // Get or create the stream
                let initial_max = self.local_params.initial_max_stream_data_bidi_remote;
                let _stream_state =
                    self.streams
                        .get_or_create(stream.stream_id, is_client, initial_max);

                // Even if get_or_create fails (e.g., capacity), try to mark received
                if self.streams.get(stream.stream_id).is_some() {
                    // Enforce per-stream flow control and final-size consistency
                    // (mark_recv's error was previously discarded), and charge the
                    // newly received bytes to connection-level flow control
                    // (RFC 9000 §4.1). A violation is a fatal connection error.
                    let new_bytes = self.streams.mark_recv(
                        stream.stream_id,
                        stream.offset,
                        stream.data.len() as u64,
                        stream.fin,
                    )?;
                    self.flow_control.on_recv(new_bytes)?;

                    // Store the stream data in our receive buffer
                    self.store_stream_data(
                        sio,
                        stream.stream_id,
                        stream.offset,
                        stream.data,
                        stream.fin,
                    );

                    // Generate event
                    self.push_event(Event::StreamReadable(stream.stream_id));
                }
            }

            Frame::MaxData(max_data) => {
                self.flow_control.handle_max_data(max_data);
            }

            Frame::MaxStreamData(msd) => {
                let _ = self
                    .streams
                    .handle_max_stream_data(msd.stream_id, msd.max_data);
            }

            Frame::MaxStreams(ms) => {
                self.flow_control
                    .handle_max_streams(ms.bidirectional, ms.max_streams);
            }

            Frame::ResetStream(rst) => {
                if self.streams.get(rst.stream_id).is_some() {
                    let _ = self.streams.handle_reset(rst.stream_id, rst.final_size);
                    self.push_event(Event::StreamReset {
                        stream_id: rst.stream_id,
                        error_code: rst.error_code,
                    });
                }
            }

            Frame::StopSending(ss) => {
                if self.streams.get(ss.stream_id).is_some() {
                    let _ = self.streams.handle_stop_sending(ss.stream_id);
                    self.push_event(Event::StopSending {
                        stream_id: ss.stream_id,
                        error_code: ss.error_code,
                    });
                }
            }

            Frame::ConnectionClose(cc) => {
                self.state = ConnectionState::Draining;
                let mut reason = heapless::Vec::new();
                let copy_len = cc.reason.len().min(64);
                let _ = reason.extend_from_slice(&cc.reason[..copy_len]);
                self.push_event(Event::ConnectionClose {
                    error_code: cc.error_code,
                    reason,
                });
            }

            Frame::HandshakeDone => {
                // Only meaningful client-side: server sent HANDSHAKE_DONE
                if self.role == crate::tls::handshake::Role::Client {
                    if matches!(self.state, ConnectionState::Handshaking) {
                        self.state = ConnectionState::Active;
                        self.address_validated = true;
                        self.push_event(Event::Connected);
                    }
                    // Drop handshake keys now that handshake is confirmed
                    self.keys.drop_handshake();
                    self.sent_tracker.drop_space(Level::Handshake);
                    self.loss_detector.drop_space(Level::Handshake);
                }
            }

            Frame::NewToken(_) | Frame::NewConnectionId(_) | Frame::RetireConnectionId(_) => {
                // Accept and ignore for now
            }

            Frame::PathChallenge(data) => {
                // RFC 9000 §8.2.2: echo the 8-byte challenge data in a PATH_RESPONSE
                self.pending_path_response = Some(data);
            }

            Frame::PathResponse(_) => {
                // We don't currently initiate PATH_CHALLENGEs, so ignore responses.
            }

            Frame::DataBlocked(_) | Frame::StreamDataBlocked(_) | Frame::StreamsBlocked(_) => {
                // Informational; peer is blocked. No action needed.
            }
        }

        Ok(())
    }

    /// Handle a CRYPTO frame: reassemble data and feed complete TLS messages
    /// to the TLS engine.
    ///
    /// CRYPTO frames may arrive out of order within a packet or across packets.
    /// We buffer them and only deliver contiguous data to the TLS engine when
    /// we have at least one complete TLS handshake message (4-byte header +
    /// body).
    fn handle_crypto_frame<const CRYPTO_BUF: usize>(
        &mut self,
        level: Level,
        offset: u64,
        data: &[u8],
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        // If we no longer have a handshake slot, skip crypto processing.
        let slot = match self.handshake_slot {
            Some(s) => s,
            None => return Ok(()),
        };

        // Reject CRYPTO frames with very large offsets that could cause
        // resource exhaustion or overflow issues.
        const MAX_CRYPTO_OFFSET: u64 = 1 << 20; // 1 MiB
        if offset > MAX_CRYPTO_OFFSET
            || offset.saturating_add(data.len() as u64) > MAX_CRYPTO_OFFSET
        {
            return Err(Error::Transport(
                crate::error::TransportError::CryptoBufferExceeded,
            ));
        }

        let idx = level_index(level);

        // Insert into the reassembly buffer.
        pool.get_mut(slot).crypto_reasm[idx].insert(offset, data)?;

        // Deliver complete TLS handshake messages from the contiguous frontier.
        loop {
            // Re-check: check_tls_keys may have released the slot.
            let slot = match self.handshake_slot {
                Some(s) => s,
                None => break,
            };
            let ctx = pool.get_mut(slot);
            let avail = ctx.crypto_reasm[idx].contiguous_len();
            if avail < 4 {
                // Not enough data for a TLS handshake message header.
                break;
            }

            // Peek at the TLS handshake header to determine message length.
            let msg_len = {
                let hdr = ctx.crypto_reasm[idx].contiguous_data();
                // TLS handshake: 1 byte type + 3 bytes length
                4 + ((hdr[1] as usize) << 16 | (hdr[2] as usize) << 8 | hdr[3] as usize)
            };

            if avail < msg_len {
                // Incomplete TLS message — wait for more data.
                break;
            }

            // Feed the complete message straight from the reassembly buffer.
            // `tls` and `crypto_reasm` are disjoint fields of the same context,
            // so the input slice and the TLS engine can be borrowed at once —
            // no intermediate stack copy. This also lifts the old 2 KiB message
            // cap: messages up to CRYPTO_BUF (e.g. a larger Certificate) work.
            ctx.tls
                .read_handshake(level, &ctx.crypto_reasm[idx].contiguous_data()[..msg_len])?;

            // Advance the reassembly buffer past this message.
            ctx.crypto_reasm[idx].advance(msg_len);

            // Check for newly derived keys after each TLS message.
            self.check_tls_keys(pool)?;
        }

        Ok(())
    }

    /// Check if TLS engine has produced new keys and install them.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn check_tls_keys<const CRYPTO_BUF: usize>(
        &mut self,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        let slot = match self.handshake_slot {
            Some(s) => s,
            None => return Ok(()),
        };

        while let Some(derived) = pool.get_mut(slot).tls.derived_keys() {
            let level = derived.level;
            #[cfg(feature = "std")]
            eprintln!("[debug] installing keys for {:?}", level);
            self.keys.install_derived(&self.crypto, &derived)?;

            match level {
                Level::Handshake => {
                    // When handshake keys arrive on the client side, we can
                    // drop Initial keys (the client already sent its ClientHello).
                    // On the server side, we still need Initial keys to send
                    // the ServerHello, so defer dropping until after that.
                    if self.role == crate::tls::handshake::Role::Client {
                        self.keys.drop_initial();
                        self.sent_tracker.drop_space(Level::Initial);
                        self.loss_detector.drop_space(Level::Initial);
                    }
                }
                Level::Application => {
                    // Application keys ready. For server, transition to Active.
                    if self.role == crate::tls::handshake::Role::Server
                        && matches!(self.state, ConnectionState::Handshaking)
                    {
                        self.state = ConnectionState::Active;
                        self.address_validated = true;
                        self.push_event(Event::Connected);
                        // Server drops handshake keys after confirming
                        self.keys.drop_handshake();
                        self.sent_tracker.drop_space(Level::Handshake);
                        self.loss_detector.drop_space(Level::Handshake);
                    }
                }
                _ => {}
            }

            // Store peer transport params if available
            if let Some(peer_params) = pool.get_mut(slot).tls.peer_transport_params() {
                // Update flow control with peer's limits
                self.flow_control
                    .handle_max_data(peer_params.initial_max_data);
                self.flow_control
                    .handle_max_streams(true, peer_params.initial_max_streams_bidi);
                self.flow_control
                    .handle_max_streams(false, peer_params.initial_max_streams_uni);

                // RFC 9000 §10.1: the effective idle timeout is the minimum
                // of the two advertised non-zero max_idle_timeout values
                // (0 = that endpoint imposes no timeout). Params carry
                // milliseconds; connection timers run on microseconds.
                let effective_ms = match (
                    self.local_params.max_idle_timeout,
                    peer_params.max_idle_timeout,
                ) {
                    (0, p) => p,
                    (l, 0) => l,
                    (l, p) => l.min(p),
                };
                if effective_ms != 0 {
                    self.idle_timeout = Some(effective_ms.saturating_mul(1000));
                }

                self.peer_params = Some(peer_params.clone());
            }
        }

        // Release the handshake slot when the handshake is truly complete.
        // For the server: release when Active (handshake confirmed).
        // For the client: release once app keys are installed AND the TLS
        // engine has written its Finished message (is_complete == true).
        // We must NOT release earlier because the TLS engine still has the
        // client Finished in its pending_write buffer that poll_transmit
        // needs to flush. Releasing the slot resets the context and loses
        // that data, causing the handshake to stall.
        let can_release = if self.role == crate::tls::handshake::Role::Server {
            matches!(self.state, ConnectionState::Active)
        } else {
            // Client: release once app keys are installed AND TLS is complete
            // (i.e., client Finished has been written out via write_handshake).
            self.keys.app_send.is_some()
                && self.keys.app_recv.is_some()
                && pool.get_mut(slot).tls.is_complete()
        };

        if can_release {
            pool.release(slot);
            self.handshake_slot = None;
        }

        Ok(())
    }

    #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
    fn check_tls_keys<const CRYPTO_BUF: usize>(
        &mut self,
        _pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) -> Result<(), Error> {
        // Without crypto features, we can't install keys
        Ok(())
    }

    /// Release the handshake pool slot if the TLS handshake is fully complete.
    ///
    /// This is called from `poll_transmit` after flushing handshake-level
    /// packets. For the client, the TLS engine is not "complete" until
    /// `write_handshake` has been called and the Finished message has been
    /// flushed. So the slot can only be released here, not in `recv()`.
    pub(crate) fn maybe_release_handshake_slot<const CRYPTO_BUF: usize>(
        &mut self,
        pool: &mut dyn super::HandshakePoolAccess<C, CRYPTO_BUF>,
    ) {
        let slot = match self.handshake_slot {
            Some(s) => s,
            None => return,
        };

        let can_release = if self.role == crate::tls::handshake::Role::Server {
            matches!(self.state, ConnectionState::Active)
        } else {
            // Client: release once app keys are installed AND TLS is complete.
            self.keys.app_send.is_some()
                && self.keys.app_recv.is_some()
                && pool.get_mut(slot).tls.is_complete()
        };

        if can_release {
            pool.release(slot);
            self.handshake_slot = None;
        }
    }
}

/// Map Level to array index 0..3.
pub(crate) fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::Application => 2,
    }
}

/// Decrypt a long-header packet (Initial or Handshake) and return the
/// decrypted payload bytes and the decoded packet number.
///
/// This is a free function (not a method on `Connection`) so that the
/// borrow on the keys does not conflict with the `&mut self` borrow
/// needed for subsequent frame dispatch.
///
/// Generic over AEAD and HeaderProtection so that Initial packets
/// (concrete AES-128-GCM) and Handshake packets (negotiated cipher)
/// can share the same decryption logic.
fn decrypt_long_packet<A: Aead, HP: HeaderProtection>(
    pkt_data: &[u8],
    pn_offset: usize,
    payload_length: usize,
    largest_pn: u64,
    recv: &crate::crypto::DirectionalKeys<A, HP>,
    scratch: &mut [u8],
) -> Result<(usize, usize, u64), Error> {
    // Copy packet data to caller-provided scratch for in-place decryption
    let total_len = pn_offset + payload_length;
    if total_len > scratch.len() {
        return Err(Error::BufferTooSmall { needed: total_len });
    }
    scratch[..total_len].copy_from_slice(&pkt_data[..total_len]);

    // Remove header protection (RFC 9001 Section 5.4.2)
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > total_len {
        return Err(Error::Crypto);
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&scratch[sample_offset..sample_offset + 16]);
    let mask = recv.header_protection.mask(&sample);

    // For long headers: first_byte ^= mask[0] & 0x0f
    scratch[0] ^= mask[0] & 0x0f;
    let pn_len = ((scratch[0] & 0x03) + 1) as usize;

    // Unmask PN bytes
    for i in 0..pn_len {
        scratch[pn_offset + i] ^= mask[1 + i];
    }

    // Decode packet number
    let mut truncated_pn: u32 = 0;
    for i in 0..pn_len {
        truncated_pn = (truncated_pn << 8) | scratch[pn_offset + i] as u32;
    }
    let pn = packet::decode_pn(truncated_pn, pn_len, largest_pn);

    if pn > crate::varint::MAX_VARINT {
        return Err(Error::Transport(
            crate::error::TransportError::ProtocolViolation,
        ));
    }

    // Decrypt payload using split_at_mut for zero-copy AAD
    let payload_offset = pn_offset + pn_len;
    let encrypted_len = payload_length - pn_len;

    let nonce = recv.nonce(pn);
    let pt_len = {
        let (aad, payload_area) =
            scratch[..payload_offset + encrypted_len].split_at_mut(payload_offset);
        recv.aead
            .open_in_place(&nonce, &*aad, payload_area, encrypted_len)?
    };

    // Decrypted payload is now at scratch[payload_offset..payload_offset + pt_len]
    Ok((payload_offset, pt_len, pn))
}

use super::ConnectionId;

#[cfg(test)]
mod tests {
    use super::CryptoReassemblyBuf;

    #[test]
    fn in_order_delivery() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        buf.insert(0, b"hello").unwrap();
        assert_eq!(buf.contiguous_len(), 5);
        assert_eq!(buf.contiguous_data(), b"hello");

        buf.insert(5, b" world").unwrap();
        assert_eq!(buf.contiguous_len(), 11);
        assert_eq!(buf.contiguous_data(), b"hello world");
    }

    #[test]
    fn out_of_order_two_frames() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        // Second chunk arrives first.
        buf.insert(5, b" world").unwrap();
        assert_eq!(buf.contiguous_len(), 0);

        // First chunk fills the gap.
        buf.insert(0, b"hello").unwrap();
        assert_eq!(buf.contiguous_len(), 11);
        assert_eq!(buf.contiguous_data(), b"hello world");
    }

    #[test]
    fn out_of_order_three_frames() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        // Arrive in order: [10..15], [0..5], [5..10]
        buf.insert(10, b"CCCCC").unwrap();
        assert_eq!(buf.contiguous_len(), 0);

        buf.insert(0, b"AAAAA").unwrap();
        assert_eq!(buf.contiguous_len(), 5); // only A block contiguous

        buf.insert(5, b"BBBBB").unwrap();
        assert_eq!(buf.contiguous_len(), 15); // all contiguous now
        assert_eq!(buf.contiguous_data(), b"AAAAABBBBBCCCCC");
    }

    #[test]
    fn advance_shifts_buffer() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        buf.insert(0, b"AAAAABBBBB").unwrap();
        assert_eq!(buf.contiguous_len(), 10);

        buf.advance(5);
        assert_eq!(buf.contiguous_len(), 5);
        assert_eq!(buf.contiguous_data(), b"BBBBB");
        assert_eq!(buf.delivered, 5);

        // Insert more data after advance.
        buf.insert(10, b"CCCCC").unwrap();
        assert_eq!(buf.contiguous_len(), 10);
        assert_eq!(buf.contiguous_data(), b"BBBBBCCCCC");
    }

    #[test]
    fn duplicate_retransmit_ignored() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        buf.insert(0, b"hello").unwrap();
        buf.advance(5);

        // Retransmit of already-delivered data.
        buf.insert(0, b"hello").unwrap();
        assert_eq!(buf.contiguous_len(), 0);
        assert_eq!(buf.delivered, 5);
    }

    #[test]
    fn partial_overlap_with_delivered() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        buf.insert(0, b"hello").unwrap();
        buf.advance(3); // delivered 3 bytes, "lo" remains

        // Frame overlaps: bytes 2..7 but 2..3 already delivered.
        buf.insert(2, b"lo wo").unwrap();
        assert_eq!(buf.contiguous_len(), 4); // "lo w" from offset 3..7
        // But note: "lo" was already there, and "o w" is new. Let's check:
        // After advance(3), delivered=3, buffer has "lo" at [0..2].
        // insert(2, "lo wo") → trimmed to insert(3, "o wo") → rel 0..4.
        // Merged with existing [0..2] → [0..4].
        assert_eq!(&buf.contiguous_data()[..4], b"o wo");
    }

    #[test]
    fn overlapping_ranges_merge() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        buf.insert(0, b"AAAA").unwrap(); // [0..4]
        buf.insert(8, b"CCCC").unwrap(); // [8..12]
        assert_eq!(buf.contiguous_len(), 4); // only first block

        // Bridge the gap.
        buf.insert(3, b"BBBBBBB").unwrap(); // [3..10] overlaps both
        assert_eq!(buf.contiguous_len(), 12);
    }

    #[test]
    fn empty_insert_is_noop() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        buf.insert(0, b"").unwrap();
        assert_eq!(buf.contiguous_len(), 0);
    }

    #[test]
    fn buffer_overflow_returns_error() {
        let mut buf = CryptoReassemblyBuf::<4096>::new();
        // Try to insert beyond buffer capacity.
        let big = [0u8; 100];
        let result = buf.insert(4000, &big);
        assert!(result.is_err());
    }
}
