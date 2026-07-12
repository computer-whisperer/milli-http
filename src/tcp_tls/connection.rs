//! TLS 1.3 connection state machine over TCP.
//!
//! Follows the milli-http `feed_data()` → `poll_output()` → `poll_event()` pattern.

use crate::buf::{Buf, BufExt};
use crate::crypto::key_schedule::derive_tls_record_keys;
use crate::crypto::{Aead, CryptoProvider, Level};
use crate::error::Error;
use crate::tls::handshake::{ServerTlsConfig, TlsConfig, TlsEngine};
use crate::tls::{DerivedKeys, TlsSession};

use super::io::TlsIo;
use super::record::{self, ContentType, RECORD_HEADER_LEN};

/// Events produced by TlsConnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsEvent {
    /// TLS handshake is complete; application data can now flow.
    HandshakeComplete,
    /// Application data is available (call `recv_app_data`).
    AppData,
    /// Peer sent a close_notify alert.
    PeerClosed,
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    /// TLS handshake in progress (plaintext records).
    Handshake,
    /// Handshake in progress, ServerHello received, handshake records encrypted.
    HandshakeEncrypted,
    /// Handshake complete, application data flowing.
    Active,
    /// close_notify sent or received.
    Closing,
    /// Connection fully closed.
    Closed,
}

/// AEAD + IV for one direction.
struct DirectionalRecordKeys<A: Aead> {
    aead: A,
    iv: [u8; 12],
}

/// TLS 1.3 connection state machine.
///
/// `C`: CryptoProvider implementation.
///
/// I/O buffers are **not** owned by this struct; callers provide them via
/// [`TlsIo`] on every method that touches network or application data.
pub struct TlsConnection<C: CryptoProvider> {
    provider: C,
    engine: TlsEngine<C>,
    state: ConnState,

    send_offset: usize,

    // AEAD keys for handshake traffic
    hs_send: Option<DirectionalRecordKeys<C::Aead>>,
    hs_recv: Option<DirectionalRecordKeys<C::Aead>>,

    // AEAD keys for application traffic
    app_send: Option<DirectionalRecordKeys<C::Aead>>,
    app_recv: Option<DirectionalRecordKeys<C::Aead>>,

    // Per-direction sequence numbers
    send_seq: u64,
    recv_seq: u64,
    hs_send_seq: u64,
    hs_recv_seq: u64,

    // RFC 8449 record_size_limit advertised by the peer: the max
    // plaintext-plus-content-type bytes per record the peer will receive.
    // 16385 ("no limit") until the peer advertises one during the handshake.
    peer_record_limit: u16,

    // Event queue
    events: heapless::Deque<TlsEvent, 8>,

    // Whether we've already sent the engine's handshake output
    engine_output_pending: bool,

    // Track whether we need to send ChangeCipherSpec (middlebox compat)
    ccs_sent: bool,
}

impl<C: CryptoProvider> TlsConnection<C>
where
    C::Hkdf: Default,
{
    /// Create a new client-side TLS connection.
    pub fn new_client(provider: C, config: TlsConfig, secret: [u8; 32], random: [u8; 32]) -> Self {
        let engine = TlsEngine::<C>::new_tcp_client(config, secret, random);
        Self::new(provider, engine)
    }

    /// Create a new server-side TLS connection.
    pub fn new_server(
        provider: C,
        config: ServerTlsConfig,
        secret: [u8; 32],
        random: [u8; 32],
    ) -> Self {
        let engine = TlsEngine::<C>::new_tcp_server(config, secret, random);
        Self::new(provider, engine)
    }

    fn new(provider: C, engine: TlsEngine<C>) -> Self {
        Self {
            provider,
            engine,
            state: ConnState::Handshake,
            send_offset: 0,
            hs_send: None,
            hs_recv: None,
            app_send: None,
            app_recv: None,
            send_seq: 0,
            recv_seq: 0,
            hs_send_seq: 0,
            hs_recv_seq: 0,
            peer_record_limit: 16385,
            events: heapless::Deque::new(),
            engine_output_pending: true,
            ccs_sent: false,
        }
    }

    /// Feed raw TCP data into the connection.
    ///
    /// Records are decrypted **in place** inside `io.recv_buf`: between calls
    /// the buffer's visible contents are exactly the decrypted plaintext ready
    /// for the application (drained by [`recv_app_data`](Self::recv_app_data)
    /// or directly by a composed protocol layer), while any remaining
    /// ciphertext (a partial trailing record, or records left unprocessed
    /// after an alert) is parked as a hidden tail (see [`Buf::hide_tail`]).
    pub fn feed_data<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        data: &[u8],
    ) -> Result<(), Error> {
        self.engine
            .set_local_record_size_limit(local_record_size_limit::<BUF>());
        // Reveal pending ciphertext behind the plaintext prefix, append the
        // new bytes after it, process, then re-hide whatever ciphertext is
        // left. `plain` tracks the plaintext/ciphertext boundary throughout —
        // including across early returns (alerts, errors) — so the invariant
        // holds on every exit path.
        let mut plain = io.recv_buf.len();
        io.recv_buf.unhide_tail();
        let result = self.feed_revealed(io, data, &mut plain);
        io.recv_buf.hide_tail(io.recv_buf.len() - plain);
        result
    }

    /// Body of `feed_data` running with the ciphertext tail revealed.
    fn feed_revealed<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        data: &[u8],
        plain: &mut usize,
    ) -> Result<(), Error> {
        if io.recv_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: io.recv_buf.len() + data.len(),
            });
        }
        io.recv_buf.buf_try_reserve(data.len())?;
        let _ = io.recv_buf.extend_from_slice(data);
        self.process_recv(io, plain)
    }

    /// Pull the next chunk of outgoing TCP data.
    pub fn poll_output<'a, const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        self.engine
            .set_local_record_size_limit(local_record_size_limit::<BUF>());
        self.flush_engine_output(io);
        self.flush_app_send(io);

        if self.send_offset >= io.send_buf.len() {
            return None;
        }

        let avail = io.send_buf.len() - self.send_offset;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&io.send_buf[self.send_offset..self.send_offset + n]);
        self.send_offset += n;

        if self.send_offset >= io.send_buf.len() {
            io.send_buf.clear();
            self.send_offset = 0;
        }

        Some(&buf[..n])
    }

    /// Poll for the next TLS event.
    pub fn poll_event(&mut self) -> Option<TlsEvent> {
        self.events.pop_front()
    }

    /// Read decrypted application data (the visible plaintext prefix of
    /// `io.recv_buf`).
    pub fn recv_app_data<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        if io.recv_buf.is_empty() {
            return Err(Error::WouldBlock);
        }
        let n = io.recv_buf.len().min(buf.len());
        buf[..n].copy_from_slice(&io.recv_buf[..n]);
        io.drain_recv(n);
        Ok(n)
    }

    /// Queue application data for encryption and sending.
    pub fn send_app_data<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        data: &[u8],
    ) -> Result<usize, Error> {
        if self.state != ConnState::Active {
            return Err(Error::InvalidState);
        }
        if io.app_send_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: io.app_send_buf.len() + data.len(),
            });
        }
        io.app_send_buf.buf_try_reserve(data.len())?;
        let _ = io.app_send_buf.extend_from_slice(data);
        Ok(data.len())
    }

    /// Get the negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.engine.alpn()
    }

    /// Whether the connection is active (handshake complete, not closed).
    pub fn is_active(&self) -> bool {
        self.state == ConnState::Active
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnState::Closed | ConnState::Closing)
    }

    /// Initiate a graceful close (send close_notify).
    pub fn close<const BUF: usize>(&mut self, io: &mut TlsIo<'_, BUF>) -> Result<(), Error> {
        if self.state == ConnState::Closed || self.state == ConnState::Closing {
            return Ok(());
        }
        self.send_alert(io, 1, 0)?; // warning(1) close_notify(0)
        self.state = ConnState::Closing;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: processing received data
    // ------------------------------------------------------------------

    /// Process received TLS records from `io.recv_buf`.
    ///
    /// `*plain` is the boundary between decrypted application plaintext
    /// (`recv_buf[..*plain]`, kept for the app) and raw ciphertext
    /// (`recv_buf[*plain..]`, zero or more records, possibly a partial one at
    /// the end). Each complete record is taken from the ciphertext region:
    /// application data is decrypted in place and compacted down onto the end
    /// of the plaintext region (advancing `*plain`); every other record is
    /// handled and removed. `*plain` is kept correct on every return path.
    fn process_recv<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        plain: &mut usize,
    ) -> Result<(), Error> {
        loop {
            let off = *plain;
            if io.recv_buf.len() - off < RECORD_HEADER_LEN {
                return Ok(());
            }

            let hdr = record::decode_record_header(&io.recv_buf[off..off + RECORD_HEADER_LEN])?;
            let total = RECORD_HEADER_LEN + hdr.length as usize;

            // A record larger than the receive buffer can never be assembled —
            // fail fast instead of waiting forever for bytes that will be
            // rejected by `feed_data`'s capacity check. (Should not happen once
            // BUF holds a full 16 KiB record, but turns a misconfigured BUF
            // from a silent hang into a clean connection error.)
            if total > BUF {
                return Err(Error::BufferTooSmall { needed: total });
            }

            if io.recv_buf.len() - off < total {
                return Ok(());
            }

            let header_bytes: [u8; 5] = [
                io.recv_buf[off],
                io.recv_buf[off + 1],
                io.recv_buf[off + 2],
                io.recv_buf[off + 3],
                io.recv_buf[off + 4],
            ];
            let payload_len = hdr.length as usize;
            let ct = hdr.content_type;
            let ps = off + RECORD_HEADER_LEN;

            let mut need_check_keys = false;
            // Length of decrypted application plaintext (at `ps`) to keep for
            // the app, if this record carried any.
            let mut app_data_len: Option<usize> = None;

            match self.state {
                ConnState::Handshake => match ct {
                    ContentType::Handshake => {
                        self.engine
                            .read_handshake(Level::Initial, &io.recv_buf[ps..ps + payload_len])
                            .map_err(|_| Error::Tls)?;
                        need_check_keys = true;
                    }
                    ContentType::ChangeCipherSpec => {}
                    ContentType::Alert => {
                        if payload_len < 2 {
                            return Err(Error::Tls);
                        }
                        let desc = io.recv_buf[ps + 1];
                        remove_range(io, off, off + total);
                        return self.handle_alert_desc(desc);
                    }
                    _ => return Err(Error::Tls),
                },
                ConnState::HandshakeEncrypted => match ct {
                    ContentType::ApplicationData => {
                        let keys = self.hs_recv.as_ref().ok_or(Error::Tls)?;
                        let nonce = record::build_nonce(&keys.iv, self.hs_recv_seq);
                        let plain_len = keys.aead.open_in_place(
                            &nonce,
                            &header_bytes,
                            &mut io.recv_buf[ps..ps + payload_len],
                            payload_len,
                        )?;
                        // Advance only after successful decryption.
                        self.hs_recv_seq += 1;
                        let (data_len, inner_ct) =
                            find_inner_content_type(&io.recv_buf[ps..ps + plain_len])?;
                        match inner_ct {
                            ContentType::Handshake => {
                                self.engine
                                    .read_handshake(
                                        Level::Handshake,
                                        &io.recv_buf[ps..ps + data_len],
                                    )
                                    .map_err(|_| Error::Tls)?;
                                need_check_keys = true;
                            }
                            ContentType::Alert => {
                                if data_len < 2 {
                                    return Err(Error::Tls);
                                }
                                let desc = io.recv_buf[ps + 1];
                                remove_range(io, off, off + total);
                                return self.handle_alert_desc(desc);
                            }
                            _ => return Err(Error::Tls),
                        }
                    }
                    ContentType::ChangeCipherSpec => {}
                    ContentType::Handshake => {
                        self.engine
                            .read_handshake(Level::Initial, &io.recv_buf[ps..ps + payload_len])
                            .map_err(|_| Error::Tls)?;
                        need_check_keys = true;
                    }
                    _ => return Err(Error::Tls),
                },
                ConnState::Active => {
                    match ct {
                        ContentType::ApplicationData => {
                            let keys = self.app_recv.as_ref().ok_or(Error::Tls)?;
                            let nonce = record::build_nonce(&keys.iv, self.recv_seq);
                            let plain_len = keys.aead.open_in_place(
                                &nonce,
                                &header_bytes,
                                &mut io.recv_buf[ps..ps + payload_len],
                                payload_len,
                            )?;
                            // Advance only after successful decryption.
                            self.recv_seq += 1;
                            let (data_len, inner_ct) =
                                find_inner_content_type(&io.recv_buf[ps..ps + plain_len])?;
                            match inner_ct {
                                ContentType::ApplicationData => {
                                    app_data_len = Some(data_len);
                                }
                                ContentType::Alert => {
                                    if data_len < 2 {
                                        return Err(Error::Tls);
                                    }
                                    let desc = io.recv_buf[ps + 1];
                                    remove_range(io, off, off + total);
                                    return self.handle_alert_desc(desc);
                                }
                                ContentType::Handshake => {} // Post-handshake
                                _ => return Err(Error::Tls),
                            }
                        }
                        ContentType::ChangeCipherSpec => {}
                        _ => return Err(Error::Tls),
                    }
                }
                ConnState::Closing | ConnState::Closed => {}
            }

            match app_data_len {
                Some(data_len) => {
                    // Keep the plaintext: compact it down over the record
                    // header, then close the gap left by the AEAD tag /
                    // content-type byte / padding so any trailing ciphertext
                    // stays contiguous.
                    io.recv_buf.copy_within(ps..ps + data_len, off);
                    remove_range(io, off + data_len, off + total);
                    *plain += data_len;
                    let _ = self.events.push_back(TlsEvent::AppData);
                }
                None => remove_range(io, off, off + total),
            }

            if need_check_keys {
                self.check_keys()?;
            }
        }
    }

    fn handle_alert_desc(&mut self, desc: u8) -> Result<(), Error> {
        if desc == 0 {
            self.state = ConnState::Closing;
            let _ = self.events.push_back(TlsEvent::PeerClosed);
            Ok(())
        } else {
            self.state = ConnState::Closed;
            Err(Error::Tls)
        }
    }

    fn send_alert<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        level: u8,
        desc: u8,
    ) -> Result<(), Error> {
        let alert_data = [level, desc];
        if self.state == ConnState::Active {
            self.encrypt_and_send(io, &alert_data, ContentType::Alert, false)
        } else {
            let mut buf = [0u8; 16];
            let n = record::encode_record_header(ContentType::Alert, 2, &mut buf)?;
            buf[n] = level;
            buf[n + 1] = desc;
            io.queue_send(&buf[..n + 2])
        }
    }

    // ------------------------------------------------------------------
    // Internal: key management
    // ------------------------------------------------------------------

    fn check_keys(&mut self) -> Result<(), Error> {
        // Pick up the peer's RFC 8449 record-size limit as soon as the engine
        // has parsed it (ClientHello for servers, EncryptedExtensions for
        // clients) — it applies to every record we protect from then on.
        if let Some(limit) = self.engine.peer_record_size_limit() {
            self.peer_record_limit = limit;
        }

        while let Some(keys) = self.engine.derived_keys() {
            self.install_keys(keys)?;
        }

        if self.engine.is_complete() && self.state != ConnState::Active {
            self.state = ConnState::Active;
            self.send_seq = 0;
            self.recv_seq = 0;
            self.engine.shrink_post_handshake();
            // Handshake keys are no longer needed
            self.hs_send = None;
            self.hs_recv = None;
            let _ = self.events.push_back(TlsEvent::HandshakeComplete);
        }

        Ok(())
    }

    fn install_keys(&mut self, keys: DerivedKeys) -> Result<(), Error> {
        let hkdf = C::Hkdf::default();
        let key_len = C::Aead::KEY_LEN;

        let send_secret = &keys.send_secret[..keys.secret_len];
        let recv_secret = &keys.recv_secret[..keys.secret_len];

        match keys.level {
            Level::Handshake => {
                let mut send_key_buf = [0u8; 32];
                let mut send_iv = [0u8; 12];
                derive_tls_record_keys(
                    &hkdf,
                    send_secret,
                    &mut send_key_buf[..key_len],
                    &mut send_iv,
                )?;
                let send_aead = self.provider.aead(&send_key_buf[..key_len])?;
                self.hs_send = Some(DirectionalRecordKeys {
                    aead: send_aead,
                    iv: send_iv,
                });

                let mut recv_key_buf = [0u8; 32];
                let mut recv_iv = [0u8; 12];
                derive_tls_record_keys(
                    &hkdf,
                    recv_secret,
                    &mut recv_key_buf[..key_len],
                    &mut recv_iv,
                )?;
                let recv_aead = self.provider.aead(&recv_key_buf[..key_len])?;
                self.hs_recv = Some(DirectionalRecordKeys {
                    aead: recv_aead,
                    iv: recv_iv,
                });

                self.hs_send_seq = 0;
                self.hs_recv_seq = 0;
                self.state = ConnState::HandshakeEncrypted;
                self.engine_output_pending = true;
            }
            Level::Application => {
                let mut send_key_buf = [0u8; 32];
                let mut send_iv = [0u8; 12];
                derive_tls_record_keys(
                    &hkdf,
                    send_secret,
                    &mut send_key_buf[..key_len],
                    &mut send_iv,
                )?;
                let send_aead = self.provider.aead(&send_key_buf[..key_len])?;
                self.app_send = Some(DirectionalRecordKeys {
                    aead: send_aead,
                    iv: send_iv,
                });

                let mut recv_key_buf = [0u8; 32];
                let mut recv_iv = [0u8; 12];
                derive_tls_record_keys(
                    &hkdf,
                    recv_secret,
                    &mut recv_key_buf[..key_len],
                    &mut recv_iv,
                )?;
                let recv_aead = self.provider.aead(&recv_key_buf[..key_len])?;
                self.app_recv = Some(DirectionalRecordKeys {
                    aead: recv_aead,
                    iv: recv_iv,
                });

                self.engine_output_pending = true;
            }
            _ => {}
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: output generation
    // ------------------------------------------------------------------

    fn flush_engine_output<const BUF: usize>(&mut self, io: &mut TlsIo<'_, BUF>) {
        if !self.engine_output_pending {
            return;
        }

        let mut buf = [0u8; 2048];
        loop {
            let (n, level) = match self.engine.write_handshake(&mut buf) {
                Ok(result) => result,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }

            match level {
                Level::Initial => {
                    let _ = self.wrap_plaintext_record(io, ContentType::Handshake, &buf[..n]);
                }
                Level::Handshake => {
                    if !self.ccs_sent {
                        let ccs = [
                            ContentType::ChangeCipherSpec as u8,
                            0x03,
                            0x03,
                            0x00,
                            0x01,
                            0x01,
                        ];
                        let _ = io.queue_send(&ccs);
                        self.ccs_sent = true;
                    }
                    // RFC 8449: the peer's record-size limit applies to every
                    // record protected with handshake keys, so fragment the
                    // flight (EE+Cert+CV+Finished) into multiple records if
                    // it exceeds the limit. Prefer record boundaries that
                    // coincide with handshake-message boundaries so minimal
                    // receivers need no cross-record message reassembly.
                    let cap = self.peer_plaintext_cap();
                    let mut start = 0usize;
                    while start < n {
                        // Greedily pack whole messages while they fit.
                        let mut end = start;
                        while end < n {
                            let msg_end = handshake_msg_end(&buf[..n], end);
                            if msg_end - start > cap {
                                break;
                            }
                            end = msg_end;
                        }
                        if end == start {
                            // A single message exceeds the cap: fragment it
                            // across records (RFC 8446 §5.1 — the peer must
                            // reassemble).
                            let msg_end = handshake_msg_end(&buf[..n], start);
                            for chunk in buf[start..msg_end].chunks(cap) {
                                let _ =
                                    self.encrypt_and_send(io, chunk, ContentType::Handshake, true);
                            }
                            start = msg_end;
                        } else {
                            let _ = self.encrypt_and_send(
                                io,
                                &buf[start..end],
                                ContentType::Handshake,
                                true,
                            );
                            start = end;
                        }
                    }
                }
                _ => {}
            }
        }

        let _ = self.check_keys();
        self.engine_output_pending = false;
    }

    fn flush_app_send<const BUF: usize>(&mut self, io: &mut TlsIo<'_, BUF>) {
        if io.app_send_buf.is_empty() || self.state != ConnState::Active {
            return;
        }

        let cap = self.peer_plaintext_cap();
        while !io.app_send_buf.is_empty() {
            let chunk_len = io.app_send_buf.len().min(cap);
            let keys = match self.app_send.as_ref() {
                Some(k) => k,
                None => break,
            };
            let nonce = record::build_nonce(&keys.iv, self.send_seq);

            if encrypt_into::<C::Aead, BUF>(
                &io.app_send_buf[..chunk_len],
                ContentType::ApplicationData,
                &keys.aead,
                &nonce,
                io.send_buf,
            )
            .is_err()
            {
                // Record was not emitted (e.g. send_buf full); do NOT consume the
                // sequence number, or every subsequent record desyncs the peer's nonce.
                break;
            }
            // Only advance the sequence number once the record is committed.
            self.send_seq += 1;

            io.app_send_buf.copy_within(chunk_len.., 0);
            io.app_send_buf.truncate(io.app_send_buf.len() - chunk_len);
        }
    }

    /// Max plaintext bytes per outgoing protected record under the peer's
    /// RFC 8449 limit (the advertised value counts the inner content-type
    /// byte, so plaintext ≤ limit − 1), never exceeding the TLS 1.3 maximum
    /// of 16384 and never below 1.
    fn peer_plaintext_cap(&self) -> usize {
        (self.peer_record_limit as usize)
            .saturating_sub(1)
            .clamp(1, 16384)
    }

    fn wrap_plaintext_record<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        ct: ContentType,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut header = [0u8; 5];
        record::encode_record_header(ct, data.len() as u16, &mut header)?;
        io.queue_send(&header)?;
        io.queue_send(data)
    }

    fn encrypt_and_send<const BUF: usize>(
        &mut self,
        io: &mut TlsIo<'_, BUF>,
        data: &[u8],
        inner_ct: ContentType,
        use_hs_keys: bool,
    ) -> Result<(), Error> {
        if use_hs_keys {
            let keys = self.hs_send.as_ref().ok_or(Error::Tls)?;
            let nonce = record::build_nonce(&keys.iv, self.hs_send_seq);
            encrypt_into::<C::Aead, BUF>(data, inner_ct, &keys.aead, &nonce, io.send_buf)?;
            // Advance only after a record was actually produced, so a buffer-full
            // failure cannot consume a sequence number and desync the peer.
            self.hs_send_seq += 1;
            Ok(())
        } else {
            let keys = self.app_send.as_ref().ok_or(Error::Tls)?;
            let nonce = record::build_nonce(&keys.iv, self.send_seq);
            encrypt_into::<C::Aead, BUF>(data, inner_ct, &keys.aead, &nonce, io.send_buf)?;
            self.send_seq += 1;
            Ok(())
        }
    }
}

/// End offset of the TLS handshake message starting at `off` (1-byte type +
/// 3-byte body length + body), clamped to `buf.len()`. Returns `buf.len()`
/// when there is no room for a full header.
fn handshake_msg_end(buf: &[u8], off: usize) -> usize {
    if off + 4 > buf.len() {
        return buf.len();
    }
    let body_len =
        ((buf[off + 1] as usize) << 16) | ((buf[off + 2] as usize) << 8) | (buf[off + 3] as usize);
    (off + 4 + body_len).min(buf.len())
}

/// The RFC 8449 record_size_limit we advertise, derived from the record
/// layer's receive-buffer size.
///
/// The advertised value is the max plaintext-plus-content-type bytes per
/// record; `recv_buf` must hold the whole ciphertext record (5-byte header +
/// plaintext + 1 content-type byte + 16-byte AEAD tag = plaintext + 22), so
/// keep 64 bytes of margin over that expansion. Clamped to the legal range
/// [64, 16385] (16385 = "no limit" for TLS 1.3).
fn local_record_size_limit<const BUF: usize>() -> u16 {
    BUF.saturating_sub(64).clamp(64, 16385) as u16
}

/// Remove `recv_buf[start..end]`, shifting everything after `end` down.
fn remove_range<const BUF: usize>(io: &mut TlsIo<'_, BUF>, start: usize, end: usize) {
    let len = io.recv_buf.len();
    io.recv_buf.copy_within(end.., start);
    io.recv_buf.truncate(len - (end - start));
}

/// Find the inner content type from decrypted TLS record plaintext.
/// The inner CT is the last non-zero byte; everything before it is the actual data.
fn find_inner_content_type(plaintext: &[u8]) -> Result<(usize, ContentType), Error> {
    let mut pos = plaintext.len();
    while pos > 0 && plaintext[pos - 1] == 0 {
        pos -= 1;
    }
    if pos == 0 {
        return Err(Error::Tls);
    }
    let ct = ContentType::from_byte(plaintext[pos - 1]).ok_or(Error::Tls)?;
    Ok((pos - 1, ct))
}

/// Encrypt a TLS record directly into `send_buf`, avoiding any large stack temp.
///
/// Writes a complete TLS record: 5-byte header + AEAD-encrypted (data + inner_ct + tag).
fn encrypt_into<A: crate::crypto::Aead, const BUF: usize>(
    data: &[u8],
    inner_ct: ContentType,
    aead: &A,
    nonce: &[u8; 12],
    send_buf: &mut Buf<BUF>,
) -> Result<(), Error> {
    let inner_len = data.len() + 1; // data + inner content type byte
    let outer_payload_len = inner_len + A::TAG_LEN;
    let total_needed = RECORD_HEADER_LEN + outer_payload_len;

    if send_buf.len() + total_needed > BUF {
        return Err(Error::BufferTooSmall {
            needed: send_buf.len() + total_needed,
        });
    }
    send_buf.buf_try_reserve(total_needed)?;

    // Build and write record header (also used as AAD)
    let mut header = [0u8; 5];
    record::encode_record_header(
        ContentType::ApplicationData,
        outer_payload_len as u16,
        &mut header,
    )?;
    let _ = send_buf.extend_from_slice(&header);

    // Write plaintext payload directly into send_buf: data + inner_ct
    let enc_start = send_buf.len();
    let _ = send_buf.extend_from_slice(data);
    let _ = send_buf.push(inner_ct as u8);
    // Reserve space for AEAD tag
    for _ in 0..A::TAG_LEN {
        let _ = send_buf.push(0);
    }

    // Encrypt in-place within send_buf
    let ct_len = aead.seal_in_place(nonce, &header, &mut send_buf[enc_start..], inner_len)?;
    send_buf.truncate(enc_start + ct_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::super::io::TlsIoBufs;
    use super::*;
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    use crate::tls::TransportParams;
    use crate::tls::handshake::{ServerTlsConfig, TlsConfig};

    type TestConn = TlsConnection<Aes128GcmProvider>;
    type TestIo = TlsIoBufs<32768>;

    const TEST_SEED: [u8; 32] = [0x01u8; 32];

    fn test_cert_der() -> Vec<u8> {
        let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&TEST_SEED);
        let mut buf = [0u8; 512];
        let len = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut buf).unwrap();
        buf[..len].to_vec()
    }

    fn make_client() -> TestConn {
        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        TestConn::new_client(Aes128GcmProvider, config, [0xAA; 32], [0xBB; 32])
    }

    fn make_server(cert: &'static [u8]) -> TestConn {
        let config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
        };
        TestConn::new_server(Aes128GcmProvider, config, [0xCC; 32], [0xDD; 32])
    }

    fn transfer<const A: usize, const B: usize>(
        src: &mut TestConn,
        sio: &mut TlsIoBufs<A>,
        dst: &mut TestConn,
        dio: &mut TlsIoBufs<B>,
    ) -> bool {
        let mut any = false;
        let mut buf = [0u8; 32768];
        while let Some(data) = src.poll_output(&mut sio.as_io(), &mut buf) {
            let copy = data.to_vec();
            dst.feed_data(&mut dio.as_io(), &copy).unwrap();
            any = true;
        }
        any
    }

    fn handshake<const A: usize, const B: usize>(
        client: &mut TestConn,
        cio: &mut TlsIoBufs<A>,
        server: &mut TestConn,
        sio: &mut TlsIoBufs<B>,
    ) {
        for _ in 0..20 {
            let a = transfer(client, cio, server, sio);
            let b = transfer(server, sio, client, cio);
            if !a && !b {
                break;
            }
        }
    }

    fn drain_events(c: &mut TestConn) -> Vec<TlsEvent> {
        let mut events = Vec::new();
        while let Some(ev) = c.poll_event() {
            events.push(ev);
        }
        events
    }

    #[test]
    fn handshake_completes() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        assert!(!client.is_active());
        assert!(!server.is_active());

        handshake(&mut client, &mut cio, &mut server, &mut sio);

        let client_events = drain_events(&mut client);
        let server_events = drain_events(&mut server);

        assert!(
            client_events.contains(&TlsEvent::HandshakeComplete),
            "client should emit HandshakeComplete, got: {:?}",
            client_events,
        );
        assert!(
            server_events.contains(&TlsEvent::HandshakeComplete),
            "server should emit HandshakeComplete, got: {:?}",
            server_events,
        );

        assert!(client.is_active());
        assert!(server.is_active());
    }

    #[test]
    fn app_data_roundtrip() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        client
            .send_app_data(&mut cio.as_io(), b"Hello from client")
            .unwrap();
        transfer(&mut client, &mut cio, &mut server, &mut sio);

        let server_events = drain_events(&mut server);
        assert!(server_events.contains(&TlsEvent::AppData));

        let mut recv_buf = [0u8; 256];
        let n = server
            .recv_app_data(&mut sio.as_io(), &mut recv_buf)
            .unwrap();
        assert_eq!(&recv_buf[..n], b"Hello from client");

        server
            .send_app_data(&mut sio.as_io(), b"Hello from server")
            .unwrap();
        transfer(&mut server, &mut sio, &mut client, &mut cio);

        let client_events = drain_events(&mut client);
        assert!(client_events.contains(&TlsEvent::AppData));

        let n = client
            .recv_app_data(&mut cio.as_io(), &mut recv_buf)
            .unwrap();
        assert_eq!(&recv_buf[..n], b"Hello from server");
    }

    #[test]
    fn alpn_negotiation() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        assert_eq!(client.alpn(), Some(b"h2".as_slice()));
        assert_eq!(server.alpn(), Some(b"h2".as_slice()));
    }

    #[test]
    fn send_before_handshake_fails() {
        let cert = test_cert_der().leak();
        let client = make_client();
        let _server = make_server(cert);

        assert!(!client.is_active());
    }

    #[test]
    fn graceful_close() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        client.close(&mut cio.as_io()).unwrap();
        assert!(client.is_closed());

        transfer(&mut client, &mut cio, &mut server, &mut sio);

        let server_events = drain_events(&mut server);
        assert!(
            server_events.contains(&TlsEvent::PeerClosed),
            "server should see PeerClosed, got: {:?}",
            server_events,
        );
    }

    #[test]
    fn multiple_app_data_messages() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        for i in 0..5u8 {
            let msg = [b'A' + i; 100];
            client.send_app_data(&mut cio.as_io(), &msg).unwrap();
        }

        transfer(&mut client, &mut cio, &mut server, &mut sio);

        let mut recv_buf = [0u8; 1024];
        let n = server
            .recv_app_data(&mut sio.as_io(), &mut recv_buf)
            .unwrap();
        assert_eq!(n, 500);
    }

    #[test]
    fn send_app_data_before_handshake_returns_error() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let _server = make_server(cert);

        let result = client.send_app_data(&mut cio.as_io(), b"too early");
        assert!(result.is_err());
    }

    #[test]
    fn recv_app_data_when_empty_returns_would_block() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        let mut buf = [0u8; 64];
        let result = server.recv_app_data(&mut sio.as_io(), &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn fragmented_feed_data() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        for _ in 0..20 {
            let mut buf = [0u8; 32768];
            while let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf) {
                let copy = data.to_vec();
                for byte in &copy {
                    server
                        .feed_data(&mut sio.as_io(), core::slice::from_ref(byte))
                        .unwrap();
                }
            }
            let mut buf2 = [0u8; 32768];
            while let Some(data) = server.poll_output(&mut sio.as_io(), &mut buf2) {
                let copy = data.to_vec();
                for byte in &copy {
                    client
                        .feed_data(&mut cio.as_io(), core::slice::from_ref(byte))
                        .unwrap();
                }
            }
            if client.is_active() && server.is_active() {
                break;
            }
        }

        assert!(
            client.is_active(),
            "handshake should complete with fragmented data"
        );
        assert!(server.is_active());

        drain_events(&mut client);
        drain_events(&mut server);

        client
            .send_app_data(&mut cio.as_io(), b"fragmented test")
            .unwrap();
        let mut buf = [0u8; 32768];
        while let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf) {
            let copy = data.to_vec();
            for byte in &copy {
                server
                    .feed_data(&mut sio.as_io(), core::slice::from_ref(byte))
                    .unwrap();
            }
        }

        let events = drain_events(&mut server);
        assert!(events.contains(&TlsEvent::AppData));

        let mut recv = [0u8; 64];
        let n = server.recv_app_data(&mut sio.as_io(), &mut recv).unwrap();
        assert_eq!(&recv[..n], b"fragmented test");
    }

    #[test]
    fn server_initiated_close() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        server.close(&mut sio.as_io()).unwrap();
        assert!(server.is_closed());

        transfer(&mut server, &mut sio, &mut client, &mut cio);

        let client_events = drain_events(&mut client);
        assert!(
            client_events.contains(&TlsEvent::PeerClosed),
            "client should see PeerClosed, got: {:?}",
            client_events,
        );
    }

    #[test]
    fn large_payload_near_record_limit() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        let big_data = [0x42u8; 16000];
        client.send_app_data(&mut cio.as_io(), &big_data).unwrap();
        transfer(&mut client, &mut cio, &mut server, &mut sio);

        let events = drain_events(&mut server);
        assert!(events.contains(&TlsEvent::AppData));

        let mut recv = [0u8; 16384];
        let n = server.recv_app_data(&mut sio.as_io(), &mut recv).unwrap();
        assert_eq!(n, 16000);
        assert!(recv[..n].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn data_after_close_ignored() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        client.close(&mut cio.as_io()).unwrap();
        transfer(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut server);

        assert!(client.is_closed());
        client.close(&mut cio.as_io()).unwrap();
    }

    #[test]
    fn tls_client_wrapper_handshake() {
        use super::super::client::TlsClient;
        use super::super::server::TlsServer;

        let cert: &'static [u8] = test_cert_der().leak();

        let client_config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        let server_config = ServerTlsConfig {
            cert_der: cert,
            private_key_der: &TEST_SEED,
            alpn_protocols: &[b"h2"],
            transport_params: TransportParams::default_params(),
        };

        let mut client: TlsClient<Aes128GcmProvider, 32768> =
            TlsClient::new(Aes128GcmProvider, client_config, [0xAA; 32], [0xBB; 32]);
        let mut server: TlsServer<Aes128GcmProvider, 32768> =
            TlsServer::new(Aes128GcmProvider, server_config, [0xCC; 32], [0xDD; 32]);

        for _ in 0..20 {
            let mut any = false;
            let mut buf = [0u8; 32768];
            while let Some(data) = client.poll_output(&mut buf) {
                let copy = data.to_vec();
                server.feed_data(&copy).unwrap();
                any = true;
            }
            let mut buf2 = [0u8; 32768];
            while let Some(data) = server.poll_output(&mut buf2) {
                let copy = data.to_vec();
                client.feed_data(&copy).unwrap();
                any = true;
            }
            if !any {
                break;
            }
        }

        assert!(client.is_active());
        assert!(server.is_active());
        assert_eq!(client.alpn(), Some(b"h2".as_slice()));

        client.send_app_data(b"wrapper test").unwrap();
        let mut buf = [0u8; 32768];
        while let Some(data) = client.poll_output(&mut buf) {
            let copy = data.to_vec();
            server.feed_data(&copy).unwrap();
        }

        let mut recv = [0u8; 64];
        let n = server.recv_app_data(&mut recv).unwrap();
        assert_eq!(&recv[..n], b"wrapper test");
    }

    #[test]
    fn find_inner_content_type_basic() {
        let data = [0x41, 0x42, 0x43, ContentType::ApplicationData as u8];
        let (len, ct) = find_inner_content_type(&data).unwrap();
        assert_eq!(len, 3);
        assert_eq!(ct, ContentType::ApplicationData);
    }

    #[test]
    fn find_inner_content_type_with_padding() {
        let data = [0x41, ContentType::Handshake as u8, 0x00, 0x00];
        let (len, ct) = find_inner_content_type(&data).unwrap();
        assert_eq!(len, 1);
        assert_eq!(ct, ContentType::Handshake);
    }

    #[test]
    fn find_inner_content_type_empty() {
        let data = [0u8; 4];
        assert!(find_inner_content_type(&data).is_err());
    }

    #[test]
    fn malformed_record_invalid_content_type() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let _server = make_server(cert);

        let mut buf = [0u8; 32768];
        while let Some(_) = client.poll_output(&mut cio.as_io(), &mut buf) {}

        let result = client.feed_data(&mut cio.as_io(), &[0xFF, 0x03, 0x03, 0x00, 0x01, 0x00]);
        assert_eq!(result, Err(Error::Tls));
    }

    #[test]
    fn malformed_record_truncated_header() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let _server = make_server(cert);

        let mut buf = [0u8; 32768];
        while let Some(_) = client.poll_output(&mut cio.as_io(), &mut buf) {}

        let result = client.feed_data(&mut cio.as_io(), &[0x16, 0x03, 0x03]);
        assert!(result.is_ok(), "partial header should be buffered");

        let result = client.feed_data(&mut cio.as_io(), &[0x00, 0x01, 0x00]);
        assert!(result.is_err(), "malformed handshake record should error");
    }

    #[test]
    fn send_after_close_fails() {
        let cert: &'static [u8] = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        client.close(&mut cio.as_io()).unwrap();

        let result = client.send_app_data(&mut cio.as_io(), b"hello");
        assert_eq!(result, Err(Error::InvalidState));
    }

    /// RFC 8449: a client with small buffers advertises a record_size_limit
    /// in its ClientHello, and the server must cap every application-data
    /// record it sends to that limit.
    #[test]
    fn server_caps_app_records_to_client_record_size_limit() {
        const CLIENT_BUF: usize = 2048;
        // What `local_record_size_limit::<CLIENT_BUF>()` advertises.
        let limit = CLIENT_BUF - 64;

        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TlsIoBufs::<CLIENT_BUF>::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        assert!(client.is_active());
        assert!(server.is_active());
        drain_events(&mut client);
        drain_events(&mut server);

        // Server sends more data than fits in one capped record.
        let payload: Vec<u8> = (0..8000u32).map(|i| (i % 251) as u8).collect();
        server.send_app_data(&mut sio.as_io(), &payload).unwrap();

        let mut raw = Vec::new();
        let mut buf = [0u8; 32768];
        while let Some(data) = server.poll_output(&mut sio.as_io(), &mut buf) {
            raw.extend_from_slice(data);
        }

        // Walk the raw record stream: every record payload must respect the
        // limit (plaintext <= limit - 1, so ciphertext <= limit + 16).
        let mut off = 0;
        let mut records = 0;
        let mut received = Vec::new();
        while off + RECORD_HEADER_LEN <= raw.len() {
            let rec_len = u16::from_be_bytes([raw[off + 3], raw[off + 4]]) as usize;
            let total = RECORD_HEADER_LEN + rec_len;
            assert!(
                rec_len <= limit + 16,
                "record payload {} exceeds peer limit {} (+16 AEAD tag)",
                rec_len,
                limit
            );
            // Feed one record at a time so the client's small buffers keep up.
            client
                .feed_data(&mut cio.as_io(), &raw[off..off + total])
                .unwrap();
            let mut rbuf = [0u8; CLIENT_BUF];
            while let Ok(n) = client.recv_app_data(&mut cio.as_io(), &mut rbuf) {
                received.extend_from_slice(&rbuf[..n]);
            }
            records += 1;
            off += total;
        }
        assert_eq!(off, raw.len(), "trailing partial record in stream");
        assert!(
            records >= 5,
            "8000 bytes under a {} limit should span >= 5 records, got {}",
            limit,
            records
        );
        assert_eq!(received, payload);
    }

    /// RFC 8449: the limit also applies to records protected with handshake
    /// keys, so the server must fragment its EE+Cert+CV+Finished flight when
    /// the client's limit is smaller than the flight (~360 bytes with the
    /// test Ed25519 cert). Without fragmentation this handshake cannot
    /// complete — the single flight record would exceed the client's entire
    /// receive buffer. (The limit here is still large enough that record
    /// boundaries fall on message boundaries, which our minimal client
    /// requires; real peers also reassemble messages split across records.)
    #[test]
    fn server_fragments_handshake_flight_to_client_record_size_limit() {
        const CLIENT_BUF: usize = 320;
        let limit = CLIENT_BUF - 64; // 256

        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TlsIoBufs::<CLIENT_BUF>::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        // Drive the handshake while checking every server record against the
        // client's limit. Feed in small slices so the client's tiny recv_buf
        // never has to hold more than one (partial) record at a time.
        for _ in 0..40 {
            let mut any = false;

            let mut buf = [0u8; 32768];
            while let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf) {
                let copy = data.to_vec();
                server.feed_data(&mut sio.as_io(), &copy).unwrap();
                any = true;
            }

            let mut buf2 = [0u8; 32768];
            let mut server_out = Vec::new();
            while let Some(data) = server.poll_output(&mut sio.as_io(), &mut buf2) {
                server_out.extend_from_slice(data);
                any = true;
            }
            // Verify record sizes on the server's encrypted records
            // (ApplicationData outer type, 0x17).
            let mut off = 0;
            while off + RECORD_HEADER_LEN <= server_out.len() {
                let ct = server_out[off];
                let rec_len =
                    u16::from_be_bytes([server_out[off + 3], server_out[off + 4]]) as usize;
                if ct == ContentType::ApplicationData as u8 {
                    assert!(
                        rec_len <= limit + 16,
                        "protected record payload {} exceeds client limit {}",
                        rec_len,
                        limit
                    );
                }
                off += RECORD_HEADER_LEN + rec_len;
            }
            for slice in server_out.chunks(16) {
                client.feed_data(&mut cio.as_io(), slice).unwrap();
            }

            if !any && client.is_active() && server.is_active() {
                break;
            }
        }

        assert!(client.is_active(), "handshake should complete");
        assert!(server.is_active());

        // App data still round-trips both ways under the small limit.
        drain_events(&mut client);
        drain_events(&mut server);
        client
            .send_app_data(&mut cio.as_io(), b"small-limit ping")
            .unwrap();
        transfer(&mut client, &mut cio, &mut server, &mut sio);
        let mut rbuf = [0u8; 64];
        let n = server.recv_app_data(&mut sio.as_io(), &mut rbuf).unwrap();
        assert_eq!(&rbuf[..n], b"small-limit ping");
    }

    /// In-place decryption parks a partial trailing record as a hidden
    /// ciphertext tail behind the readable plaintext. Draining part of the
    /// plaintext while the partial record is parked, then delivering the rest
    /// of the record, must yield both messages intact.
    #[test]
    fn partial_record_parks_ciphertext_across_feeds_and_drains() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        let mut buf = [0u8; 32768];
        server
            .send_app_data(&mut sio.as_io(), b"first message")
            .unwrap();
        let mut wire1 = Vec::new();
        while let Some(d) = server.poll_output(&mut sio.as_io(), &mut buf) {
            wire1.extend_from_slice(d);
        }
        server
            .send_app_data(&mut sio.as_io(), b"second message")
            .unwrap();
        let mut wire2 = Vec::new();
        while let Some(d) = server.poll_output(&mut sio.as_io(), &mut buf) {
            wire2.extend_from_slice(d);
        }

        // Deliver message 1's record plus only half of message 2's record.
        let split = wire2.len() / 2;
        let mut feed = wire1.clone();
        feed.extend_from_slice(&wire2[..split]);
        client.feed_data(&mut cio.as_io(), &feed).unwrap();

        // Drain part of the plaintext while the partial record is parked
        // behind it (exercises truncate-relocating-the-hidden-tail).
        let mut r5 = [0u8; 5];
        let n = client.recv_app_data(&mut cio.as_io(), &mut r5).unwrap();
        assert_eq!(&r5[..n], b"first");

        // Deliver the rest of message 2's record; everything must come out.
        client.feed_data(&mut cio.as_io(), &wire2[split..]).unwrap();
        let mut out = Vec::new();
        let mut rb = [0u8; 64];
        while let Ok(n) = client.recv_app_data(&mut cio.as_io(), &mut rb) {
            out.extend_from_slice(&rb[..n]);
        }
        assert_eq!(out, b" messagesecond message");
    }

    /// A close_notify alert arriving in the same TCP segment as application
    /// data takes the early-return path out of record processing. The already
    /// decrypted plaintext must remain readable afterwards.
    #[test]
    fn app_data_readable_after_close_notify_in_same_feed() {
        let cert = test_cert_der().leak();
        let mut client = make_client();
        let mut cio = TestIo::new();
        let mut server = make_server(cert);
        let mut sio = TestIo::new();

        handshake(&mut client, &mut cio, &mut server, &mut sio);
        drain_events(&mut client);
        drain_events(&mut server);

        let mut buf = [0u8; 32768];
        let mut wire = Vec::new();
        server
            .send_app_data(&mut sio.as_io(), b"parting words")
            .unwrap();
        while let Some(d) = server.poll_output(&mut sio.as_io(), &mut buf) {
            wire.extend_from_slice(d);
        }
        server.close(&mut sio.as_io()).unwrap();
        while let Some(d) = server.poll_output(&mut sio.as_io(), &mut buf) {
            wire.extend_from_slice(d);
        }

        client.feed_data(&mut cio.as_io(), &wire).unwrap();
        let events = drain_events(&mut client);
        assert!(events.contains(&TlsEvent::AppData), "got: {:?}", events);
        assert!(events.contains(&TlsEvent::PeerClosed), "got: {:?}", events);

        let mut rb = [0u8; 64];
        let n = client.recv_app_data(&mut cio.as_io(), &mut rb).unwrap();
        assert_eq!(&rb[..n], b"parting words");
    }
}
