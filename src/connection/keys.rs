//! Connection-level key management.
//!
//! Tracks send/recv `DirectionalKeys` for each encryption level
//! (Initial, Handshake, Application) and provides helpers to derive
//! Initial keys from a DCID and install keys from TLS-derived secrets.
//!
//! Per RFC 9001 section 5.2, Initial packets always use AES-128-GCM
//! regardless of the negotiated cipher suite. The initial key fields
//! therefore use concrete AES types instead of the generic `CryptoProvider`.

use crate::crypto::{Aead, CryptoProvider, DirectionalKeys, HeaderProtection, Level};
use crate::error::Error;
use crate::tls::DerivedKeys;
use zeroize::Zeroize;

#[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
use crate::crypto::rustcrypto::{Aes128GcmAead, AesHeaderProtection};

// ---------------------------------------------------------------------------
// OptKeys — stack or heap-boxed optional directional keys
// ---------------------------------------------------------------------------

/// Optional directional keys — stack-based without alloc, heap-boxed with alloc.
///
/// When the `alloc` feature is enabled, each `Some` variant wraps its keys in a
/// `Box`, so that `None` costs only 8 bytes (pointer-width) instead of the full
/// `size_of::<DirectionalKeys>()`. After the handshake, four of the seven key
/// slots in `ConnectionKeys` are `None`, saving ~1.5 KB per connection.
pub(crate) struct OptKeys<A: Aead, H: HeaderProtection>(
    #[cfg(not(feature = "alloc"))] Option<DirectionalKeys<A, H>>,
    #[cfg(feature = "alloc")] Option<alloc::boxed::Box<DirectionalKeys<A, H>>>,
);

impl<A: Aead, H: HeaderProtection> OptKeys<A, H> {
    pub fn none() -> Self {
        Self(None)
    }

    pub fn some(keys: DirectionalKeys<A, H>) -> Self {
        #[cfg(not(feature = "alloc"))]
        {
            Self(Some(keys))
        }
        #[cfg(feature = "alloc")]
        {
            Self(Some(alloc::boxed::Box::new(keys)))
        }
    }

    pub fn as_ref(&self) -> Option<&DirectionalKeys<A, H>> {
        #[cfg(not(feature = "alloc"))]
        {
            self.0.as_ref()
        }
        #[cfg(feature = "alloc")]
        {
            self.0.as_deref()
        }
    }

    pub fn take(&mut self) -> OptKeys<A, H> {
        OptKeys(self.0.take())
    }

    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    #[allow(dead_code)] // used in tests
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn clear(&mut self) {
        self.0 = None;
    }
}

/// State for QUIC Key Update (RFC 9001 section 6).
///
/// Tracks traffic secrets so we can derive next-generation keys, and holds
/// the previous read key for decrypting packets from the old key phase
/// during a transition period.
///
/// Per RFC 9001 section 6, header protection keys do NOT change during
/// key updates. Only the AEAD key and IV are rotated. We store the
/// original HP key material so we can reconstruct the HP objects for
/// new `DirectionalKeys` instances.
/// Conservative AEAD confidentiality limit: 2^23 packets for AES-128-GCM
/// (RFC 9001 §6.6). Safe for all QUIC cipher suites — ChaCha20-Poly1305
/// has no practical confidentiality limit but uses this for uniformity.
pub const AEAD_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

pub struct KeyUpdateState<C: CryptoProvider> {
    /// Current key phase bit (0 or 1). Flips on each key update.
    pub key_phase: u8,
    /// Current send traffic secret (needed to derive next generation).
    pub send_secret: [u8; 48],
    /// Current recv traffic secret (needed to derive next generation).
    pub recv_secret: [u8; 48],
    /// Length of the traffic secrets (32 for SHA-256, 48 for SHA-384).
    pub secret_len: usize,
    /// Original send HP key bytes (never changes after initial installation).
    pub send_hp_key: [u8; 32],
    /// Original recv HP key bytes (never changes after initial installation).
    pub recv_hp_key: [u8; 32],
    /// Length of HP key (16 for AES, 32 for ChaCha20).
    pub hp_key_len: usize,
    /// Previous-generation read AEAD key, for decrypting packets still
    /// encrypted with the old key phase during a transition.
    pub(crate) prev_recv_key: OptKeys<C::Aead, C::HeaderProtection>,
    /// Whether we have received a packet with the new key phase from the peer
    /// (i.e., the current key update is confirmed). A new key update MUST NOT
    /// be initiated until this is true.
    pub update_confirmed: bool,
    /// Number of packets encrypted with the current send key (RFC 9001 §6.6).
    pub packets_encrypted: u64,
    /// Number of packets decrypted with the current recv key (RFC 9001 §6.6).
    pub packets_decrypted: u64,
}

impl<C: CryptoProvider> Drop for KeyUpdateState<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.send_secret.zeroize();
        self.recv_secret.zeroize();
        self.send_hp_key.zeroize();
        self.recv_hp_key.zeroize();
    }
}

impl<C: CryptoProvider> Default for KeyUpdateState<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: CryptoProvider> KeyUpdateState<C> {
    /// Create a new key update state (not yet initialized).
    pub fn new() -> Self {
        Self {
            key_phase: 0,
            send_secret: [0u8; 48],
            recv_secret: [0u8; 48],
            secret_len: 0,
            send_hp_key: [0u8; 32],
            recv_hp_key: [0u8; 32],
            hp_key_len: 0,
            prev_recv_key: OptKeys::none(),
            update_confirmed: true, // No pending update initially
            packets_encrypted: 0,
            packets_decrypted: 0,
        }
    }
}

/// All keys for a QUIC connection, separated by level and direction.
pub struct ConnectionKeys<C: CryptoProvider> {
    // Initial keys always use AES-128-GCM per RFC 9001 section 5.2,
    // regardless of the negotiated cipher suite (C).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub(crate) initial_send: OptKeys<Aes128GcmAead, AesHeaderProtection>,
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub(crate) initial_recv: OptKeys<Aes128GcmAead, AesHeaderProtection>,
    // Without crypto features, we still need the fields for the struct definition.
    #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
    _initial_marker: core::marker::PhantomData<C>,
    // Handshake and Application keys use the negotiated cipher suite.
    pub(crate) handshake_send: OptKeys<C::Aead, C::HeaderProtection>,
    pub(crate) handshake_recv: OptKeys<C::Aead, C::HeaderProtection>,
    pub(crate) app_send: OptKeys<C::Aead, C::HeaderProtection>,
    pub(crate) app_recv: OptKeys<C::Aead, C::HeaderProtection>,
    /// Key update state for 1-RTT keys (RFC 9001 section 6).
    pub key_update: KeyUpdateState<C>,
}

impl<C: CryptoProvider> Default for ConnectionKeys<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: CryptoProvider> ConnectionKeys<C> {
    /// Create an empty key set (no keys installed yet).
    pub fn new() -> Self {
        Self {
            #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
            initial_send: OptKeys::none(),
            #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
            initial_recv: OptKeys::none(),
            #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
            _initial_marker: core::marker::PhantomData,
            handshake_send: OptKeys::none(),
            handshake_recv: OptKeys::none(),
            app_send: OptKeys::none(),
            app_recv: OptKeys::none(),
            key_update: KeyUpdateState::new(),
        }
    }

    /// Derive and install Initial keys from a Destination Connection ID.
    ///
    /// Per RFC 9001 section 5.2, Initial keys always use AES-128-GCM with
    /// AES header protection, regardless of the negotiated cipher suite.
    ///
    /// For a client: send = client keys, recv = server keys.
    /// For a server: send = server keys, recv = client keys.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn derive_initial(
        &mut self,
        _provider: &C,
        dcid: &[u8],
        is_client: bool,
    ) -> Result<(), Error> {
        // Always use AES-128-GCM for Initial keys per RFC 9001.
        let aes_provider = crate::crypto::rustcrypto::Aes128GcmProvider;
        let hkdf = aes_provider.hkdf();
        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        crate::crypto::key_schedule::derive_initial_secrets(
            &hkdf,
            dcid,
            &mut client_secret,
            &mut server_secret,
        )?;

        let client_keys = crate::crypto::key_schedule::derive_directional_keys(
            &aes_provider,
            &hkdf,
            &client_secret,
        )?;
        let server_keys = crate::crypto::key_schedule::derive_directional_keys(
            &aes_provider,
            &hkdf,
            &server_secret,
        )?;
        client_secret.zeroize();
        server_secret.zeroize();

        if is_client {
            self.initial_send = OptKeys::some(client_keys);
            self.initial_recv = OptKeys::some(server_keys);
        } else {
            self.initial_send = OptKeys::some(server_keys);
            self.initial_recv = OptKeys::some(client_keys);
        }
        Ok(())
    }

    /// Install keys derived from TLS (handshake or application level).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn install_derived(&mut self, provider: &C, derived: &DerivedKeys) -> Result<(), Error> {
        let hkdf = provider.hkdf();
        let send_keys = crate::crypto::key_schedule::derive_directional_keys(
            provider,
            &hkdf,
            &derived.send_secret[..derived.secret_len],
        )?;
        let recv_keys = crate::crypto::key_schedule::derive_directional_keys(
            provider,
            &hkdf,
            &derived.recv_secret[..derived.secret_len],
        )?;

        match derived.level {
            Level::Handshake => {
                self.handshake_send = OptKeys::some(send_keys);
                self.handshake_recv = OptKeys::some(recv_keys);
            }
            Level::Application => {
                self.app_send = OptKeys::some(send_keys);
                self.app_recv = OptKeys::some(recv_keys);
                // Save traffic secrets for key update derivation (RFC 9001 section 6)
                self.key_update.send_secret[..derived.secret_len]
                    .copy_from_slice(&derived.send_secret[..derived.secret_len]);
                self.key_update.recv_secret[..derived.secret_len]
                    .copy_from_slice(&derived.recv_secret[..derived.secret_len]);
                self.key_update.secret_len = derived.secret_len;
                self.key_update.key_phase = 0;
                self.key_update.update_confirmed = true;

                // Save the initial HP key bytes. Per RFC 9001 section 6, header
                // protection keys do NOT change during key updates.
                let hp_key_len = core::cmp::max(C::Aead::KEY_LEN, 16);
                let mut send_hp = [0u8; 32];
                let mut recv_hp = [0u8; 32];
                crate::crypto::key_schedule::hkdf_expand_label(
                    &hkdf,
                    &derived.send_secret[..derived.secret_len],
                    b"quic hp",
                    &[],
                    &mut send_hp[..hp_key_len],
                )?;
                crate::crypto::key_schedule::hkdf_expand_label(
                    &hkdf,
                    &derived.recv_secret[..derived.secret_len],
                    b"quic hp",
                    &[],
                    &mut recv_hp[..hp_key_len],
                )?;
                self.key_update.send_hp_key = send_hp;
                self.key_update.recv_hp_key = recv_hp;
                self.key_update.hp_key_len = hp_key_len;
            }
            Level::Initial => {
                // Initial keys are derived via derive_initial() with AES-128-GCM.
                // This path should not be reached; ignore gracefully.
            }
        }
        Ok(())
    }

    /// Get the send-direction initial keys (AES-128-GCM per RFC 9001).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn initial_send_keys(
        &self,
    ) -> Option<&DirectionalKeys<Aes128GcmAead, AesHeaderProtection>> {
        self.initial_send.as_ref()
    }

    /// Get the recv-direction initial keys (AES-128-GCM per RFC 9001).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn initial_recv_keys(
        &self,
    ) -> Option<&DirectionalKeys<Aes128GcmAead, AesHeaderProtection>> {
        self.initial_recv.as_ref()
    }

    /// Get the send-direction keys for a given level (Handshake or Application).
    ///
    /// For Initial keys, use [`initial_send_keys`](Self::initial_send_keys)
    /// instead, since Initial keys use concrete AES types.
    pub fn send_keys(
        &self,
        level: Level,
    ) -> Option<&DirectionalKeys<C::Aead, C::HeaderProtection>> {
        match level {
            Level::Initial => None,
            Level::Handshake => self.handshake_send.as_ref(),
            Level::Application => self.app_send.as_ref(),
        }
    }

    /// Get the recv-direction keys for a given level (Handshake or Application).
    ///
    /// For Initial keys, use [`initial_recv_keys`](Self::initial_recv_keys)
    /// instead, since Initial keys use concrete AES types.
    pub fn recv_keys(
        &self,
        level: Level,
    ) -> Option<&DirectionalKeys<C::Aead, C::HeaderProtection>> {
        match level {
            Level::Initial => None,
            Level::Handshake => self.handshake_recv.as_ref(),
            Level::Application => self.app_recv.as_ref(),
        }
    }

    /// Drop Initial keys (after handshake keys are installed).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn drop_initial(&mut self) {
        self.initial_send.clear();
        self.initial_recv.clear();
    }

    #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
    pub fn drop_initial(&mut self) {
        // No initial key fields without crypto features.
    }

    /// Drop Handshake keys (after handshake is confirmed).
    pub fn drop_handshake(&mut self) {
        self.handshake_send.clear();
        self.handshake_recv.clear();
    }

    /// Check if we have send keys at a given level.
    pub fn has_send_keys(&self, level: Level) -> bool {
        match level {
            #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
            Level::Initial => self.initial_send.is_some(),
            #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
            Level::Initial => false,
            _ => self.send_keys(level).is_some(),
        }
    }

    /// Check if we have recv keys at a given level.
    pub fn has_recv_keys(&self, level: Level) -> bool {
        match level {
            #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
            Level::Initial => self.initial_recv.is_some(),
            #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
            Level::Initial => false,
            _ => self.recv_keys(level).is_some(),
        }
    }

    /// Get the current key phase bit (0 or 1) for 1-RTT packets.
    pub fn key_phase(&self) -> u8 {
        self.key_update.key_phase
    }

    /// Check if a key update can be initiated.
    ///
    /// A key update MUST NOT be initiated before the previous one is confirmed
    /// (i.e., we have received a packet with the new key phase from the peer).
    /// Also requires that application keys are installed.
    pub fn can_initiate_key_update(&self) -> bool {
        self.app_send.is_some()
            && self.app_recv.is_some()
            && self.key_update.update_confirmed
            && self.key_update.secret_len > 0
    }

    /// Returns true if the AEAD confidentiality limit is approaching and
    /// a key update should be initiated (RFC 9001 §6.6).
    pub fn needs_key_update(&self) -> bool {
        self.can_initiate_key_update()
            && (self.key_update.packets_encrypted >= AEAD_CONFIDENTIALITY_LIMIT
                || self.key_update.packets_decrypted >= AEAD_CONFIDENTIALITY_LIMIT)
    }

    /// Derive a `DirectionalKeys` for key update, keeping the original HP key.
    ///
    /// Per RFC 9001 section 6, header protection keys do NOT change during key
    /// updates. This derives only the AEAD key and IV from the new secret, then
    /// reconstructs the HP object from the stored original HP key bytes.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn derive_key_update_keys(
        &self,
        provider: &C,
        secret: &[u8],
        hp_key: &[u8],
    ) -> Result<DirectionalKeys<C::Aead, C::HeaderProtection>, Error> {
        let hkdf = provider.hkdf();

        let mut key_buf = [0u8; 32];
        let mut iv = [0u8; 12];
        let key_len = C::Aead::KEY_LEN;

        crate::crypto::key_schedule::hkdf_expand_label(
            &hkdf,
            secret,
            b"quic key",
            &[],
            &mut key_buf[..key_len],
        )?;
        crate::crypto::key_schedule::hkdf_expand_label(&hkdf, secret, b"quic iv", &[], &mut iv)?;

        let aead = provider.aead(&key_buf[..key_len])?;
        // Re-create HP from the ORIGINAL HP key (unchanged across key updates)
        let header_protection = provider.header_protection(hp_key)?;

        Ok(DirectionalKeys {
            aead,
            header_protection,
            iv,
        })
    }

    /// Perform a key update: derive next-generation application keys.
    ///
    /// This rotates:
    ///   current recv -> prev_recv (for decrypting late packets from old phase)
    ///   new send/recv keys derived from updated traffic secrets
    ///   key_phase bit flipped
    ///
    /// Per RFC 9001 section 6.1:
    ///   new_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
    ///
    /// Per RFC 9001 section 6, header protection keys do NOT change.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn perform_key_update(&mut self, provider: &C) -> Result<(), Error> {
        if !self.can_initiate_key_update() {
            return Err(Error::Transport(
                crate::error::TransportError::KeyUpdateError,
            ));
        }

        let hkdf = provider.hkdf();
        let secret_len = self.key_update.secret_len;
        let hp_key_len = self.key_update.hp_key_len;

        // Derive next-generation send secret
        let mut new_send_secret = [0u8; 48];
        crate::crypto::key_schedule::derive_next_application_secret(
            &hkdf,
            &self.key_update.send_secret[..secret_len],
            &mut new_send_secret[..secret_len],
        )?;

        // Derive next-generation recv secret
        let mut new_recv_secret = [0u8; 48];
        crate::crypto::key_schedule::derive_next_application_secret(
            &hkdf,
            &self.key_update.recv_secret[..secret_len],
            &mut new_recv_secret[..secret_len],
        )?;

        // Derive new directional keys with ORIGINAL HP keys preserved
        let new_send_keys = self.derive_key_update_keys(
            provider,
            &new_send_secret[..secret_len],
            &self.key_update.send_hp_key[..hp_key_len],
        )?;
        let new_recv_keys = self.derive_key_update_keys(
            provider,
            &new_recv_secret[..secret_len],
            &self.key_update.recv_hp_key[..hp_key_len],
        )?;

        // Rotate: current recv -> prev_recv
        self.key_update.prev_recv_key = self.app_recv.take();

        // Install new keys
        self.app_send = OptKeys::some(new_send_keys);
        self.app_recv = OptKeys::some(new_recv_keys);

        // Update secrets
        self.key_update.send_secret[..secret_len].copy_from_slice(&new_send_secret[..secret_len]);
        self.key_update.recv_secret[..secret_len].copy_from_slice(&new_recv_secret[..secret_len]);

        // Flip key phase
        self.key_update.key_phase ^= 1;

        // Mark as not yet confirmed (waiting for peer acknowledgment)
        self.key_update.update_confirmed = false;

        // Reset AEAD usage counters for the new key generation
        self.key_update.packets_encrypted = 0;
        self.key_update.packets_decrypted = 0;

        Ok(())
    }

    /// Handle reception of a packet with a different key phase from the peer.
    ///
    /// This derives the next-generation recv key, attempts to decrypt with it,
    /// and if successful, rotates keys. The caller should use this when the
    /// key_phase bit in a received short header differs from `self.key_phase`.
    ///
    /// Returns the new recv directional keys for the caller to attempt decryption.
    /// If decryption succeeds, the caller must call `confirm_peer_key_update`.
    ///
    /// HP keys are preserved (RFC 9001 section 6: HP keys don't change).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn derive_next_recv_keys(
        &self,
        provider: &C,
    ) -> Result<DirectionalKeys<C::Aead, C::HeaderProtection>, Error> {
        let hkdf = provider.hkdf();
        let secret_len = self.key_update.secret_len;
        let hp_key_len = self.key_update.hp_key_len;
        if secret_len == 0 {
            return Err(Error::Crypto);
        }

        // Derive next recv secret
        let mut new_recv_secret = [0u8; 48];
        crate::crypto::key_schedule::derive_next_application_secret(
            &hkdf,
            &self.key_update.recv_secret[..secret_len],
            &mut new_recv_secret[..secret_len],
        )?;

        self.derive_key_update_keys(
            provider,
            &new_recv_secret[..secret_len],
            &self.key_update.recv_hp_key[..hp_key_len],
        )
    }

    /// Confirm a peer-initiated key update after successful decryption.
    ///
    /// This completes the key rotation: installs the new recv keys,
    /// derives and installs new send keys, flips the key phase, and
    /// moves the old recv key to prev_recv.
    ///
    /// HP keys are preserved (RFC 9001 section 6: HP keys don't change).
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    pub fn confirm_peer_key_update(
        &mut self,
        provider: &C,
        new_recv_keys: DirectionalKeys<C::Aead, C::HeaderProtection>,
    ) -> Result<(), Error> {
        let hkdf = provider.hkdf();
        let secret_len = self.key_update.secret_len;
        let hp_key_len = self.key_update.hp_key_len;

        // Derive updated send and recv secrets
        let mut new_send_secret = [0u8; 48];
        crate::crypto::key_schedule::derive_next_application_secret(
            &hkdf,
            &self.key_update.send_secret[..secret_len],
            &mut new_send_secret[..secret_len],
        )?;

        let mut new_recv_secret = [0u8; 48];
        crate::crypto::key_schedule::derive_next_application_secret(
            &hkdf,
            &self.key_update.recv_secret[..secret_len],
            &mut new_recv_secret[..secret_len],
        )?;

        // Derive new send keys with ORIGINAL HP key preserved
        let new_send_keys = self.derive_key_update_keys(
            provider,
            &new_send_secret[..secret_len],
            &self.key_update.send_hp_key[..hp_key_len],
        )?;

        // Rotate: current recv -> prev_recv
        self.key_update.prev_recv_key = self.app_recv.take();

        // Install new keys
        self.app_send = OptKeys::some(new_send_keys);
        self.app_recv = OptKeys::some(new_recv_keys);

        // Update secrets
        self.key_update.send_secret[..secret_len].copy_from_slice(&new_send_secret[..secret_len]);
        self.key_update.recv_secret[..secret_len].copy_from_slice(&new_recv_secret[..secret_len]);

        // Flip key phase
        self.key_update.key_phase ^= 1;

        // Peer-initiated key update is immediately confirmed
        self.key_update.update_confirmed = true;

        // Reset AEAD usage counters for the new key generation.
        // packets_decrypted starts at 1 because the packet that triggered
        // this key update was already successfully decrypted with the new key.
        self.key_update.packets_encrypted = 0;
        self.key_update.packets_decrypted = 1;

        Ok(())
    }

    /// Get the previous-generation recv keys, for decrypting late packets
    /// that were encrypted with the old key phase.
    pub fn prev_recv_keys(&self) -> Option<&DirectionalKeys<C::Aead, C::HeaderProtection>> {
        self.key_update.prev_recv_key.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_initial_client_keys() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        keys.derive_initial(&provider, &dcid, true).unwrap();

        assert!(keys.initial_send.is_some());
        assert!(keys.initial_recv.is_some());
        assert!(keys.handshake_send.is_none());
        assert!(keys.app_send.is_none());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn derive_initial_server_keys_swapped() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let dcid = [0x01, 0x02, 0x03, 0x04];

        let mut client_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        client_keys.derive_initial(&provider, &dcid, true).unwrap();

        let mut server_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        server_keys.derive_initial(&provider, &dcid, false).unwrap();

        // Client send IV should equal server recv IV, and vice versa
        assert_eq!(
            client_keys.initial_send.as_ref().unwrap().iv,
            server_keys.initial_recv.as_ref().unwrap().iv
        );
        assert_eq!(
            client_keys.initial_recv.as_ref().unwrap().iv,
            server_keys.initial_send.as_ref().unwrap().iv
        );
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn install_handshake_keys() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();

        // Create fake derived keys
        let mut send_secret = [0u8; 48];
        send_secret[..32].copy_from_slice(&[0xAA; 32]);
        let mut recv_secret = [0u8; 48];
        recv_secret[..32].copy_from_slice(&[0xBB; 32]);

        let derived = DerivedKeys {
            level: Level::Handshake,
            send_secret,
            recv_secret,
            secret_len: 32,
        };

        keys.install_derived(&provider, &derived).unwrap();
        assert!(keys.handshake_send.is_some());
        assert!(keys.handshake_recv.is_some());
        assert!(keys.app_send.is_none());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn drop_initial_clears_keys() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();
        keys.derive_initial(&provider, &[1, 2, 3, 4], true).unwrap();

        assert!(keys.has_send_keys(Level::Initial));
        assert!(keys.has_recv_keys(Level::Initial));

        keys.drop_initial();
        assert!(!keys.has_send_keys(Level::Initial));
        assert!(!keys.has_recv_keys(Level::Initial));
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn send_recv_keys_by_level() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();
        keys.derive_initial(&provider, &[1, 2, 3, 4], true).unwrap();

        // Initial keys use dedicated accessors (concrete AES type)
        assert!(keys.initial_send_keys().is_some());
        assert!(keys.initial_recv_keys().is_some());
        // has_send_keys/has_recv_keys still works for Initial
        assert!(keys.has_send_keys(Level::Initial));
        assert!(keys.has_recv_keys(Level::Initial));
        assert!(keys.send_keys(Level::Handshake).is_none());
        assert!(keys.recv_keys(Level::Handshake).is_none());
        assert!(keys.send_keys(Level::Application).is_none());
        assert!(keys.recv_keys(Level::Application).is_none());
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn encrypt_decrypt_with_initial_keys() {
        use crate::crypto::Aead as _;
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let provider = Aes128GcmProvider;
        let dcid = [0x01, 0x02, 0x03, 0x04];

        let mut client_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        client_keys.derive_initial(&provider, &dcid, true).unwrap();

        let mut server_keys = ConnectionKeys::<Aes128GcmProvider>::new();
        server_keys.derive_initial(&provider, &dcid, false).unwrap();

        // Client encrypts, server decrypts
        let plaintext = b"hello server";
        let aad = b"packet header";
        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let send = client_keys.initial_send_keys().unwrap();
        let nonce = send.nonce(0);
        let ct_len = send
            .aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();

        let recv = server_keys.initial_recv_keys().unwrap();
        let nonce = recv.nonce(0);
        let pt_len = recv
            .aead
            .open_in_place(&nonce, aad, &mut buf, ct_len)
            .unwrap();
        assert_eq!(&buf[..pt_len], plaintext);
    }

    // =====================================================================
    // Key Update tests (RFC 9001 section 6)
    // =====================================================================

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    mod key_update_tests {
        use super::*;
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        /// Helper: install fake application keys with known secrets.
        fn make_keys_with_app(
            send_secret: &[u8; 32],
            recv_secret: &[u8; 32],
        ) -> ConnectionKeys<Aes128GcmProvider> {
            let provider = Aes128GcmProvider;
            let mut keys = ConnectionKeys::<Aes128GcmProvider>::new();

            let mut ss = [0u8; 48];
            ss[..32].copy_from_slice(send_secret);
            let mut rs = [0u8; 48];
            rs[..32].copy_from_slice(recv_secret);

            let derived = DerivedKeys {
                level: Level::Application,
                send_secret: ss,
                recv_secret: rs,
                secret_len: 32,
            };
            keys.install_derived(&provider, &derived).unwrap();
            keys
        }

        #[test]
        fn key_phase_starts_at_zero() {
            let keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);
            assert_eq!(keys.key_phase(), 0);
        }

        #[test]
        fn can_initiate_key_update_after_app_keys_installed() {
            let keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);
            assert!(keys.can_initiate_key_update());
        }

        #[test]
        fn cannot_initiate_without_app_keys() {
            let keys = ConnectionKeys::<Aes128GcmProvider>::new();
            assert!(!keys.can_initiate_key_update());
        }

        #[test]
        fn perform_key_update_flips_phase() {
            let provider = Aes128GcmProvider;
            let mut keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);
            assert_eq!(keys.key_phase(), 0);

            keys.perform_key_update(&provider).unwrap();
            assert_eq!(keys.key_phase(), 1);
        }

        #[test]
        fn perform_key_update_rotates_recv_to_prev() {
            let provider = Aes128GcmProvider;
            let mut keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);

            // Before key update: no prev recv key
            assert!(keys.prev_recv_keys().is_none());

            // Save the old recv IV for comparison
            let old_recv_iv = keys.app_recv.as_ref().unwrap().iv;

            keys.perform_key_update(&provider).unwrap();

            // After key update: prev recv key has the old IV
            let prev = keys.prev_recv_keys().unwrap();
            assert_eq!(prev.iv, old_recv_iv);

            // New recv key has a different IV
            let new_recv_iv = keys.app_recv.as_ref().unwrap().iv;
            assert_ne!(new_recv_iv, old_recv_iv);
        }

        #[test]
        fn second_key_update_blocked_until_confirmed() {
            let provider = Aes128GcmProvider;
            let mut keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);

            keys.perform_key_update(&provider).unwrap();
            assert!(!keys.key_update.update_confirmed);

            // Second update should fail
            let result = keys.perform_key_update(&provider);
            assert!(result.is_err());
        }

        #[test]
        fn second_key_update_succeeds_after_confirmed() {
            let provider = Aes128GcmProvider;
            let mut keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);

            keys.perform_key_update(&provider).unwrap();
            assert_eq!(keys.key_phase(), 1);

            // Simulate peer confirmation
            keys.key_update.update_confirmed = true;

            keys.perform_key_update(&provider).unwrap();
            assert_eq!(keys.key_phase(), 0); // Flipped back
        }

        #[test]
        fn key_update_produces_different_keys() {
            let provider = Aes128GcmProvider;
            let mut keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);

            let old_send_iv = keys.app_send.as_ref().unwrap().iv;
            let old_recv_iv = keys.app_recv.as_ref().unwrap().iv;

            keys.perform_key_update(&provider).unwrap();

            let new_send_iv = keys.app_send.as_ref().unwrap().iv;
            let new_recv_iv = keys.app_recv.as_ref().unwrap().iv;

            assert_ne!(old_send_iv, new_send_iv);
            assert_ne!(old_recv_iv, new_recv_iv);
        }

        #[test]
        fn key_update_encrypt_decrypt_roundtrip() {
            let provider = Aes128GcmProvider;

            // Client and server have complementary keys
            let send_secret = [0xAA; 32];
            let recv_secret = [0xBB; 32];

            // Client: send=AA, recv=BB
            let mut client_keys = make_keys_with_app(&send_secret, &recv_secret);
            // Server: send=BB, recv=AA (swapped)
            let mut server_keys = make_keys_with_app(&recv_secret, &send_secret);

            // Before key update: client encrypts, server decrypts
            let plaintext = b"hello before key update";
            let aad = b"header";
            let mut buf = [0u8; 128];
            buf[..plaintext.len()].copy_from_slice(plaintext);

            let send = client_keys.app_send.as_ref().unwrap();
            let nonce = send.nonce(0);
            let ct_len = send
                .aead
                .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
                .unwrap();

            let recv = server_keys.app_recv.as_ref().unwrap();
            let nonce = recv.nonce(0);
            let pt_len = recv
                .aead
                .open_in_place(&nonce, aad, &mut buf, ct_len)
                .unwrap();
            assert_eq!(&buf[..pt_len], plaintext);

            // Client initiates key update
            client_keys.perform_key_update(&provider).unwrap();
            // Server also performs matching key update (peer-initiated)
            server_keys.perform_key_update(&provider).unwrap();

            // After key update: client encrypts with new keys, server decrypts
            let plaintext2 = b"hello after key update";
            buf = [0u8; 128];
            buf[..plaintext2.len()].copy_from_slice(plaintext2);

            let send = client_keys.app_send.as_ref().unwrap();
            let nonce = send.nonce(1);
            let ct_len = send
                .aead
                .seal_in_place(&nonce, aad, &mut buf, plaintext2.len())
                .unwrap();

            let recv = server_keys.app_recv.as_ref().unwrap();
            let nonce = recv.nonce(1);
            let pt_len = recv
                .aead
                .open_in_place(&nonce, aad, &mut buf, ct_len)
                .unwrap();
            assert_eq!(&buf[..pt_len], plaintext2);
        }

        #[test]
        fn old_phase_packet_decrypts_with_prev_key() {
            let provider = Aes128GcmProvider;

            let send_secret = [0xCC; 32];
            let recv_secret = [0xDD; 32];

            let mut keys = make_keys_with_app(&send_secret, &recv_secret);

            // Encrypt a packet with the current (generation 0) recv key
            let plaintext = b"old phase packet";
            let aad = b"header";
            let mut buf = [0u8; 128];
            buf[..plaintext.len()].copy_from_slice(plaintext);

            // The "remote" side would use their send key which is our recv secret
            let recv = keys.app_recv.as_ref().unwrap();
            let nonce = recv.nonce(42);
            // Encrypt using what would be the sender's key (which matches our recv key)
            let ct_len = recv
                .aead
                .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
                .unwrap();

            // Now perform a key update
            keys.perform_key_update(&provider).unwrap();

            // The old key should now be in prev_recv
            let prev = keys.prev_recv_keys().unwrap();
            let nonce = prev.nonce(42);
            let pt_len = prev
                .aead
                .open_in_place(&nonce, aad, &mut buf, ct_len)
                .unwrap();
            assert_eq!(&buf[..pt_len], plaintext);
        }

        #[test]
        fn derive_next_recv_keys_matches_peer_send() {
            let provider = Aes128GcmProvider;

            let client_send = [0xEE; 32];
            let client_recv = [0xFF; 32];

            // Client has send=EE, recv=FF
            let client_keys = make_keys_with_app(&client_send, &client_recv);
            // Server has send=FF, recv=EE
            let mut server_keys = make_keys_with_app(&client_recv, &client_send);

            // Server performs key update (this updates server's send and recv)
            server_keys.perform_key_update(&provider).unwrap();

            // Client derives next recv keys (which should match server's new send keys)
            let next_recv = client_keys.derive_next_recv_keys(&provider).unwrap();

            // Test: server encrypts with new send key, client decrypts with derived next recv
            let plaintext = b"peer key update test";
            let aad = b"hdr";
            let mut buf = [0u8; 128];
            buf[..plaintext.len()].copy_from_slice(plaintext);

            let server_send = server_keys.app_send.as_ref().unwrap();
            let nonce = server_send.nonce(0);
            let ct_len = server_send
                .aead
                .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
                .unwrap();

            let nonce = next_recv.nonce(0);
            let pt_len = next_recv
                .aead
                .open_in_place(&nonce, aad, &mut buf, ct_len)
                .unwrap();
            assert_eq!(&buf[..pt_len], plaintext);
        }

        #[test]
        fn confirm_peer_key_update_rotates_correctly() {
            let provider = Aes128GcmProvider;

            let client_send = [0x11; 32];
            let client_recv = [0x22; 32];

            let mut client_keys = make_keys_with_app(&client_send, &client_recv);
            let mut server_keys = make_keys_with_app(&client_recv, &client_send);

            // Server initiates key update
            server_keys.perform_key_update(&provider).unwrap();
            assert_eq!(server_keys.key_phase(), 1);

            // Client detects the key phase change and derives next recv keys
            let next_recv = client_keys.derive_next_recv_keys(&provider).unwrap();
            // After successful decryption, client confirms the peer key update
            client_keys
                .confirm_peer_key_update(&provider, next_recv)
                .unwrap();

            // Client's key phase should now be 1 (matching server)
            assert_eq!(client_keys.key_phase(), 1);
            // Client update is immediately confirmed (peer-initiated)
            assert!(client_keys.key_update.update_confirmed);
            // Previous recv key should exist
            assert!(client_keys.prev_recv_keys().is_some());

            // Now both sides should be able to communicate with the new keys
            let plaintext = b"after peer key update";
            let aad = b"hdr";
            let mut buf = [0u8; 128];
            buf[..plaintext.len()].copy_from_slice(plaintext);

            let send = server_keys.app_send.as_ref().unwrap();
            let nonce = send.nonce(0);
            let ct_len = send
                .aead
                .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
                .unwrap();

            let recv = client_keys.app_recv.as_ref().unwrap();
            let nonce = recv.nonce(0);
            let pt_len = recv
                .aead
                .open_in_place(&nonce, aad, &mut buf, ct_len)
                .unwrap();
            assert_eq!(&buf[..pt_len], plaintext);
        }

        #[test]
        fn secrets_are_updated_after_key_update() {
            let provider = Aes128GcmProvider;
            let mut keys = make_keys_with_app(&[0xAA; 32], &[0xBB; 32]);

            let old_send_secret = keys.key_update.send_secret;
            let old_recv_secret = keys.key_update.recv_secret;

            keys.perform_key_update(&provider).unwrap();

            // Secrets must have changed
            assert_ne!(&keys.key_update.send_secret[..32], &old_send_secret[..32]);
            assert_ne!(&keys.key_update.recv_secret[..32], &old_recv_secret[..32]);
        }

        #[test]
        fn multiple_key_updates_chain_correctly() {
            let provider = Aes128GcmProvider;

            let client_send = [0xAA; 32];
            let client_recv = [0xBB; 32];

            let mut client_keys = make_keys_with_app(&client_send, &client_recv);
            let mut server_keys = make_keys_with_app(&client_recv, &client_send);

            // Perform 3 rounds of key updates
            for expected_phase in [1u8, 0, 1] {
                client_keys.perform_key_update(&provider).unwrap();
                server_keys.perform_key_update(&provider).unwrap();

                assert_eq!(client_keys.key_phase(), expected_phase);
                assert_eq!(server_keys.key_phase(), expected_phase);

                // Verify encryption/decryption still works each round
                let plaintext = b"round data";
                let aad = b"hdr";
                let mut buf = [0u8; 128];
                buf[..plaintext.len()].copy_from_slice(plaintext);

                let send = client_keys.app_send.as_ref().unwrap();
                let nonce = send.nonce(0);
                let ct_len = send
                    .aead
                    .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
                    .unwrap();

                let recv = server_keys.app_recv.as_ref().unwrap();
                let nonce = recv.nonce(0);
                let pt_len = recv
                    .aead
                    .open_in_place(&nonce, aad, &mut buf, ct_len)
                    .unwrap();
                assert_eq!(&buf[..pt_len], plaintext);

                // Simulate confirmation for next round
                client_keys.key_update.update_confirmed = true;
                server_keys.key_update.update_confirmed = true;
            }
        }
    }
}
