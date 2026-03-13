//! TLS 1.3 handshake state machine for QUIC.
//!
//! Client-side state machine:
//! ```text
//! Start -> WaitServerHello -> WaitEncryptedExtensions -> WaitCertificate ->
//! WaitCertificateVerify -> WaitFinished -> SendFinished -> Complete
//! ```
//!
//! Server-side state machine:
//! ```text
//! WaitClientHello -> SendServerFlight(Initial) -> SendServerFlight(Handshake) ->
//! WaitClientFinished -> Complete
//! ```

use crate::buf::{Buf, BufExt};
use crate::crypto::{Aead, CryptoProvider, Level};
use zeroize::Zeroize;
use crate::error::Error;
use crate::tls::extensions::{
    encode_client_hello_extensions, encode_encrypted_extensions_data,
    encode_server_hello_extensions, parse_client_hello_extensions,
    parse_encrypted_extensions_data, parse_server_hello_extensions,
};
use crate::tls::key_schedule_tls::{compute_finished_verify_data, TlsKeySchedule};
use crate::tls::messages::{
    self, CipherSuite, HandshakeType, encode_certificate, encode_certificate_verify,
    encode_client_hello, encode_encrypted_extensions, encode_finished, encode_server_hello,
    iter_cipher_suites, parse_certificate, parse_certificate_verify, parse_client_hello,
    parse_encrypted_extensions, parse_finished, parse_server_hello, read_handshake_header,
};
use crate::tls::transcript::TranscriptHash;
use crate::tls::transport_params::TransportParams;
use crate::tls::{DerivedKeys, TlsSession};

/// Client or server role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Handshake states for both client and server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    // --- Client states ---
    /// Initial state — ClientHello needs to be written.
    Start,
    /// ClientHello has been sent, waiting for ServerHello.
    WaitServerHello,
    /// ServerHello received, waiting for EncryptedExtensions.
    WaitEncryptedExtensions,
    /// Waiting for server Certificate.
    WaitCertificate,
    /// Waiting for CertificateVerify.
    WaitCertificateVerify,
    /// Waiting for server Finished.
    WaitFinished,
    /// Need to send client Finished.
    SendFinished,

    // --- Server states ---
    /// Server waiting for ClientHello.
    WaitClientHello,
    /// Server has built ServerHello (Initial level) — waiting to flush it.
    SendServerFlightInitial,
    /// Server has built EE+Cert+CV+Finished (Handshake level) — waiting to flush.
    SendServerFlightHandshake,
    /// Server waiting for client Finished.
    WaitClientFinished,

    // --- Shared ---
    /// Handshake is complete.
    Complete,
}

/// Configuration for creating a client-side TLS engine.
pub struct TlsConfig {
    /// Server name for SNI.
    pub server_name: heapless::String<64>,
    /// ALPN protocols to offer.
    pub alpn_protocols: &'static [&'static [u8]],
    /// Our QUIC transport parameters.
    pub transport_params: TransportParams,
    /// DER-encoded pinned server certificates for verification.
    /// If empty, certificate verification is skipped (insecure, for testing).
    pub pinned_certs: &'static [&'static [u8]],
}

/// Configuration for creating a server-side TLS engine.
#[derive(Clone)]
pub struct ServerTlsConfig {
    /// DER-encoded server certificate.
    ///
    /// The certificate may contain either an Ed25519 public key (OID 1.3.101.112)
    /// or a P-256/secp256r1 public key (OID 1.2.840.10045.3.1.7). The key type
    /// is auto-detected from the certificate.
    pub cert_der: &'static [u8],
    /// Private key bytes (32 bytes) for CertificateVerify signing.
    ///
    /// For Ed25519: the 32-byte seed.
    /// For ECDSA-P256: the 32-byte private scalar.
    pub private_key_der: &'static [u8],
    /// ALPN protocols the server supports.
    pub alpn_protocols: &'static [&'static [u8]],
    /// Our QUIC transport parameters.
    pub transport_params: TransportParams,
}

/// TLS 1.3 handshake engine for QUIC, generic over the crypto provider.
pub struct TlsEngine<C: CryptoProvider> {
    role: Role,
    state: HandshakeState,

    // X25519 keypair
    private_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,

    // Random bytes (ClientHello random for client, ServerHello random for server)
    client_random: [u8; 32],

    // Negotiated cipher suite
    cipher_suite: Option<CipherSuite>,

    // TLS key schedule
    key_schedule: TlsKeySchedule,
    client_handshake_secret: [u8; 32],
    server_handshake_secret: [u8; 32],
    client_app_secret: [u8; 32],
    server_app_secret: [u8; 32],

    // Transcript hash
    transcript: TranscriptHash,

    // Output buffer for pending handshake messages
    pending_write: Buf<2048>,
    pending_level: Level,

    // Second output buffer for the server's handshake-level flight
    // (ServerHello goes at Initial, everything else at Handshake)
    pending_write_hs: Buf<2048>,

    // Keys ready to be picked up by QUIC
    pending_keys: Option<DerivedKeys>,

    // Configuration
    server_name: heapless::String<64>,
    alpn_protocols: &'static [&'static [u8]],
    transport_params: TransportParams,
    peer_transport_params: Option<TransportParams>,

    // Negotiated ALPN
    negotiated_alpn: Option<heapless::Vec<u8, 16>>,

    // Certificate verification (client-side)
    pinned_certs: &'static [&'static [u8]],

    // Server certificate data (stored for verification by client, or as config for server)
    server_cert_data: Buf<2048>,

    // Server certificate DER (static reference, for server role)
    server_cert_der: &'static [u8],
    // Server Ed25519 private key seed (static reference, for server role)
    server_private_key_der: &'static [u8],

    // Handshake complete flag
    complete: bool,

    // Whether this is a QUIC connection (affects transport params + legacy session ID)
    quic_mode: bool,

    // Legacy session ID for TCP TLS (RFC 8446 middlebox compat)
    legacy_session_id: [u8; 32],

    _crypto: core::marker::PhantomData<C>,
}

impl<C: CryptoProvider> Drop for TlsEngine<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_handshake_secret.zeroize();
        self.server_handshake_secret.zeroize();
        self.client_app_secret.zeroize();
        self.server_app_secret.zeroize();
        // private_key (x25519_dalek::StaticSecret) zeroizes itself on drop
        // key_schedule (TlsKeySchedule) zeroizes itself on drop
    }
}

impl<C: CryptoProvider> TlsEngine<C>
where
    C::Hkdf: Default,
{
    /// Create a new client-side TLS engine.
    ///
    /// `secret_bytes` should be 32 random bytes for the X25519 private key.
    /// `random` should be 32 random bytes for the ClientHello random field.
    pub fn new_client(config: TlsConfig, secret_bytes: [u8; 32], random: [u8; 32]) -> Self {
        let private_key = x25519_dalek::StaticSecret::from(secret_bytes);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        let hkdf = C::Hkdf::default();
        let key_schedule = TlsKeySchedule::new(&hkdf);

        Self {
            role: Role::Client,
            state: HandshakeState::Start,
            private_key,
            public_key,
            client_random: random,
            cipher_suite: None,
            key_schedule,
            client_handshake_secret: [0u8; 32],
            server_handshake_secret: [0u8; 32],
            client_app_secret: [0u8; 32],
            server_app_secret: [0u8; 32],
            transcript: TranscriptHash::new(),
            pending_write: Buf::new(),
            pending_level: Level::Initial,
            pending_write_hs: Buf::new(),
            pending_keys: None,
            server_name: config.server_name,
            alpn_protocols: config.alpn_protocols,
            transport_params: config.transport_params,
            peer_transport_params: None,
            negotiated_alpn: None,
            pinned_certs: config.pinned_certs,
            server_cert_data: Buf::new(),
            server_cert_der: &[],
            server_private_key_der: &[],
            complete: false,
            quic_mode: true,
            legacy_session_id: [0u8; 32],
            _crypto: core::marker::PhantomData,
        }
    }

    /// Create a new server-side TLS engine.
    ///
    /// `secret_bytes` should be 32 random bytes for the X25519 private key.
    /// `random` should be 32 random bytes for the ServerHello random field.
    pub fn new_server(config: ServerTlsConfig, secret_bytes: [u8; 32], random: [u8; 32]) -> Self {
        let private_key = x25519_dalek::StaticSecret::from(secret_bytes);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        let hkdf = C::Hkdf::default();
        let key_schedule = TlsKeySchedule::new(&hkdf);

        Self {
            role: Role::Server,
            state: HandshakeState::WaitClientHello,
            private_key,
            public_key,
            client_random: random, // For the server, this stores the ServerHello random
            cipher_suite: None,
            key_schedule,
            client_handshake_secret: [0u8; 32],
            server_handshake_secret: [0u8; 32],
            client_app_secret: [0u8; 32],
            server_app_secret: [0u8; 32],
            transcript: TranscriptHash::new(),
            pending_write: Buf::new(),
            pending_level: Level::Initial,
            pending_write_hs: Buf::new(),
            pending_keys: None,
            server_name: heapless::String::new(),
            alpn_protocols: config.alpn_protocols,
            transport_params: config.transport_params,
            peer_transport_params: None,
            negotiated_alpn: None,
            pinned_certs: &[],
            server_cert_data: Buf::new(),
            server_cert_der: config.cert_der,
            server_private_key_der: config.private_key_der,
            complete: false,
            quic_mode: true,
            legacy_session_id: [0u8; 32],
            _crypto: core::marker::PhantomData,
        }
    }

    /// Create a new TCP client-side TLS engine (no QUIC transport parameters).
    pub fn new_tcp_client(config: TlsConfig, secret_bytes: [u8; 32], random: [u8; 32]) -> Self {
        let mut engine = Self::new_client(config, secret_bytes, random);
        engine.quic_mode = false;
        engine.legacy_session_id = random; // Use random for middlebox compat
        engine
    }

    /// Create a new TCP server-side TLS engine (no QUIC transport parameters).
    pub fn new_tcp_server(config: ServerTlsConfig, secret_bytes: [u8; 32], random: [u8; 32]) -> Self {
        let mut engine = Self::new_server(config, secret_bytes, random);
        engine.quic_mode = false;
        engine
    }

    /// Create a placeholder TLS engine for pool initialization.
    ///
    /// The resulting engine is not usable for handshakes — it must be
    /// overwritten with a real client/server engine before use.
    pub fn new_placeholder() -> Self {
        let secret = [0u8; 32];
        let random = [0u8; 32];
        let private_key = x25519_dalek::StaticSecret::from(secret);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        let hkdf = C::Hkdf::default();
        let key_schedule = TlsKeySchedule::new(&hkdf);

        Self {
            role: Role::Client,
            state: HandshakeState::Start,
            private_key,
            public_key,
            client_random: random,
            cipher_suite: None,
            key_schedule,
            client_handshake_secret: [0u8; 32],
            server_handshake_secret: [0u8; 32],
            client_app_secret: [0u8; 32],
            server_app_secret: [0u8; 32],
            transcript: TranscriptHash::new(),
            pending_write: Buf::new(),
            pending_level: Level::Initial,
            pending_write_hs: Buf::new(),
            pending_keys: None,
            server_name: heapless::String::new(),
            alpn_protocols: &[],
            transport_params: TransportParams::default_params(),
            peer_transport_params: None,
            negotiated_alpn: None,
            pinned_certs: &[],
            server_cert_data: Buf::new(),
            server_cert_der: &[],
            server_private_key_der: &[],
            complete: false,
            quic_mode: true,
            legacy_session_id: [0u8; 32],
            _crypto: core::marker::PhantomData,
        }
    }

    /// Update the CID-related transport parameters (original_destination_connection_id
    /// and initial_source_connection_id). Called by the Connection layer so these
    /// are included in the server's EncryptedExtensions.
    pub fn set_transport_param_cids(&mut self, original_dcid: &[u8], initial_scid: &[u8]) {
        let odcid_len = original_dcid.len().min(20);
        self.transport_params.original_dcid[..odcid_len].copy_from_slice(&original_dcid[..odcid_len]);
        self.transport_params.original_dcid_len = odcid_len as u8;

        let iscid_len = initial_scid.len().min(20);
        self.transport_params.initial_scid[..iscid_len].copy_from_slice(&initial_scid[..iscid_len]);
        self.transport_params.initial_scid_len = iscid_len as u8;
    }

    // =========================================================================
    // Client-side methods
    // =========================================================================

    /// Build and buffer the ClientHello message.
    fn build_client_hello(&mut self, random: &[u8; 32]) -> Result<(), Error> {
        // Encode extensions
        let mut ext_buf = [0u8; 1024];
        let tp = if self.quic_mode { Some(&self.transport_params) } else { None };
        let ext_len = encode_client_hello_extensions(
            self.server_name.as_str(),
            self.public_key.as_bytes(),
            self.alpn_protocols,
            tp,
            &mut ext_buf,
        )?;

        let suites = [
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ];

        // QUIC doesn't use the legacy session ID; TCP needs one for middlebox compat
        let session_id: &[u8] = if self.quic_mode { &[] } else { &self.legacy_session_id };

        let mut msg_buf = [0u8; 2048];
        let msg_len = encode_client_hello(
            random,
            session_id,
            &suites,
            &ext_buf[..ext_len],
            &mut msg_buf,
        )?;

        // Add to transcript
        self.transcript.update(&msg_buf[..msg_len]);

        // Buffer for write_handshake
        self.pending_write.clear();
        self.pending_write.buf_extend_from_slice(&msg_buf[..msg_len])?;
        self.pending_level = Level::Initial;

        self.state = HandshakeState::WaitServerHello;
        Ok(())
    }

    /// Process a ServerHello message (client side).
    fn process_server_hello(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let sh = parse_server_hello(msg_body)?;

        // Validate cipher suite
        self.cipher_suite = Some(sh.cipher_suite);

        // Parse extensions
        let ext = parse_server_hello_extensions(sh.extensions)?;

        // Must have TLS 1.3
        if ext.selected_version != 0x0304 {
            return Err(Error::Tls);
        }

        // Must have key_share
        let server_public = ext.key_share.ok_or(Error::Tls)?;

        // Perform X25519 Diffie-Hellman
        let server_pk = x25519_dalek::PublicKey::from(server_public);
        let shared_secret = self.private_key.diffie_hellman(&server_pk);

        // RFC 7748: reject low-order points that produce all-zero shared secret
        if shared_secret.as_bytes().iter().all(|&b| b == 0) {
            return Err(Error::Tls);
        }

        // Derive handshake secrets
        let hkdf = C::Hkdf::default();
        self.key_schedule
            .derive_handshake_secret(&hkdf, shared_secret.as_bytes())?;

        // Get transcript hash at ClientHello..ServerHello
        let transcript_hash = self.transcript.current_hash();

        // Derive handshake traffic secrets
        self.key_schedule.derive_handshake_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut self.client_handshake_secret,
            &mut self.server_handshake_secret,
        )?;

        // Emit handshake-level keys for QUIC
        let mut send_secret = [0u8; 48];
        let mut recv_secret = [0u8; 48];
        send_secret[..32].copy_from_slice(&self.client_handshake_secret);
        recv_secret[..32].copy_from_slice(&self.server_handshake_secret);
        self.pending_keys = Some(DerivedKeys {
            level: Level::Handshake,
            send_secret,
            recv_secret,
            secret_len: 32,
        });

        self.state = HandshakeState::WaitEncryptedExtensions;
        Ok(())
    }

    /// Process an EncryptedExtensions message (client side).
    fn process_encrypted_extensions(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let ext_data = parse_encrypted_extensions(msg_body)?;
        let parsed = parse_encrypted_extensions_data(ext_data)?;

        self.negotiated_alpn = parsed.alpn;
        self.peer_transport_params = parsed.transport_params;

        self.state = HandshakeState::WaitCertificate;
        Ok(())
    }

    /// Process a Certificate message (client side).
    fn process_certificate(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let cert = parse_certificate(msg_body)?;

        // Store the first certificate for potential verification
        self.server_cert_data.clear();
        if let Some(entry_result) = messages::iter_certificate_entries(cert.entries).next() {
            let entry = entry_result?;
            // Store first cert (the end-entity cert)
            let _ = self.server_cert_data.buf_extend_from_slice(entry.cert_data);
        }

        self.state = HandshakeState::WaitCertificateVerify;
        Ok(())
    }

    /// Process a CertificateVerify message (client side).
    ///
    /// Verifies the signature over the transcript hash per RFC 8446 section 4.4.3.
    /// Supports both Ed25519 (0x0807) and ECDSA-P256 (0x0403) signatures.
    ///
    /// The transcript hash used is the hash of all messages up to and including the
    /// Certificate message (which was added to the transcript before this method is called,
    /// but the CertificateVerify itself has NOT yet been added).
    fn process_certificate_verify(
        &mut self,
        msg_body: &[u8],
        transcript_before_cv: &[u8; 32],
    ) -> Result<(), Error> {
        let cv = parse_certificate_verify(msg_body)?;

        // Check pinned certificates if configured
        if !self.pinned_certs.is_empty() {
            let mut found = false;
            for pinned in self.pinned_certs {
                if *pinned == self.server_cert_data.as_slice() {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(Error::Tls);
            }
        }

        // Dispatch based on the signature algorithm
        match cv.algorithm {
            crate::crypto::ed25519::ED25519_ALGORITHM => {
                // Extract the Ed25519 public key from the server's certificate
                let pubkey = crate::crypto::ed25519::extract_ed25519_pubkey_from_cert(
                    self.server_cert_data.as_slice(),
                )?;

                // Verify the Ed25519 signature
                crate::crypto::ed25519::verify_certificate_verify(
                    &pubkey,
                    cv.signature,
                    transcript_before_cv,
                )?;
            }
            crate::crypto::ecdsa_p256::ECDSA_SECP256R1_SHA256 => {
                // Extract the P-256 public key from the server's certificate
                let pubkey = crate::crypto::ecdsa_p256::extract_p256_pubkey_from_cert(
                    self.server_cert_data.as_slice(),
                )?;

                // Verify the ECDSA-P256 signature
                crate::crypto::ecdsa_p256::verify_certificate_verify(
                    &pubkey,
                    cv.signature,
                    transcript_before_cv,
                )?;
            }
            _ => {
                // Unsupported signature algorithm
                return Err(Error::Tls);
            }
        }

        self.state = HandshakeState::WaitFinished;
        Ok(())
    }

    /// Process a server Finished message (client side).
    fn process_server_finished(
        &mut self,
        msg_body: &[u8],
        transcript_before_finished: &[u8; 32],
    ) -> Result<(), Error> {
        let verify_data = parse_finished(msg_body)?;

        // Verify the server's Finished MAC
        let hkdf = C::Hkdf::default();
        let mut server_finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(
            &hkdf,
            &self.server_handshake_secret,
            &mut server_finished_key,
        )?;

        let expected =
            compute_finished_verify_data(&hkdf, &server_finished_key, transcript_before_finished)?;
        server_finished_key.zeroize();

        // Constant-time comparison
        if !ct_eq(&expected, verify_data) {
            return Err(Error::Tls);
        }

        // Now derive application secrets.
        // The transcript hash for app secrets includes everything up to and including
        // the server's Finished message (which has already been added to transcript
        // by the caller).
        let transcript_hash = self.transcript.current_hash();

        self.key_schedule.derive_master_secret(&hkdf)?;
        self.key_schedule.derive_app_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut self.client_app_secret,
            &mut self.server_app_secret,
        )?;

        // Emit application-level keys
        let mut send_secret = [0u8; 48];
        let mut recv_secret = [0u8; 48];
        send_secret[..32].copy_from_slice(&self.client_app_secret);
        recv_secret[..32].copy_from_slice(&self.server_app_secret);
        self.pending_keys = Some(DerivedKeys {
            level: Level::Application,
            send_secret,
            recv_secret,
            secret_len: 32,
        });

        // Build client Finished
        let mut client_finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(
            &hkdf,
            &self.client_handshake_secret,
            &mut client_finished_key,
        )?;

        let client_verify =
            compute_finished_verify_data(&hkdf, &client_finished_key, &transcript_hash)?;
        client_finished_key.zeroize();

        let mut fin_buf = [0u8; 36];
        let fin_len = encode_finished(&client_verify, &mut fin_buf)?;

        // Add client Finished to transcript
        self.transcript.update(&fin_buf[..fin_len]);

        self.pending_write.clear();
        self.pending_write.buf_extend_from_slice(&fin_buf[..fin_len])?;
        self.pending_level = Level::Handshake;

        self.state = HandshakeState::SendFinished;
        Ok(())
    }

    // =========================================================================
    // Server-side methods
    // =========================================================================

    /// Process a ClientHello message and build the entire server flight.
    ///
    /// After this method completes:
    /// - `pending_write` contains the ServerHello (Initial level)
    /// - `pending_write_hs` contains EE+Cert+CV+Finished (Handshake level)
    /// - `pending_keys` contains the handshake-level keys
    fn process_client_hello(&mut self, msg_body: &[u8]) -> Result<(), Error> {
        let ch = parse_client_hello(msg_body)?;

        // Parse extensions
        let ext = parse_client_hello_extensions(ch.extensions)?;

        // Must support TLS 1.3
        if !ext.supports_tls13 {
            return Err(Error::Tls);
        }

        // Must have key_share (X25519)
        let client_public_bytes = ext.key_share.ok_or(Error::Tls)?;

        // Select cipher suite that matches our CryptoProvider's AEAD.
        // The cipher suite must match the AEAD key length to ensure the
        // QUIC packet encryption uses the correct algorithm.
        let our_suite = match C::Aead::KEY_LEN {
            16 => CipherSuite::TlsAes128GcmSha256,
            32 => CipherSuite::TlsChacha20Poly1305Sha256,
            _ => return Err(Error::Tls),
        };
        let mut client_supports_our_suite = false;
        for cs_u16 in iter_cipher_suites(ch.cipher_suites) {
            if cs_u16 == our_suite.to_u16() {
                client_supports_our_suite = true;
                break;
            }
        }
        if !client_supports_our_suite {
            return Err(Error::Tls);
        }
        let selected_suite = our_suite;
        self.cipher_suite = Some(selected_suite);

        // ALPN negotiation: select the first protocol the client offers that we support
        let mut selected_alpn: Option<heapless::Vec<u8, 16>> = None;
        for client_proto in &ext.alpn_protocols {
            for &server_proto in self.alpn_protocols {
                if client_proto.as_slice() == server_proto {
                    selected_alpn = Some(client_proto.clone());
                    break;
                }
            }
            if selected_alpn.is_some() {
                break;
            }
        }

        // Store peer transport params
        self.peer_transport_params = ext.transport_params;

        // Store negotiated ALPN
        self.negotiated_alpn = selected_alpn.clone();

        // --- Build ServerHello ---
        let server_random = self.client_random; // We stored the server random in client_random field

        // Encode ServerHello extensions
        let mut sh_ext_buf = [0u8; 128];
        let sh_ext_len =
            encode_server_hello_extensions(self.public_key.as_bytes(), &mut sh_ext_buf)?;

        let mut sh_buf = [0u8; 512];
        let sh_len = encode_server_hello(
            &server_random,
            ch.session_id, // echo the client's session ID
            selected_suite,
            &sh_ext_buf[..sh_ext_len],
            &mut sh_buf,
        )?;

        // Add ServerHello to transcript (ClientHello was already added by the caller)
        self.transcript.update(&sh_buf[..sh_len]);

        // --- Perform X25519 DH ---
        let client_pk = x25519_dalek::PublicKey::from(client_public_bytes);
        let shared_secret = self.private_key.diffie_hellman(&client_pk);

        // RFC 7748: reject low-order points that produce all-zero shared secret
        if shared_secret.as_bytes().iter().all(|&b| b == 0) {
            return Err(Error::Tls);
        }

        // Derive handshake secrets
        let hkdf = C::Hkdf::default();
        self.key_schedule
            .derive_handshake_secret(&hkdf, shared_secret.as_bytes())?;

        // Get transcript hash at ClientHello..ServerHello
        let transcript_hash = self.transcript.current_hash();

        // Derive handshake traffic secrets
        self.key_schedule.derive_handshake_traffic_secrets(
            &hkdf,
            &transcript_hash,
            &mut self.client_handshake_secret,
            &mut self.server_handshake_secret,
        )?;

        // Emit handshake-level keys for QUIC
        // For the server: send = server_handshake, recv = client_handshake
        let mut send_secret = [0u8; 48];
        let mut recv_secret = [0u8; 48];
        send_secret[..32].copy_from_slice(&self.server_handshake_secret);
        recv_secret[..32].copy_from_slice(&self.client_handshake_secret);
        self.pending_keys = Some(DerivedKeys {
            level: Level::Handshake,
            send_secret,
            recv_secret,
            secret_len: 32,
        });

        // --- Build Handshake-level messages (EE + Cert + CV + Finished) ---
        // Encode each sub-message directly into hs_buf to minimize stack usage.
        // Each message is encoded at hs_buf[hs_off..], then transcript-updated
        // in-place, avoiding separate intermediate buffers.
        let mut hs_buf = [0u8; 2048];
        let mut hs_off = 0;

        // EncryptedExtensions — needs a small temp for the extension payload
        {
            let alpn_bytes = selected_alpn
                .as_ref()
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let mut ee_ext_buf = [0u8; 512];
            let tp = if self.quic_mode { Some(&self.transport_params) } else { None };
            let ee_ext_len = encode_encrypted_extensions_data(
                alpn_bytes,
                tp,
                &mut ee_ext_buf,
            )?;
            let ee_len = encode_encrypted_extensions(
                &ee_ext_buf[..ee_ext_len],
                &mut hs_buf[hs_off..],
            )?;
            self.transcript.update(&hs_buf[hs_off..hs_off + ee_len]);
            hs_off += ee_len;
        }

        // Certificate — encode directly into hs_buf
        {
            let remaining = hs_buf.len() - hs_off;
            if remaining < 256 {
                return Err(Error::BufferTooSmall { needed: hs_off + 256 });
            }
            let cert_len = encode_certificate(self.server_cert_der, &mut hs_buf[hs_off..])?;
            self.transcript.update(&hs_buf[hs_off..hs_off + cert_len]);
            hs_off += cert_len;
        }

        // CertificateVerify — encode directly into hs_buf
        {
            let cv_transcript_hash = self.transcript.current_hash();
            // Sign with the key type matching the certificate.
            let mut cv_buf = [0u8; 256];
            let cv_len = if crate::crypto::ecdsa_p256::cert_has_p256_key(self.server_cert_der) {
                let signature = crate::crypto::ecdsa_p256::sign_certificate_verify(
                    self.server_private_key_der,
                    &cv_transcript_hash,
                )?;
                encode_certificate_verify(
                    crate::crypto::ecdsa_p256::ECDSA_SECP256R1_SHA256,
                    &signature,
                    &mut cv_buf,
                )?
            } else {
                let signing_key_bytes: [u8; 32] = self
                    .server_private_key_der
                    .try_into()
                    .map_err(|_| Error::Tls)?;
                let signature = crate::crypto::ed25519::sign_certificate_verify(
                    &signing_key_bytes,
                    &cv_transcript_hash,
                )?;
                encode_certificate_verify(
                    crate::crypto::ed25519::ED25519_ALGORITHM,
                    &signature,
                    &mut cv_buf,
                )?
            };
            if hs_off + cv_len > hs_buf.len() {
                return Err(Error::BufferTooSmall { needed: hs_off + cv_len });
            }
            hs_buf[hs_off..hs_off + cv_len].copy_from_slice(&cv_buf[..cv_len]);
            self.transcript.update(&hs_buf[hs_off..hs_off + cv_len]);
            hs_off += cv_len;
        }

        // Server Finished — encode directly into hs_buf
        {
            let mut server_finished_key = [0u8; 32];
            TlsKeySchedule::derive_finished_key(
                &hkdf,
                &self.server_handshake_secret,
                &mut server_finished_key,
            )?;
            let transcript_before_fin = self.transcript.current_hash();
            let server_verify =
                compute_finished_verify_data(&hkdf, &server_finished_key, &transcript_before_fin)?;
            server_finished_key.zeroize();
            let fin_len = encode_finished(&server_verify, &mut hs_buf[hs_off..])?;
            self.transcript.update(&hs_buf[hs_off..hs_off + fin_len]);
            hs_off += fin_len;
        }

        // Buffer the ServerHello at Initial level
        self.pending_write.clear();
        self.pending_write.buf_extend_from_slice(&sh_buf[..sh_len])?;
        self.pending_level = Level::Initial;

        // Buffer the Handshake-level flight
        #[cfg(feature = "std")]
        {
            // Debug: dump TLS message types in the handshake flight
            let mut doff = 0;
            while doff + 4 <= hs_off {
                let msg_type = hs_buf[doff];
                let msg_len = (hs_buf[doff + 1] as usize) << 16
                    | (hs_buf[doff + 2] as usize) << 8
                    | hs_buf[doff + 3] as usize;
                std::eprintln!(
                    "[debug] HS flight msg: type={} len={} (offset {})",
                    msg_type, msg_len, doff
                );
                doff += 4 + msg_len;
            }
            std::eprintln!("[debug] HS flight total: {} bytes", hs_off);
        }
        self.pending_write_hs.clear();
        self.pending_write_hs.buf_extend_from_slice(&hs_buf[..hs_off])?;

        self.state = HandshakeState::SendServerFlightInitial;
        Ok(())
    }

    /// Process a client Finished message (server side).
    fn process_client_finished(
        &mut self,
        msg_body: &[u8],
        transcript_before_finished: &[u8; 32],
    ) -> Result<(), Error> {
        let verify_data = parse_finished(msg_body)?;

        // Verify the client's Finished MAC
        let hkdf = C::Hkdf::default();
        let mut client_finished_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(
            &hkdf,
            &self.client_handshake_secret,
            &mut client_finished_key,
        )?;

        let expected =
            compute_finished_verify_data(&hkdf, &client_finished_key, transcript_before_finished)?;
        client_finished_key.zeroize();

        // Constant-time comparison
        if !ct_eq(&expected, verify_data) {
            return Err(Error::Tls);
        }

        // Derive application secrets.
        // For the server, the transcript hash for app secrets is computed after
        // the server's Finished (which is already in the transcript), but BEFORE
        // the client's Finished. The TLS 1.3 spec says app secrets use the
        // transcript up to and including the server Finished.
        //
        // However, we already computed through server Finished in process_client_hello.
        // The transcript_before_finished here is the hash just before the client's Finished
        // was added, which includes everything through the server's Finished — that is
        // the correct hash for deriving app secrets.

        self.key_schedule.derive_master_secret(&hkdf)?;
        self.key_schedule.derive_app_traffic_secrets(
            &hkdf,
            transcript_before_finished,
            &mut self.client_app_secret,
            &mut self.server_app_secret,
        )?;

        // Emit application-level keys
        // For the server: send = server_app, recv = client_app
        let mut send_secret = [0u8; 48];
        let mut recv_secret = [0u8; 48];
        send_secret[..32].copy_from_slice(&self.server_app_secret);
        recv_secret[..32].copy_from_slice(&self.client_app_secret);
        self.pending_keys = Some(DerivedKeys {
            level: Level::Application,
            send_secret,
            recv_secret,
            secret_len: 32,
        });

        self.state = HandshakeState::Complete;
        self.complete = true;
        Ok(())
    }

    // =========================================================================
    // Read/write dispatch
    // =========================================================================

    fn read_client(&mut self, level: Level, data: &[u8]) -> Result<(), Error> {
        // Validate encryption level matches expected state.
        let expected_level = match self.state {
            HandshakeState::WaitServerHello => Level::Initial,
            HandshakeState::WaitEncryptedExtensions
            | HandshakeState::WaitCertificate
            | HandshakeState::WaitCertificateVerify
            | HandshakeState::WaitFinished => Level::Handshake,
            _ => return Err(Error::InvalidState),
        };
        if level != expected_level {
            return Err(Error::Transport(
                crate::error::TransportError::ProtocolViolation,
            ));
        }

        // Multiple TLS messages may be concatenated in a single CRYPTO frame.
        let mut off = 0;
        while off < data.len() {
            let remaining = &data[off..];
            let (msg_type_byte, body_len) = read_handshake_header(remaining)?;
            let msg_len = 4 + body_len;

            if remaining.len() < msg_len {
                return Err(Error::Tls);
            }

            let full_msg = &remaining[..msg_len];
            let msg_body = &remaining[4..msg_len];

            let msg_type = HandshakeType::from_u8(msg_type_byte).ok_or(Error::Tls)?;

            match (self.state, msg_type) {
                (HandshakeState::WaitServerHello, HandshakeType::ServerHello) => {
                    // Add full message (including header) to transcript
                    self.transcript.update(full_msg);
                    self.process_server_hello(msg_body)?;
                }
                (HandshakeState::WaitEncryptedExtensions, HandshakeType::EncryptedExtensions) => {
                    self.transcript.update(full_msg);
                    self.process_encrypted_extensions(msg_body)?;
                }
                (HandshakeState::WaitCertificate, HandshakeType::Certificate) => {
                    self.transcript.update(full_msg);
                    self.process_certificate(msg_body)?;
                }
                (HandshakeState::WaitCertificateVerify, HandshakeType::CertificateVerify) => {
                    // Get transcript hash BEFORE adding CertificateVerify message
                    // (the signature is computed over this hash)
                    let transcript_before_cv = self.transcript.current_hash();
                    self.transcript.update(full_msg);
                    self.process_certificate_verify(msg_body, &transcript_before_cv)?;
                }
                (HandshakeState::WaitFinished, HandshakeType::Finished) => {
                    // Get transcript hash BEFORE adding Finished message
                    let transcript_before = self.transcript.current_hash();
                    self.transcript.update(full_msg);
                    self.process_server_finished(msg_body, &transcript_before)?;
                }
                _ => {
                    return Err(Error::Tls);
                }
            }

            off += msg_len;
        }

        Ok(())
    }

    fn read_server(&mut self, level: Level, data: &[u8]) -> Result<(), Error> {
        // Validate encryption level matches expected state.
        let expected_level = match self.state {
            HandshakeState::WaitClientHello => Level::Initial,
            HandshakeState::WaitClientFinished => Level::Handshake,
            _ => return Err(Error::InvalidState),
        };
        if level != expected_level {
            return Err(Error::Transport(
                crate::error::TransportError::ProtocolViolation,
            ));
        }

        let mut off = 0;
        while off < data.len() {
            let remaining = &data[off..];
            let (msg_type_byte, body_len) = read_handshake_header(remaining)?;
            let msg_len = 4 + body_len;

            if remaining.len() < msg_len {
                return Err(Error::Tls);
            }

            let full_msg = &remaining[..msg_len];
            let msg_body = &remaining[4..msg_len];

            let msg_type = HandshakeType::from_u8(msg_type_byte).ok_or(Error::Tls)?;

            match (self.state, msg_type) {
                (HandshakeState::WaitClientHello, HandshakeType::ClientHello) => {
                    // Add ClientHello to transcript before processing
                    self.transcript.update(full_msg);
                    self.process_client_hello(msg_body)?;
                }
                (HandshakeState::WaitClientFinished, HandshakeType::Finished) => {
                    let transcript_before = self.transcript.current_hash();
                    self.transcript.update(full_msg);
                    self.process_client_finished(msg_body, &transcript_before)?;
                }
                _ => {
                    return Err(Error::Tls);
                }
            }

            off += msg_len;
        }

        Ok(())
    }

    fn write_client(&mut self, buf: &mut [u8]) -> Result<(usize, Level), Error> {
        match self.state {
            HandshakeState::Start => {
                self.build_client_hello(&self.client_random.clone())?;
            }
            HandshakeState::SendFinished => {
                // Client Finished was already built in process_server_finished.
                // It's in pending_write. After it's flushed, we're complete.
            }
            _ => {}
        }

        if self.pending_write.is_empty() {
            return Ok((0, Level::Initial));
        }

        let len = self.pending_write.len();
        if buf.len() < len {
            return Err(Error::BufferTooSmall { needed: len });
        }

        buf[..len].copy_from_slice(&self.pending_write);
        let level = self.pending_level;
        self.pending_write.clear();

        if self.state == HandshakeState::SendFinished {
            self.state = HandshakeState::Complete;
            self.complete = true;
        }

        Ok((len, level))
    }

    fn write_server(&mut self, buf: &mut [u8]) -> Result<(usize, Level), Error> {
        match self.state {
            HandshakeState::SendServerFlightInitial => {
                // Flush the ServerHello at Initial level
                if self.pending_write.is_empty() {
                    return Ok((0, Level::Initial));
                }
                let len = self.pending_write.len();
                if buf.len() < len {
                    return Err(Error::BufferTooSmall { needed: len });
                }
                buf[..len].copy_from_slice(&self.pending_write);
                self.pending_write.clear();

                // Move to the next state for the handshake-level flight
                self.state = HandshakeState::SendServerFlightHandshake;

                Ok((len, Level::Initial))
            }
            HandshakeState::SendServerFlightHandshake => {
                // Flush EE+Cert+CV+Finished at Handshake level
                if self.pending_write_hs.is_empty() {
                    return Ok((0, Level::Handshake));
                }
                let len = self.pending_write_hs.len();
                if buf.len() < len {
                    return Err(Error::BufferTooSmall { needed: len });
                }
                buf[..len].copy_from_slice(&self.pending_write_hs);
                self.pending_write_hs.clear();

                // Now wait for the client's Finished
                self.state = HandshakeState::WaitClientFinished;

                Ok((len, Level::Handshake))
            }
            _ => {
                // Nothing to write
                Ok((0, Level::Initial))
            }
        }
    }

    /// Release handshake-only buffers after the handshake completes.
    ///
    /// With alloc, this frees heap memory backing `pending_write`,
    /// `pending_write_hs`, and `server_cert_data`. Without alloc,
    /// this just clears the buffers (the inline storage remains).
    pub fn shrink_post_handshake(&mut self) {
        self.pending_write.clear();
        self.pending_write_hs.clear();
        self.server_cert_data.clear();
        #[cfg(feature = "alloc")]
        {
            self.pending_write.shrink_to_fit();
            self.pending_write_hs.shrink_to_fit();
            self.server_cert_data.shrink_to_fit();
        }
    }
}

impl<C: CryptoProvider> TlsSession for TlsEngine<C>
where
    C::Hkdf: Default,
{
    type Error = Error;

    fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), Error> {
        match self.role {
            Role::Client => self.read_client(level, data),
            Role::Server => self.read_server(level, data),
        }
    }

    fn write_handshake(&mut self, buf: &mut [u8]) -> Result<(usize, Level), Error> {
        match self.role {
            Role::Client => self.write_client(buf),
            Role::Server => self.write_server(buf),
        }
    }

    fn derived_keys(&mut self) -> Option<DerivedKeys> {
        self.pending_keys.take()
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_ref().map(|v| v.as_slice())
    }

    fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_transport_params.as_ref()
    }

    fn set_transport_params(&mut self, params: &TransportParams) {
        self.transport_params = params.clone();
    }
}

/// Constant-time comparison of two byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
        assert!(ct_eq(&[], &[]));
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_generates_client_hello() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let config = TlsConfig {
            server_name: heapless::String::try_from("example.com").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };

        let secret = [0x42u8; 32];
        let mut engine = TlsEngine::<Aes128GcmProvider>::new_client(config, secret, [0u8; 32]);

        let mut buf = [0u8; 2048];
        let (len, level) = engine.write_handshake(&mut buf).unwrap();

        assert!(len > 0, "ClientHello should have been produced");
        assert_eq!(level, Level::Initial);

        // Verify it's a ClientHello
        let (msg_type, body_len) = read_handshake_header(&buf[..len]).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientHello as u8);
        assert_eq!(body_len + 4, len);

        // State should be WaitServerHello
        assert!(!engine.is_complete());

        // A second write_handshake should produce nothing
        let (len2, _) = engine.write_handshake(&mut buf).unwrap();
        assert_eq!(len2, 0);
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_rejects_unexpected_message() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let config = TlsConfig {
            server_name: heapless::String::try_from("test.example").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };

        let secret = [0x42u8; 32];
        let mut engine = TlsEngine::<Aes128GcmProvider>::new_client(config, secret, [0u8; 32]);

        // Send ClientHello first
        let mut buf = [0u8; 2048];
        engine.write_handshake(&mut buf).unwrap();

        // Now feed an EncryptedExtensions (wrong state — should be ServerHello)
        let fake_ee = [
            HandshakeType::EncryptedExtensions as u8,
            0, 0, 2, // length = 2
            0, 0, // empty extensions list
        ];
        let result = engine.read_handshake(Level::Initial, &fake_ee);
        assert!(result.is_err());
    }

    /// Integration test: simulate a full client handshake with constructed server messages.
    /// Uses real Ed25519 signing/verification for CertificateVerify.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_full_handshake_flow() {
        use crate::crypto::rustcrypto::{Aes128GcmProvider, HkdfSha256};
        use crate::tls::key_schedule_tls::compute_finished_verify_data;

        let config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };

        let client_secret_bytes = [0x42u8; 32];
        let mut engine = TlsEngine::<Aes128GcmProvider>::new_client(config, client_secret_bytes, [0u8; 32]);

        // Step 1: Write ClientHello
        let mut buf = [0u8; 2048];
        let (ch_len, ch_level) = engine.write_handshake(&mut buf).unwrap();
        assert!(ch_len > 0);
        assert_eq!(ch_level, Level::Initial);

        // We need to build a ServerHello that the client can process.
        // Generate a server X25519 keypair
        let server_secret = x25519_dalek::StaticSecret::from([0xAA; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);

        // Build a ServerHello message
        let mut sh_buf = [0u8; 512];
        let sh_len = build_test_server_hello(
            &[0xBB; 32],
            CipherSuite::TlsAes128GcmSha256,
            server_public.as_bytes(),
            &mut sh_buf,
        );

        // Step 2: Feed ServerHello to client
        engine
            .read_handshake(Level::Initial, &sh_buf[..sh_len])
            .unwrap();

        // Should have handshake keys now
        let keys = engine.derived_keys().unwrap();
        assert_eq!(keys.level, Level::Handshake);

        // Start maintaining a parallel transcript for computing server messages
        let mut server_transcript = TranscriptHash::new();
        server_transcript.update(&buf[..ch_len]);
        server_transcript.update(&sh_buf[..sh_len]);

        // Step 3: Feed EncryptedExtensions
        let mut ee_buf = [0u8; 512];
        let ee_len = build_test_encrypted_extensions(&mut ee_buf);
        engine
            .read_handshake(Level::Handshake, &ee_buf[..ee_len])
            .unwrap();

        // Check we got ALPN
        assert_eq!(engine.alpn(), Some(b"h3".as_slice()));

        // Check we got transport params
        assert!(engine.peer_transport_params().is_some());

        server_transcript.update(&ee_buf[..ee_len]);

        // Step 4: Feed Certificate (with real Ed25519 cert)
        let mut cert_buf = [0u8; 512];
        let cert_len = build_test_certificate(get_test_ed25519_cert_der(), &mut cert_buf);
        engine
            .read_handshake(Level::Handshake, &cert_buf[..cert_len])
            .unwrap();

        server_transcript.update(&cert_buf[..cert_len]);

        // Step 5: Feed CertificateVerify (with real Ed25519 signature)
        // The transcript hash before CertificateVerify is what gets signed
        let cv_transcript_hash = server_transcript.current_hash();
        let mut cv_buf = [0u8; 256];
        let cv_len = build_test_certificate_verify(
            &TEST_ED25519_SEED,
            &cv_transcript_hash,
            &mut cv_buf,
        );
        engine
            .read_handshake(Level::Handshake, &cv_buf[..cv_len])
            .unwrap();

        server_transcript.update(&cv_buf[..cv_len]);

        // Step 6: Feed server Finished
        // Compute the shared secret as the server would
        let client_pk = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(client_secret_bytes),
        );
        let shared = server_secret.diffie_hellman(&client_pk);

        // Re-derive the key schedule from scratch (same as client)
        let hkdf = HkdfSha256;
        let mut server_ks = TlsKeySchedule::new(&hkdf);
        server_ks
            .derive_handshake_secret(&hkdf, shared.as_bytes())
            .unwrap();

        // We need the transcript hash at ClientHello..ServerHello
        let mut ch_sh_transcript = TranscriptHash::new();
        ch_sh_transcript.update(&buf[..ch_len]);
        ch_sh_transcript.update(&sh_buf[..sh_len]);
        let ch_sh_hash = ch_sh_transcript.current_hash();

        let mut s_client_hs = [0u8; 32];
        let mut s_server_hs = [0u8; 32];
        server_ks
            .derive_handshake_traffic_secrets(&hkdf, &ch_sh_hash, &mut s_client_hs, &mut s_server_hs)
            .unwrap();

        // Compute server Finished
        let mut server_fin_key = [0u8; 32];
        TlsKeySchedule::derive_finished_key(&hkdf, &s_server_hs, &mut server_fin_key).unwrap();
        let server_fin_hash = server_transcript.current_hash();
        let server_verify =
            compute_finished_verify_data(&hkdf, &server_fin_key, &server_fin_hash).unwrap();

        let mut fin_buf = [0u8; 36];
        let fin_len = encode_finished(&server_verify, &mut fin_buf).unwrap();

        engine
            .read_handshake(Level::Handshake, &fin_buf[..fin_len])
            .unwrap();

        // Should have application keys
        let app_keys = engine.derived_keys().unwrap();
        assert_eq!(app_keys.level, Level::Application);

        // Step 7: Write client Finished
        let mut client_fin_buf = [0u8; 256];
        let (cfin_len, cfin_level) = engine.write_handshake(&mut client_fin_buf).unwrap();
        assert!(cfin_len > 0);
        assert_eq!(cfin_level, Level::Handshake);

        // Handshake should be complete
        assert!(engine.is_complete());

        // Verify the client Finished is a proper Finished message
        let (msg_type, _body_len) = read_handshake_header(&client_fin_buf[..cfin_len]).unwrap();
        assert_eq!(msg_type, HandshakeType::Finished as u8);
    }

    // --- Test helper functions to build server messages ---

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_server_hello(
        random: &[u8; 32],
        cipher_suite: CipherSuite,
        server_public_key: &[u8; 32],
        out: &mut [u8],
    ) -> usize {
        // Build ServerHello body
        let mut body = [0u8; 256];
        let mut off = 0;

        // Version: 0x0303
        body[off] = 0x03;
        body[off + 1] = 0x03;
        off += 2;

        // Random
        body[off..off + 32].copy_from_slice(random);
        off += 32;

        // Session ID: empty
        body[off] = 0;
        off += 1;

        // Cipher suite
        let cs = cipher_suite.to_u16();
        body[off] = (cs >> 8) as u8;
        body[off + 1] = (cs & 0xFF) as u8;
        off += 2;

        // Compression method: null
        body[off] = 0;
        off += 1;

        // Extensions
        let mut ext_buf = [0u8; 128];
        let mut ext_off = 0;

        // supported_versions
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x2b; // type
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x02; // length
        ext_off += 2;
        ext_buf[ext_off] = 0x03;
        ext_buf[ext_off + 1] = 0x04; // TLS 1.3
        ext_off += 2;

        // key_share
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x33; // type
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x24; // length = 36
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x1d; // X25519
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x20; // key length = 32
        ext_off += 2;
        ext_buf[ext_off..ext_off + 32].copy_from_slice(server_public_key);
        ext_off += 32;

        // Extensions length
        body[off] = ((ext_off >> 8) & 0xFF) as u8;
        body[off + 1] = (ext_off & 0xFF) as u8;
        off += 2;
        body[off..off + ext_off].copy_from_slice(&ext_buf[..ext_off]);
        off += ext_off;

        // Write handshake header
        out[0] = HandshakeType::ServerHello as u8;
        out[1] = ((off >> 16) & 0xFF) as u8;
        out[2] = ((off >> 8) & 0xFF) as u8;
        out[3] = (off & 0xFF) as u8;
        out[4..4 + off].copy_from_slice(&body[..off]);

        4 + off
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_encrypted_extensions(out: &mut [u8]) -> usize {
        // Build EncryptedExtensions body
        let mut body = [0u8; 256];
        let mut ext_buf = [0u8; 256];
        let mut ext_off = 0;

        // ALPN extension
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x10; // ALPN type
        ext_off += 2;
        // ALPN data: list_len(2) + proto_len(1) + "h3"(2) = 5
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x05;
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x03; // list length
        ext_off += 2;
        ext_buf[ext_off] = 0x02; // "h3" length
        ext_off += 1;
        ext_buf[ext_off] = b'h';
        ext_buf[ext_off + 1] = b'3';
        ext_off += 2;

        // QUIC transport params extension
        let params = TransportParams::default_params();
        let mut tp_buf = [0u8; 128];
        let tp_len = params.encode(&mut tp_buf).unwrap();

        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x39; // QUIC TP type
        ext_off += 2;
        ext_buf[ext_off] = ((tp_len >> 8) & 0xFF) as u8;
        ext_buf[ext_off + 1] = (tp_len & 0xFF) as u8;
        ext_off += 2;
        ext_buf[ext_off..ext_off + tp_len].copy_from_slice(&tp_buf[..tp_len]);
        ext_off += tp_len;

        // Extensions list length prefix
        body[0] = ((ext_off >> 8) & 0xFF) as u8;
        body[1] = (ext_off & 0xFF) as u8;
        body[2..2 + ext_off].copy_from_slice(&ext_buf[..ext_off]);
        let body_len = 2 + ext_off;

        // Handshake header
        out[0] = HandshakeType::EncryptedExtensions as u8;
        out[1] = ((body_len >> 16) & 0xFF) as u8;
        out[2] = ((body_len >> 8) & 0xFF) as u8;
        out[3] = (body_len & 0xFF) as u8;
        out[4..4 + body_len].copy_from_slice(&body[..body_len]);

        4 + body_len
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_certificate(cert_der: &[u8], out: &mut [u8]) -> usize {
        // Build a Certificate message wrapping the given cert DER
        let mut body = [0u8; 512];
        let mut off = 0;

        // certificate_request_context length = 0
        body[off] = 0;
        off += 1;

        // certificate_list length (3 bytes)
        let list_len = 3 + cert_der.len() + 2;
        body[off] = ((list_len >> 16) & 0xFF) as u8;
        body[off + 1] = ((list_len >> 8) & 0xFF) as u8;
        body[off + 2] = (list_len & 0xFF) as u8;
        off += 3;

        // cert_data_length
        body[off] = ((cert_der.len() >> 16) & 0xFF) as u8;
        body[off + 1] = ((cert_der.len() >> 8) & 0xFF) as u8;
        body[off + 2] = (cert_der.len() & 0xFF) as u8;
        off += 3;
        body[off..off + cert_der.len()].copy_from_slice(cert_der);
        off += cert_der.len();

        // extensions_length = 0
        body[off] = 0;
        body[off + 1] = 0;
        off += 2;

        // Handshake header
        out[0] = HandshakeType::Certificate as u8;
        out[1] = ((off >> 16) & 0xFF) as u8;
        out[2] = ((off >> 8) & 0xFF) as u8;
        out[3] = (off & 0xFF) as u8;
        out[4..4 + off].copy_from_slice(&body[..off]);

        4 + off
    }

    /// Build a CertificateVerify message with a real Ed25519 signature.
    ///
    /// `signing_key_seed` is the 32-byte Ed25519 seed.
    /// `transcript_hash` is the hash of the transcript up to (and including)
    /// the Certificate message.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn build_test_certificate_verify(
        signing_key_seed: &[u8; 32],
        transcript_hash: &[u8; 32],
        out: &mut [u8],
    ) -> usize {
        let signature = crate::crypto::ed25519::sign_certificate_verify(
            signing_key_seed,
            transcript_hash,
        )
        .unwrap();

        let mut body = [0u8; 128];

        // Algorithm: Ed25519 = 0x0807
        body[0] = 0x08;
        body[1] = 0x07;

        // Signature length + data
        body[2] = 0;
        body[3] = signature.len() as u8;
        body[4..4 + signature.len()].copy_from_slice(&signature);
        let body_len = 4 + signature.len();

        // Handshake header
        out[0] = HandshakeType::CertificateVerify as u8;
        out[1] = ((body_len >> 16) & 0xFF) as u8;
        out[2] = ((body_len >> 8) & 0xFF) as u8;
        out[3] = (body_len & 0xFF) as u8;
        out[4..4 + body_len].copy_from_slice(&body[..body_len]);

        4 + body_len
    }

    // =========================================================================
    // Server-side tests
    // =========================================================================

    /// Ed25519 private key seed used by all TLS tests.
    const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

    /// Build a real Ed25519 certificate DER from the test seed.
    /// Returns a `&'static [u8]` by caching in a `LazyLock`.
    fn get_test_ed25519_cert_der() -> &'static [u8] {
        use std::sync::LazyLock;
        static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
            let seed: [u8; 32] = [0x01u8; 32];
            let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&seed);
            let mut buf = [0u8; 512];
            let len = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut buf).unwrap();
            buf[..len].to_vec()
        });
        &V
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_server_config() -> ServerTlsConfig {
        ServerTlsConfig {
            cert_der: get_test_ed25519_cert_der(),
            private_key_der: &TEST_ED25519_SEED,
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
        }
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_client_config() -> TlsConfig {
        TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        }
    }

    /// Test: Server generates ServerHello from ClientHello.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_generates_server_hello_from_client_hello() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut client =
            TlsEngine::<Aes128GcmProvider>::new_client(make_client_config(), [0x42; 32], [0; 32]);

        // Client writes ClientHello
        let mut ch_buf = [0u8; 2048];
        let (ch_len, ch_level) = client.write_handshake(&mut ch_buf).unwrap();
        assert!(ch_len > 0);
        assert_eq!(ch_level, Level::Initial);

        // Server reads ClientHello
        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(make_server_config(), [0xAA; 32], [0xBB; 32]);

        server
            .read_handshake(Level::Initial, &ch_buf[..ch_len])
            .unwrap();

        // Server should have handshake keys
        let keys = server.derived_keys().unwrap();
        assert_eq!(keys.level, Level::Handshake);

        // Server writes ServerHello (Initial level)
        let mut sh_buf = [0u8; 2048];
        let (sh_len, sh_level) = server.write_handshake(&mut sh_buf).unwrap();
        assert!(sh_len > 0);
        assert_eq!(sh_level, Level::Initial);

        // Verify it's a ServerHello
        let (msg_type, _body_len) = read_handshake_header(&sh_buf[..sh_len]).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerHello as u8);

        // Server writes the handshake-level flight
        let mut hs_buf = [0u8; 2048];
        let (hs_len, hs_level) = server.write_handshake(&mut hs_buf).unwrap();
        assert!(hs_len > 0);
        assert_eq!(hs_level, Level::Handshake);

        // The handshake-level data should contain multiple messages:
        // EncryptedExtensions, Certificate, CertificateVerify, Finished
        let mut off = 0;
        let mut msg_types = heapless::Vec::<u8, 8>::new();
        while off < hs_len {
            let (msg_type, body_len) = read_handshake_header(&hs_buf[off..]).unwrap();
            msg_types.push(msg_type).unwrap();
            off += 4 + body_len;
        }
        assert_eq!(msg_types.len(), 4);
        assert_eq!(msg_types[0], HandshakeType::EncryptedExtensions as u8);
        assert_eq!(msg_types[1], HandshakeType::Certificate as u8);
        assert_eq!(msg_types[2], HandshakeType::CertificateVerify as u8);
        assert_eq!(msg_types[3], HandshakeType::Finished as u8);
    }

    /// Test: Full client-server handshake driven to completion.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn full_client_server_handshake() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut client =
            TlsEngine::<Aes128GcmProvider>::new_client(make_client_config(), [0x42; 32], [0; 32]);
        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(make_server_config(), [0xAA; 32], [0xBB; 32]);

        // Step 1: Client writes ClientHello
        let mut ch_buf = [0u8; 2048];
        let (ch_len, ch_level) = client.write_handshake(&mut ch_buf).unwrap();
        assert!(ch_len > 0);
        assert_eq!(ch_level, Level::Initial);

        // Step 2: Server reads ClientHello
        server
            .read_handshake(Level::Initial, &ch_buf[..ch_len])
            .unwrap();

        // Server should have handshake keys now
        let server_hs_keys = server.derived_keys().unwrap();
        assert_eq!(server_hs_keys.level, Level::Handshake);

        // Step 3: Server writes ServerHello (Initial level)
        let mut sh_buf = [0u8; 2048];
        let (sh_len, sh_level) = server.write_handshake(&mut sh_buf).unwrap();
        assert!(sh_len > 0);
        assert_eq!(sh_level, Level::Initial);

        // Step 4: Client reads ServerHello
        client
            .read_handshake(Level::Initial, &sh_buf[..sh_len])
            .unwrap();

        // Client should have handshake keys now
        let client_hs_keys = client.derived_keys().unwrap();
        assert_eq!(client_hs_keys.level, Level::Handshake);

        // Step 5: Server writes EncryptedExtensions+Certificate+CertificateVerify+Finished
        let mut hs_buf = [0u8; 2048];
        let (hs_len, hs_level) = server.write_handshake(&mut hs_buf).unwrap();
        assert!(hs_len > 0);
        assert_eq!(hs_level, Level::Handshake);

        // Step 6: Client reads the handshake-level flight
        client
            .read_handshake(Level::Handshake, &hs_buf[..hs_len])
            .unwrap();

        // Client should have application keys now
        let client_app_keys = client.derived_keys().unwrap();
        assert_eq!(client_app_keys.level, Level::Application);

        // Step 7: Client writes its Finished
        let mut cfin_buf = [0u8; 256];
        let (cfin_len, cfin_level) = client.write_handshake(&mut cfin_buf).unwrap();
        assert!(cfin_len > 0);
        assert_eq!(cfin_level, Level::Handshake);
        assert!(client.is_complete());

        // Step 8: Server reads client Finished
        server
            .read_handshake(Level::Handshake, &cfin_buf[..cfin_len])
            .unwrap();

        // Server should have application keys now
        let server_app_keys = server.derived_keys().unwrap();
        assert_eq!(server_app_keys.level, Level::Application);

        // Both engines should be complete
        assert!(client.is_complete());
        assert!(server.is_complete());

        // Verify that the application secrets match (client send = server recv, etc.)
        assert_eq!(
            &client_app_keys.send_secret[..client_app_keys.secret_len],
            &server_app_keys.recv_secret[..server_app_keys.secret_len],
            "client send secret should match server recv secret"
        );
        assert_eq!(
            &client_app_keys.recv_secret[..client_app_keys.secret_len],
            &server_app_keys.send_secret[..server_app_keys.secret_len],
            "client recv secret should match server send secret"
        );

        // Also verify handshake secrets matched
        assert_eq!(
            &client_hs_keys.send_secret[..client_hs_keys.secret_len],
            &server_hs_keys.recv_secret[..server_hs_keys.secret_len],
            "client HS send secret should match server HS recv secret"
        );
        assert_eq!(
            &client_hs_keys.recv_secret[..client_hs_keys.secret_len],
            &server_hs_keys.send_secret[..server_hs_keys.secret_len],
            "client HS recv secret should match server HS send secret"
        );
    }

    // =========================================================================
    // P-256 / ECDSA tests
    // =========================================================================

    /// P-256 private key scalar used by ECDSA TLS tests.
    const TEST_P256_SCALAR: [u8; 32] = [0x02u8; 32];

    /// Build a real P-256 ECDSA certificate DER from the test scalar.
    fn get_test_p256_cert_der() -> &'static [u8] {
        use std::sync::LazyLock;
        static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
            let scalar: [u8; 32] = [0x02u8; 32];
            let pk = crate::crypto::ecdsa_p256::p256_public_key_from_scalar(&scalar).unwrap();
            let mut buf = [0u8; 512];
            let len =
                crate::crypto::ecdsa_p256::build_p256_cert_der(pk.as_slice(), &mut buf).unwrap();
            buf[..len].to_vec()
        });
        &V
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_p256_server_config() -> ServerTlsConfig {
        ServerTlsConfig {
            cert_der: get_test_p256_cert_der(),
            private_key_der: &TEST_P256_SCALAR,
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
        }
    }

    /// Test: Full client-server handshake with ECDSA-P256 certificate.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn full_client_server_handshake_p256() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut client =
            TlsEngine::<Aes128GcmProvider>::new_client(make_client_config(), [0x42; 32], [0; 32]);
        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(make_p256_server_config(), [0xAA; 32], [0xBB; 32]);

        // Step 1: Client writes ClientHello
        let mut ch_buf = [0u8; 2048];
        let (ch_len, ch_level) = client.write_handshake(&mut ch_buf).unwrap();
        assert!(ch_len > 0);
        assert_eq!(ch_level, Level::Initial);

        // Step 2: Server reads ClientHello
        server
            .read_handshake(Level::Initial, &ch_buf[..ch_len])
            .unwrap();

        // Server should have handshake keys now
        let server_hs_keys = server.derived_keys().unwrap();
        assert_eq!(server_hs_keys.level, Level::Handshake);

        // Step 3: Server writes ServerHello (Initial level)
        let mut sh_buf = [0u8; 2048];
        let (sh_len, sh_level) = server.write_handshake(&mut sh_buf).unwrap();
        assert!(sh_len > 0);
        assert_eq!(sh_level, Level::Initial);

        // Step 4: Client reads ServerHello
        client
            .read_handshake(Level::Initial, &sh_buf[..sh_len])
            .unwrap();

        // Client should have handshake keys now
        let client_hs_keys = client.derived_keys().unwrap();
        assert_eq!(client_hs_keys.level, Level::Handshake);

        // Step 5: Server writes EncryptedExtensions+Certificate+CertificateVerify+Finished
        let mut hs_buf = [0u8; 2048];
        let (hs_len, hs_level) = server.write_handshake(&mut hs_buf).unwrap();
        assert!(hs_len > 0);
        assert_eq!(hs_level, Level::Handshake);

        // Verify CertificateVerify uses ECDSA-P256 (0x0403)
        let mut off = 0;
        while off < hs_len {
            let (msg_type, body_len) = read_handshake_header(&hs_buf[off..]).unwrap();
            if msg_type == HandshakeType::CertificateVerify as u8 {
                let cv_body = &hs_buf[off + 4..off + 4 + body_len];
                let algo = u16::from_be_bytes([cv_body[0], cv_body[1]]);
                assert_eq!(
                    algo,
                    crate::crypto::ecdsa_p256::ECDSA_SECP256R1_SHA256,
                    "CertificateVerify should use ECDSA-P256 algorithm"
                );
            }
            off += 4 + body_len;
        }

        // Step 6: Client reads the handshake-level flight
        client
            .read_handshake(Level::Handshake, &hs_buf[..hs_len])
            .unwrap();

        // Client should have application keys now
        let client_app_keys = client.derived_keys().unwrap();
        assert_eq!(client_app_keys.level, Level::Application);

        // Step 7: Client writes its Finished
        let mut cfin_buf = [0u8; 256];
        let (cfin_len, cfin_level) = client.write_handshake(&mut cfin_buf).unwrap();
        assert!(cfin_len > 0);
        assert_eq!(cfin_level, Level::Handshake);
        assert!(client.is_complete());

        // Step 8: Server reads client Finished
        server
            .read_handshake(Level::Handshake, &cfin_buf[..cfin_len])
            .unwrap();

        // Server should have application keys now
        let server_app_keys = server.derived_keys().unwrap();
        assert_eq!(server_app_keys.level, Level::Application);

        // Both engines should be complete
        assert!(client.is_complete());
        assert!(server.is_complete());

        // Verify that the application secrets match
        assert_eq!(
            &client_app_keys.send_secret[..client_app_keys.secret_len],
            &server_app_keys.recv_secret[..server_app_keys.secret_len],
            "client send secret should match server recv secret (P-256)"
        );
        assert_eq!(
            &client_app_keys.recv_secret[..client_app_keys.secret_len],
            &server_app_keys.send_secret[..server_app_keys.secret_len],
            "client recv secret should match server send secret (P-256)"
        );
    }

    /// Test: ALPN negotiation between client and server.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn alpn_negotiation() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        // Client offers h3 and hq-29, server supports h3
        let client_config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"hq-29", b"h3"],
            transport_params: TransportParams::default_params(),
            pinned_certs: &[],
        };
        let server_config = ServerTlsConfig {
            cert_der: get_test_ed25519_cert_der(),
            private_key_der: &TEST_ED25519_SEED,
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
        };

        let mut client =
            TlsEngine::<Aes128GcmProvider>::new_client(client_config, [0x42; 32], [0; 32]);
        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(server_config, [0xAA; 32], [0xBB; 32]);

        // Run handshake
        let mut ch_buf = [0u8; 2048];
        let (ch_len, _) = client.write_handshake(&mut ch_buf).unwrap();
        server
            .read_handshake(Level::Initial, &ch_buf[..ch_len])
            .unwrap();
        let _ = server.derived_keys();

        let mut sh_buf = [0u8; 2048];
        let (sh_len, _) = server.write_handshake(&mut sh_buf).unwrap();
        client
            .read_handshake(Level::Initial, &sh_buf[..sh_len])
            .unwrap();
        let _ = client.derived_keys();

        let mut hs_buf = [0u8; 2048];
        let (hs_len, _) = server.write_handshake(&mut hs_buf).unwrap();
        client
            .read_handshake(Level::Handshake, &hs_buf[..hs_len])
            .unwrap();
        let _ = client.derived_keys();

        // Server should have negotiated h3
        assert_eq!(server.alpn(), Some(b"h3".as_slice()));
        // Client should also see h3
        assert_eq!(client.alpn(), Some(b"h3".as_slice()));

        // Complete the handshake
        let mut cfin_buf = [0u8; 256];
        let (cfin_len, _) = client.write_handshake(&mut cfin_buf).unwrap();
        server
            .read_handshake(Level::Handshake, &cfin_buf[..cfin_len])
            .unwrap();
        assert!(client.is_complete());
        assert!(server.is_complete());
    }

    /// Test: Transport params exchange between client and server.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn transport_params_exchange() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let client_tp = TransportParams {
            max_idle_timeout: 10_000,
            initial_max_data: 500_000,
            ..TransportParams::default_params()
        };
        let server_tp = TransportParams {
            max_idle_timeout: 20_000,
            initial_max_data: 1_000_000,
            ..TransportParams::default_params()
        };

        let client_config = TlsConfig {
            server_name: heapless::String::try_from("test.local").unwrap(),
            alpn_protocols: &[b"h3"],
            transport_params: client_tp.clone(),
            pinned_certs: &[],
        };
        let server_config = ServerTlsConfig {
            cert_der: get_test_ed25519_cert_der(),
            private_key_der: &TEST_ED25519_SEED,
            alpn_protocols: &[b"h3"],
            transport_params: server_tp.clone(),
        };

        let mut client =
            TlsEngine::<Aes128GcmProvider>::new_client(client_config, [0x42; 32], [0; 32]);
        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(server_config, [0xAA; 32], [0xBB; 32]);

        // Run handshake
        let mut ch_buf = [0u8; 2048];
        let (ch_len, _) = client.write_handshake(&mut ch_buf).unwrap();
        server
            .read_handshake(Level::Initial, &ch_buf[..ch_len])
            .unwrap();
        let _ = server.derived_keys();

        let mut sh_buf = [0u8; 2048];
        let (sh_len, _) = server.write_handshake(&mut sh_buf).unwrap();
        client
            .read_handshake(Level::Initial, &sh_buf[..sh_len])
            .unwrap();
        let _ = client.derived_keys();

        let mut hs_buf = [0u8; 2048];
        let (hs_len, _) = server.write_handshake(&mut hs_buf).unwrap();
        client
            .read_handshake(Level::Handshake, &hs_buf[..hs_len])
            .unwrap();
        let _ = client.derived_keys();

        let mut cfin_buf = [0u8; 256];
        let (cfin_len, _) = client.write_handshake(&mut cfin_buf).unwrap();
        server
            .read_handshake(Level::Handshake, &cfin_buf[..cfin_len])
            .unwrap();
        let _ = server.derived_keys();

        // Server should have the client's transport params
        let server_peer_tp = server.peer_transport_params().unwrap();
        assert_eq!(server_peer_tp.max_idle_timeout, client_tp.max_idle_timeout);
        assert_eq!(server_peer_tp.initial_max_data, client_tp.initial_max_data);

        // Client should have the server's transport params
        let client_peer_tp = client.peer_transport_params().unwrap();
        assert_eq!(client_peer_tp.max_idle_timeout, server_tp.max_idle_timeout);
        assert_eq!(client_peer_tp.initial_max_data, server_tp.initial_max_data);
    }

    /// Test: Server rejects ClientHello at wrong level.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_rejects_client_hello_at_wrong_level() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut client =
            TlsEngine::<Aes128GcmProvider>::new_client(make_client_config(), [0x42; 32], [0; 32]);
        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(make_server_config(), [0xAA; 32], [0xBB; 32]);

        let mut ch_buf = [0u8; 2048];
        let (ch_len, _) = client.write_handshake(&mut ch_buf).unwrap();

        // Send ClientHello at Handshake level (wrong!)
        let result = server.read_handshake(Level::Handshake, &ch_buf[..ch_len]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            Error::Transport(crate::error::TransportError::ProtocolViolation)
        );
    }

    /// Test: Server rejects ClientHello with no common cipher suite.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_rejects_no_common_cipher_suite() {
        use crate::crypto::rustcrypto::Aes128GcmProvider;

        let mut server =
            TlsEngine::<Aes128GcmProvider>::new_server(make_server_config(), [0xAA; 32], [0xBB; 32]);

        // Build a ClientHello with only unsupported cipher suites
        let random = [0u8; 32];
        // Use a non-existent cipher suite
        let mut fake_ch_body = [0u8; 256];
        let mut off = 0;

        // Version 0x0303
        fake_ch_body[off] = 0x03;
        fake_ch_body[off + 1] = 0x03;
        off += 2;

        // Random
        fake_ch_body[off..off + 32].copy_from_slice(&random);
        off += 32;

        // Session ID: 0
        fake_ch_body[off] = 0;
        off += 1;

        // Cipher suites: only 0xFFFF (unsupported)
        fake_ch_body[off] = 0;
        fake_ch_body[off + 1] = 2;
        off += 2;
        fake_ch_body[off] = 0xFF;
        fake_ch_body[off + 1] = 0xFF;
        off += 2;

        // Compression methods: null
        fake_ch_body[off] = 1;
        off += 1;
        fake_ch_body[off] = 0;
        off += 1;

        // Extensions: supported_versions + key_share (minimal)
        let mut ext_buf = [0u8; 128];
        let mut ext_off = 0;

        // supported_versions
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x2b;
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x03;
        ext_off += 2;
        ext_buf[ext_off] = 0x02;
        ext_off += 1;
        ext_buf[ext_off] = 0x03;
        ext_buf[ext_off + 1] = 0x04;
        ext_off += 2;

        // key_share with X25519
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x33;
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x26; // 2 + 2 + 2 + 32 = 38
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x24; // shares length = 36
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x1d; // X25519
        ext_off += 2;
        ext_buf[ext_off] = 0x00;
        ext_buf[ext_off + 1] = 0x20; // key length = 32
        ext_off += 2;
        ext_buf[ext_off..ext_off + 32].copy_from_slice(&[0x42; 32]);
        ext_off += 32;

        // Extensions length
        fake_ch_body[off] = ((ext_off >> 8) & 0xFF) as u8;
        fake_ch_body[off + 1] = (ext_off & 0xFF) as u8;
        off += 2;
        fake_ch_body[off..off + ext_off].copy_from_slice(&ext_buf[..ext_off]);
        off += ext_off;

        // Build full message with header
        let body_len = off;
        let mut msg = [0u8; 512];
        msg[0] = HandshakeType::ClientHello as u8;
        msg[1] = ((body_len >> 16) & 0xFF) as u8;
        msg[2] = ((body_len >> 8) & 0xFF) as u8;
        msg[3] = (body_len & 0xFF) as u8;
        msg[4..4 + body_len].copy_from_slice(&fake_ch_body[..body_len]);

        let result = server.read_handshake(Level::Initial, &msg[..4 + body_len]);
        assert!(result.is_err());
    }
}
