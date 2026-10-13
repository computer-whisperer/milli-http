//! RustCrypto-backed implementations of the QUIC crypto traits.

use crate::crypto::{Aead as AeadTrait, CryptoProvider, HeaderProtection, Hkdf as HkdfTrait};
use crate::error::Error;
#[cfg(feature = "rustcrypto-chacha")]
use crate::tls::CipherSuite;

// ---- HKDF-SHA256 ----

/// HKDF using SHA-256 (via the `hkdf` crate).
#[derive(Default)]
pub struct HkdfSha256;

impl HkdfTrait for HkdfSha256 {
    const HASH_LEN: usize = 32;

    fn extract(&self, salt: &[u8], ikm: &[u8], prk: &mut [u8]) {
        let (out, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
        prk[..32].copy_from_slice(&out);
    }

    fn expand(&self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| Error::Crypto)?;
        hk.expand(info, okm).map_err(|_| Error::Crypto)
    }
}

// ---- AES-128-GCM AEAD ----

/// AES-128-GCM AEAD implementation.
pub struct Aes128GcmAead {
    cipher: aes_gcm::Aes128Gcm,
}

impl AeadTrait for Aes128GcmAead {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, Error> {
        use aes_gcm::Nonce;
        use aes_gcm::aead::AeadInPlace;

        if nonce.len() != 12 {
            return Err(Error::Crypto);
        }
        let total = payload_len + Self::TAG_LEN;
        if buf.len() < total {
            return Err(Error::BufferTooSmall { needed: total });
        }

        let nonce = Nonce::from_slice(nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf[..payload_len])
            .map_err(|_| Error::Crypto)?;
        buf[payload_len..total].copy_from_slice(&tag);
        Ok(total)
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Error> {
        use aes_gcm::aead::AeadInPlace;
        use aes_gcm::{Nonce, Tag};

        if nonce.len() != 12 {
            return Err(Error::Crypto);
        }
        if ciphertext_len < Self::TAG_LEN {
            return Err(Error::Crypto);
        }
        let plaintext_len = ciphertext_len - Self::TAG_LEN;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&buf[plaintext_len..ciphertext_len]);
        let tag = Tag::from(tag_bytes);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                aad,
                &mut buf[..plaintext_len],
                &tag,
            )
            .map_err(|_| Error::Crypto)?;
        Ok(plaintext_len)
    }
}

// ---- ChaCha20-Poly1305 AEAD ----

#[cfg(feature = "rustcrypto-chacha")]
/// ChaCha20-Poly1305 AEAD implementation.
pub struct ChaCha20Poly1305Aead {
    cipher: chacha20poly1305::ChaCha20Poly1305,
}

#[cfg(feature = "rustcrypto-chacha")]
impl AeadTrait for ChaCha20Poly1305Aead {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, Error> {
        use chacha20poly1305::aead::AeadInPlace;

        if nonce.len() != 12 {
            return Err(Error::Crypto);
        }
        let total = payload_len + Self::TAG_LEN;
        if buf.len() < total {
            return Err(Error::BufferTooSmall { needed: total });
        }

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf[..payload_len])
            .map_err(|_| Error::Crypto)?;
        buf[payload_len..total].copy_from_slice(&tag);
        Ok(total)
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Error> {
        use chacha20poly1305::aead::AeadInPlace;

        if nonce.len() != 12 {
            return Err(Error::Crypto);
        }
        if ciphertext_len < Self::TAG_LEN {
            return Err(Error::Crypto);
        }
        let plaintext_len = ciphertext_len - Self::TAG_LEN;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&buf[plaintext_len..ciphertext_len]);
        let tag = chacha20poly1305::Tag::from(tag_bytes);
        self.cipher
            .decrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                aad,
                &mut buf[..plaintext_len],
                &tag,
            )
            .map_err(|_| Error::Crypto)?;
        Ok(plaintext_len)
    }
}

// ---- AES Header Protection ----

/// AES-128-ECB header protection.
pub struct AesHeaderProtection {
    cipher: aes::Aes128,
}

impl HeaderProtection for AesHeaderProtection {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        use aes::Block;
        use aes::cipher::BlockEncrypt;

        let mut block = Block::clone_from_slice(&sample[..16]);
        self.cipher.encrypt_block(&mut block);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        mask
    }
}

// ---- ChaCha20 Header Protection ----

#[cfg(feature = "rustcrypto-chacha")]
/// ChaCha20 header protection.
pub struct ChaChaHeaderProtection {
    key: [u8; 32],
}

#[cfg(feature = "rustcrypto-chacha")]
impl Drop for ChaChaHeaderProtection {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

#[cfg(feature = "rustcrypto-chacha")]
impl HeaderProtection for ChaChaHeaderProtection {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
        let nonce_bytes: [u8; 12] = {
            let mut n = [0u8; 12];
            n.copy_from_slice(&sample[4..16]);
            n
        };

        // Build a ChaCha20 cipher with the specified counter.
        // The chacha20 crate starts at counter 0; we need to seek to the right position.
        let mut cipher = chacha20::ChaCha20::new((&self.key).into(), (&nonce_bytes).into());
        // Seek to the counter position
        use chacha20::cipher::StreamCipherSeek;
        cipher.seek(counter as u64 * 64);

        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);
        mask
    }
}

// ---- CryptoProvider bundles ----

/// AES-128-GCM cipher suite provider.
#[derive(Clone, Copy)]
pub struct Aes128GcmProvider;

impl CryptoProvider for Aes128GcmProvider {
    type Aead = Aes128GcmAead;
    type Hkdf = HkdfSha256;
    type HeaderProtection = AesHeaderProtection;

    fn aead(&self, key: &[u8]) -> Result<Self::Aead, Error> {
        use aes_gcm::KeyInit;
        if key.len() != Aes128GcmAead::KEY_LEN {
            return Err(Error::Crypto);
        }
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
        Ok(Aes128GcmAead { cipher })
    }

    fn hkdf(&self) -> Self::Hkdf {
        HkdfSha256
    }

    fn header_protection(&self, key: &[u8]) -> Result<Self::HeaderProtection, Error> {
        use aes::cipher::KeyInit;
        if key.len() != 16 {
            return Err(Error::Crypto);
        }
        let cipher = aes::Aes128::new_from_slice(key).map_err(|_| Error::Crypto)?;
        Ok(AesHeaderProtection { cipher })
    }
}

#[cfg(feature = "rustcrypto-chacha")]
/// ChaCha20-Poly1305 cipher suite provider.
#[derive(Clone, Copy)]
pub struct ChaCha20Provider;

#[cfg(feature = "rustcrypto-chacha")]
impl CryptoProvider for ChaCha20Provider {
    type Aead = ChaCha20Poly1305Aead;
    type Hkdf = HkdfSha256;
    type HeaderProtection = ChaChaHeaderProtection;

    fn aead(&self, key: &[u8]) -> Result<Self::Aead, Error> {
        use chacha20poly1305::KeyInit;
        if key.len() != ChaCha20Poly1305Aead::KEY_LEN {
            return Err(Error::Crypto);
        }
        let cipher =
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
        Ok(ChaCha20Poly1305Aead { cipher })
    }

    fn hkdf(&self) -> Self::Hkdf {
        HkdfSha256
    }

    fn header_protection(&self, key: &[u8]) -> Result<Self::HeaderProtection, Error> {
        if key.len() != 32 {
            return Err(Error::Crypto);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(ChaChaHeaderProtection { key: k })
    }
}

// ---- Either-suite provider ----

/// AEAD keyed for whichever suite the handshake negotiated.
///
/// The AES variant carries its expanded key schedule and so dwarfs the
/// ChaCha20 one; a connection holds one of these per direction, which is
/// no more than it holds on [`Aes128GcmProvider`], so no box.
#[cfg(feature = "rustcrypto-chacha")]
#[allow(clippy::large_enum_variant)]
pub enum AnySuiteAead {
    Aes128Gcm(Aes128GcmAead),
    ChaCha20Poly1305(ChaCha20Poly1305Aead),
}

#[cfg(feature = "rustcrypto-chacha")]
impl AeadTrait for AnySuiteAead {
    /// An upper bound only. The record layers size this AEAD's key from the
    /// negotiated suite (`CipherSuite::key_len`), never from this constant,
    /// and `AnySuiteProvider::cipher_suites` does not consult it either.
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, Error> {
        match self {
            Self::Aes128Gcm(aead) => aead.seal_in_place(nonce, aad, buf, payload_len),
            Self::ChaCha20Poly1305(aead) => aead.seal_in_place(nonce, aad, buf, payload_len),
        }
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Error> {
        match self {
            Self::Aes128Gcm(aead) => aead.open_in_place(nonce, aad, buf, ciphertext_len),
            Self::ChaCha20Poly1305(aead) => aead.open_in_place(nonce, aad, buf, ciphertext_len),
        }
    }
}

/// Header protection keyed for whichever suite the handshake negotiated.
/// (Same size asymmetry as [`AnySuiteAead`], same reasoning.)
#[cfg(feature = "rustcrypto-chacha")]
#[allow(clippy::large_enum_variant)]
pub enum AnySuiteHeaderProtection {
    Aes(AesHeaderProtection),
    ChaCha(ChaChaHeaderProtection),
}

#[cfg(feature = "rustcrypto-chacha")]
impl HeaderProtection for AnySuiteHeaderProtection {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        match self {
            Self::Aes(hp) => hp.mask(sample),
            Self::ChaCha(hp) => hp.mask(sample),
        }
    }
}

/// A provider that keys either suite — ChaCha20-Poly1305 preferred,
/// AES-128-GCM accepted — for a host that talks to peers built on
/// [`ChaCha20Provider`] and on [`Aes128GcmProvider`] alike. It offers both
/// suites and builds the AEAD the negotiated key length asks for (16 bytes
/// → AES, 32 → ChaCha20). A single-suite peer stays on the one provider
/// that matches its hardware.
#[cfg(feature = "rustcrypto-chacha")]
#[derive(Clone, Copy, Default)]
pub struct AnySuiteProvider;

#[cfg(feature = "rustcrypto-chacha")]
impl CryptoProvider for AnySuiteProvider {
    type Aead = AnySuiteAead;
    type Hkdf = HkdfSha256;
    type HeaderProtection = AnySuiteHeaderProtection;

    fn cipher_suites() -> &'static [CipherSuite] {
        &[
            CipherSuite::TlsChacha20Poly1305Sha256,
            CipherSuite::TlsAes128GcmSha256,
        ]
    }

    fn aead(&self, key: &[u8]) -> Result<Self::Aead, Error> {
        match key.len() {
            16 => Aes128GcmProvider.aead(key).map(AnySuiteAead::Aes128Gcm),
            32 => ChaCha20Provider
                .aead(key)
                .map(AnySuiteAead::ChaCha20Poly1305),
            _ => Err(Error::Crypto),
        }
    }

    fn hkdf(&self) -> Self::Hkdf {
        HkdfSha256
    }

    fn header_protection(&self, key: &[u8]) -> Result<Self::HeaderProtection, Error> {
        match key.len() {
            16 => Aes128GcmProvider
                .header_protection(key)
                .map(AnySuiteHeaderProtection::Aes),
            32 => ChaCha20Provider
                .header_protection(key)
                .map(AnySuiteHeaderProtection::ChaCha),
            _ => Err(Error::Crypto),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AEAD roundtrip tests ----

    #[test]
    fn aes128gcm_roundtrip() {
        let key = [0x42u8; 16];
        let provider = Aes128GcmProvider;
        let aead = provider.aead(&key).unwrap();
        let nonce = [0u8; 12];
        let aad = b"associated data";
        let plaintext = b"hello world";

        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();
        assert_eq!(ct_len, plaintext.len() + 16);

        let pt_len = aead.open_in_place(&nonce, aad, &mut buf, ct_len).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buf[..pt_len], plaintext);
    }

    #[test]
    fn aes128gcm_auth_failure() {
        let key = [0x42u8; 16];
        let provider = Aes128GcmProvider;
        let aead = provider.aead(&key).unwrap();
        let nonce = [0u8; 12];
        let aad = b"aad";
        let plaintext = b"secret";

        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();

        // Tamper with ciphertext
        buf[0] ^= 0xff;

        let result = aead.open_in_place(&nonce, aad, &mut buf, ct_len);
        assert!(result.is_err());
    }

    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn chacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let provider = ChaCha20Provider;
        let aead = provider.aead(&key).unwrap();
        let nonce = [0u8; 12];
        let aad = b"associated data";
        let plaintext = b"hello chacha";

        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();
        assert_eq!(ct_len, plaintext.len() + 16);

        let pt_len = aead.open_in_place(&nonce, aad, &mut buf, ct_len).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buf[..pt_len], plaintext);
    }

    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn chacha20poly1305_auth_failure() {
        let key = [0x42u8; 32];
        let provider = ChaCha20Provider;
        let aead = provider.aead(&key).unwrap();
        let nonce = [0u8; 12];
        let aad = b"aad";
        let plaintext = b"secret";

        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = aead
            .seal_in_place(&nonce, aad, &mut buf, plaintext.len())
            .unwrap();

        buf[0] ^= 0xff;

        let result = aead.open_in_place(&nonce, aad, &mut buf, ct_len);
        assert!(result.is_err());
    }

    // ---- Header protection tests ----

    #[test]
    fn aes_header_protection_roundtrip() {
        let key = [0x55u8; 16];
        let provider = Aes128GcmProvider;
        let hp = provider.header_protection(&key).unwrap();
        let sample = [0xaa; 16];

        let mask = hp.mask(&sample);
        // Applying XOR twice should cancel out
        let mut header_byte: u8 = 0xc0;
        header_byte ^= mask[0] & 0x0f;
        header_byte ^= mask[0] & 0x0f;
        assert_eq!(header_byte, 0xc0);
    }

    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn chacha_header_protection_roundtrip() {
        let key = [0x55u8; 32];
        let provider = ChaCha20Provider;
        let hp = provider.header_protection(&key).unwrap();
        let sample = [0xaa; 16];

        let mask = hp.mask(&sample);
        let mut header_byte: u8 = 0xc0;
        header_byte ^= mask[0] & 0x0f;
        header_byte ^= mask[0] & 0x0f;
        assert_eq!(header_byte, 0xc0);
    }

    // ---- Key length constants ----

    #[test]
    fn aes128gcm_constants() {
        assert_eq!(Aes128GcmAead::KEY_LEN, 16);
        assert_eq!(Aes128GcmAead::NONCE_LEN, 12);
        assert_eq!(Aes128GcmAead::TAG_LEN, 16);
    }

    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn chacha20poly1305_constants() {
        assert_eq!(ChaCha20Poly1305Aead::KEY_LEN, 32);
        assert_eq!(ChaCha20Poly1305Aead::NONCE_LEN, 12);
        assert_eq!(ChaCha20Poly1305Aead::TAG_LEN, 16);
    }

    // ---- Either-suite provider ----

    #[cfg(feature = "rustcrypto-chacha")]
    fn sealed<A: AeadTrait>(aead: &A) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(b"same bytes here!");
        aead.seal_in_place(&[7u8; 12], b"aad", &mut buf, 16)
            .unwrap();
        buf
    }

    /// The either-suite provider builds the AEAD the key length names, and
    /// it is byte-for-byte the single-suite provider's AEAD.
    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn any_suite_provider_keys_by_key_length() {
        let aes_key = [0x42u8; 16];
        let chacha_key = [0x42u8; 32];

        let any = AnySuiteProvider.aead(&aes_key).unwrap();
        assert!(matches!(any, AnySuiteAead::Aes128Gcm(_)));
        assert_eq!(
            sealed(&any),
            sealed(&Aes128GcmProvider.aead(&aes_key).unwrap())
        );

        let any = AnySuiteProvider.aead(&chacha_key).unwrap();
        assert!(matches!(any, AnySuiteAead::ChaCha20Poly1305(_)));
        assert_eq!(
            sealed(&any),
            sealed(&ChaCha20Provider.aead(&chacha_key).unwrap())
        );

        assert!(matches!(
            AnySuiteProvider.aead(&[0u8; 24]),
            Err(Error::Crypto)
        ));

        let mut buf = sealed(&AnySuiteProvider.aead(&chacha_key).unwrap());
        let n = AnySuiteProvider
            .aead(&chacha_key)
            .unwrap()
            .open_in_place(&[7u8; 12], b"aad", &mut buf, 32)
            .unwrap();
        assert_eq!(&buf[..n], b"same bytes here!");
    }

    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn any_suite_header_protection_keys_by_key_length() {
        let sample = [0xaau8; 16];
        let aes_key = [0x55u8; 16];
        let chacha_key = [0x55u8; 32];

        assert_eq!(
            AnySuiteProvider
                .header_protection(&aes_key)
                .unwrap()
                .mask(&sample),
            Aes128GcmProvider
                .header_protection(&aes_key)
                .unwrap()
                .mask(&sample)
        );
        assert_eq!(
            AnySuiteProvider
                .header_protection(&chacha_key)
                .unwrap()
                .mask(&sample),
            ChaCha20Provider
                .header_protection(&chacha_key)
                .unwrap()
                .mask(&sample)
        );
        assert!(matches!(
            AnySuiteProvider.header_protection(&[0u8; 24]),
            Err(Error::Crypto)
        ));
    }

    /// Single-suite providers list exactly their suite; the either-suite
    /// provider lists both, ChaCha20 first.
    #[cfg(feature = "rustcrypto-chacha")]
    #[test]
    fn providers_list_the_suites_they_key() {
        assert_eq!(
            Aes128GcmProvider::cipher_suites(),
            &[CipherSuite::TlsAes128GcmSha256]
        );
        assert_eq!(
            ChaCha20Provider::cipher_suites(),
            &[CipherSuite::TlsChacha20Poly1305Sha256]
        );
        assert_eq!(
            AnySuiteProvider::cipher_suites(),
            &[
                CipherSuite::TlsChacha20Poly1305Sha256,
                CipherSuite::TlsAes128GcmSha256
            ]
        );
    }
}
