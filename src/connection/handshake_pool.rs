//! Handshake pool: shared handshake-only state for multiple QUIC connections.
//!
//! During the TLS 1.3 handshake, each QUIC connection needs ~20-24 KiB of state
//! (TLS engine, crypto reassembly buffers, pending crypto data). After the
//! handshake completes, this state is no longer needed.
//!
//! A `HandshakePool` allows multiple connections to share a fixed number of
//! handshake "slots". Once the handshake completes, the slot is released and
//! can be reused by another connection, dramatically reducing per-connection
//! memory for established connections.

use crate::buf::Buf;
use crate::crypto::{CryptoProvider, Level};
use crate::error::Error;
use crate::tls::handshake::TlsEngine;

use super::recv::CryptoReassemblyBuf;

// ---------------------------------------------------------------------------
// HandshakeContext
// ---------------------------------------------------------------------------

/// Handshake-only state that can be shared across connections via a pool.
pub struct HandshakeContext<C: CryptoProvider, const CRYPTO_BUF: usize = 4096> {
    pub(crate) tls: TlsEngine<C>,
    pub(crate) pending_crypto: [Buf<2048>; 3],
    pub(crate) crypto_reasm: [CryptoReassemblyBuf<CRYPTO_BUF>; 3],
    pub(crate) crypto_send_offset: [u64; 3],
    pub(crate) pending_crypto_level: [Level; 3],
}

impl<C: CryptoProvider, const CRYPTO_BUF: usize> HandshakeContext<C, CRYPTO_BUF>
where
    C::Hkdf: Default,
{
    /// Create a new handshake context with default/placeholder state.
    pub fn new() -> Self {
        Self {
            tls: TlsEngine::<C>::new_placeholder(),
            pending_crypto: core::array::from_fn(|_| Buf::new()),
            crypto_reasm: core::array::from_fn(|_| CryptoReassemblyBuf::new()),
            crypto_send_offset: [0; 3],
            pending_crypto_level: [Level::Initial; 3],
        }
    }

    /// Reset the context to its initial state for reuse.
    pub fn reset(&mut self) {
        // Reset pending crypto buffers
        for buf in self.pending_crypto.iter_mut() {
            buf.clear();
        }
        // Reset reassembly buffers
        self.crypto_reasm = core::array::from_fn(|_| CryptoReassemblyBuf::new());
        // Reset send offsets
        self.crypto_send_offset = [0; 3];
        // Reset levels
        self.pending_crypto_level = [Level::Initial; 3];
    }
}

// ---------------------------------------------------------------------------
// HandshakePoolAccess trait
// ---------------------------------------------------------------------------

/// Trait for accessing handshake pool slots.
///
/// This decouples `Connection` from the pool's `N` const generic (number of
/// slots), so Connection doesn't need to carry `N` as a type parameter.
pub trait HandshakePoolAccess<C: CryptoProvider, const CRYPTO_BUF: usize> {
    /// Claim an available slot. Returns the slot index, or `Error` if the
    /// pool is exhausted.
    fn claim(&mut self) -> Result<u8, Error>;

    /// Release a slot back to the pool, resetting its context for reuse.
    fn release(&mut self, slot: u8);

    /// Get a mutable reference to a slot's handshake context.
    fn get_mut(&mut self, slot: u8) -> &mut HandshakeContext<C, CRYPTO_BUF>;
}

// ---------------------------------------------------------------------------
// HandshakeSlot
// ---------------------------------------------------------------------------

#[cfg(not(feature = "alloc"))]
struct HandshakeSlot<C: CryptoProvider, const CRYPTO_BUF: usize> {
    in_use: bool,
    ctx: HandshakeContext<C, CRYPTO_BUF>,
}

#[cfg(feature = "alloc")]
struct HandshakeSlot<C: CryptoProvider, const CRYPTO_BUF: usize> {
    ctx: Option<alloc::boxed::Box<HandshakeContext<C, CRYPTO_BUF>>>,
}

// ---------------------------------------------------------------------------
// HandshakePool
// ---------------------------------------------------------------------------

/// A pool of handshake contexts for sharing across multiple connections.
///
/// `N` is the maximum number of simultaneous handshakes. Typical values:
/// - Embedded server: `N = 1` or `N = 2`
/// - Desktop/server: `N = 4` to `N = 16`
///
/// `CRYPTO_BUF` is the per-level crypto reassembly buffer size (default 4096).
pub struct HandshakePool<C: CryptoProvider, const N: usize, const CRYPTO_BUF: usize = 4096> {
    slots: [HandshakeSlot<C, CRYPTO_BUF>; N],
}

impl<C: CryptoProvider, const N: usize, const CRYPTO_BUF: usize> HandshakePool<C, N, CRYPTO_BUF>
where
    C::Hkdf: Default,
{
    /// Create a new pool with all slots available.
    ///
    /// Each slot is initialized with a dummy TLS engine (client mode with
    /// zeroed keys). The actual TLS engine will be installed when a connection
    /// claims the slot and initializes it via `Connection::client()` or
    /// `Connection::server()`.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| {
                #[cfg(not(feature = "alloc"))]
                {
                    HandshakeSlot {
                        in_use: false,
                        ctx: HandshakeContext::new(),
                    }
                }
                #[cfg(feature = "alloc")]
                {
                    HandshakeSlot { ctx: None }
                }
            }),
        }
    }

    /// Number of slots currently claimed. Useful for telemetry and for
    /// verifying that abandoned handshakes release their slots.
    pub fn slots_in_use(&self) -> usize {
        #[cfg(not(feature = "alloc"))]
        {
            self.slots.iter().filter(|s| s.in_use).count()
        }
        #[cfg(feature = "alloc")]
        {
            self.slots.iter().filter(|s| s.ctx.is_some()).count()
        }
    }
}

impl<C: CryptoProvider, const N: usize, const CRYPTO_BUF: usize> HandshakePoolAccess<C, CRYPTO_BUF>
    for HandshakePool<C, N, CRYPTO_BUF>
where
    C::Hkdf: Default,
{
    fn claim(&mut self) -> Result<u8, Error> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            #[cfg(not(feature = "alloc"))]
            if !slot.in_use {
                slot.in_use = true;
                return Ok(i as u8);
            }
            #[cfg(feature = "alloc")]
            if slot.ctx.is_none() {
                slot.ctx = Some(alloc::boxed::Box::new(HandshakeContext::new()));
                return Ok(i as u8);
            }
        }
        Err(Error::HandshakePoolExhausted)
    }

    fn release(&mut self, slot: u8) {
        let idx = slot as usize;
        if idx < N {
            #[cfg(not(feature = "alloc"))]
            {
                self.slots[idx].in_use = false;
                self.slots[idx].ctx.reset();
            }
            #[cfg(feature = "alloc")]
            {
                self.slots[idx].ctx = None;
            }
        }
    }

    fn get_mut(&mut self, slot: u8) -> &mut HandshakeContext<C, CRYPTO_BUF> {
        #[cfg(not(feature = "alloc"))]
        {
            &mut self.slots[slot as usize].ctx
        }
        #[cfg(feature = "alloc")]
        {
            self.slots[slot as usize].ctx.as_deref_mut().unwrap()
        }
    }
}
