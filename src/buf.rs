//! Bounded byte buffer — heapless by default, heap-backed with `alloc` feature.
//!
//! `Buf<N>` is the canonical buffer type for I/O buffers in milli-http.
//! Without the `alloc` feature, it is backed by `heapless::Vec<u8, N>` (inline storage).
//! With `alloc`, it is a heap-backed buffer with capacity capped at `N`.

#[cfg(not(feature = "alloc"))]
pub type Buf<const N: usize> = heapless::Vec<u8, N>;

/// Byte buffer with capacity bounded by `N`, backed by either the heap (grows
/// on demand) or a caller-provided `'static` slice (fixed, never touches the
/// allocator).
///
/// API matches `heapless::Vec<u8, N>` so callers work identically regardless
/// of the `alloc` feature or the backing storage. The buffer starts empty and
/// will never hold more than `N` bytes.
///
/// The `Static` variant lets a memory-tight target hand a connection a fixed
/// set of `'static mut` slices (see [`from_static`](Self::from_static)) so the
/// large TLS/h2 I/O buffers live in `.bss` instead of the heap — avoiding both
/// the realloc transient (old+new allocation live during a grow) and the
/// per-connection alloc/free churn that fragments a linked-list allocator.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct Buf<const N: usize> {
    storage: Storage,
    /// Number of bytes at the tail of the physical contents that are hidden
    /// from the public view (see [`hide_tail`](Self::hide_tail)). The visible
    /// length is `physical - hidden`. The hidden region always abuts the
    /// visible end: `truncate` relocates it and `extend_from_slice`/`push`
    /// insert before it, so front-drains and appends behave as if the hidden
    /// bytes did not exist while still preserving them.
    hidden: usize,
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
enum Storage {
    Heap(alloc::vec::Vec<u8>),
    /// Caller-provided fixed slice (`mem.len() >= N`) with a logical length.
    Static {
        mem: &'static mut [u8],
        len: usize,
    },
}

#[cfg(feature = "alloc")]
impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Self {
            storage: Storage::Heap(alloc::vec::Vec::new()),
            hidden: 0,
        }
    }

    /// Build a buffer backed by a `'static` slice instead of the heap.
    ///
    /// The slice must be at least `N` bytes; the buffer caps its logical length
    /// at `N` regardless of the slice's actual length. The buffer starts empty.
    ///
    /// # Panics
    /// If `mem.len() < N`.
    pub fn from_static(mem: &'static mut [u8]) -> Self {
        assert!(
            mem.len() >= N,
            "Buf::from_static slice too small for capacity N"
        );
        Self {
            storage: Storage::Static { mem, len: 0 },
            hidden: 0,
        }
    }

    /// Recover the backing `'static` slice, leaving an empty heap-backed buffer
    /// behind. Returns `None` for a heap-backed buffer.
    ///
    /// The returned slice's contents are left as-is (not zeroed); the logical
    /// length is reset so a fresh `from_static` starts empty.
    pub fn take_static(&mut self) -> Option<&'static mut [u8]> {
        match core::mem::replace(&mut self.storage, Storage::Heap(alloc::vec::Vec::new())) {
            Storage::Static { mem, .. } => {
                self.hidden = 0;
                Some(mem)
            }
            other => {
                // Not static — put it back unchanged.
                self.storage = other;
                None
            }
        }
    }

    /// Physical content length: visible bytes plus any hidden tail.
    #[inline]
    fn phys_len(&self) -> usize {
        match &self.storage {
            Storage::Heap(v) => v.len(),
            Storage::Static { len, .. } => *len,
        }
    }

    /// Visible length (excludes any hidden tail).
    #[inline]
    pub fn len(&self) -> usize {
        self.phys_len() - self.hidden
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear everything, including any hidden tail.
    #[inline]
    pub fn clear(&mut self) {
        match &mut self.storage {
            Storage::Heap(v) => v.clear(),
            Storage::Static { len, .. } => *len = 0,
        }
        self.hidden = 0;
    }

    /// Truncate the visible contents to `len` bytes. A hidden tail (if any) is
    /// relocated to abut the new visible end, so it survives front-drains
    /// (`copy_within(n.., 0)` + `truncate(len - n)`).
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        let vis = self.len();
        if len >= vis {
            return;
        }
        let hidden = self.hidden;
        match &mut self.storage {
            Storage::Heap(v) => {
                if hidden > 0 {
                    v.copy_within(vis..vis + hidden, len);
                }
                v.truncate(len + hidden);
            }
            Storage::Static { mem, len: cur } => {
                if hidden > 0 {
                    mem.copy_within(vis..vis + hidden, len);
                }
                *cur = len + hidden;
            }
        }
    }

    /// Hide the last `n` visible bytes: they become invisible to every other
    /// method (length, slicing, drains) but are preserved and tracked across
    /// `truncate`/`extend_from_slice`/`push`, always abutting the visible end.
    /// [`unhide_tail`](Self::unhide_tail) makes them visible again.
    ///
    /// Used by the TLS record layer to park not-yet-decrypted ciphertext
    /// behind the decrypted plaintext in a single receive buffer while the
    /// application layer drains the plaintext prefix.
    ///
    /// # Panics
    /// If `n` exceeds the visible length.
    #[inline]
    pub fn hide_tail(&mut self, n: usize) {
        assert!(n <= self.len(), "hide_tail beyond visible length");
        self.hidden += n;
    }

    /// Reveal a previously hidden tail (see [`hide_tail`](Self::hide_tail)),
    /// appending it back to the visible contents. Returns the number of bytes
    /// revealed.
    #[inline]
    pub fn unhide_tail(&mut self) -> usize {
        core::mem::take(&mut self.hidden)
    }

    /// Grow the backing allocation toward `N` to fit `additional` more bytes,
    /// doubling for amortized growth but clamping the reservation to `N`.
    /// Heap-backed only; a no-op for the `Static` variant (fixed capacity).
    ///
    /// `Vec`'s default amortized growth doubles to the next power of two, which
    /// for a near-`N` buffer overshoots badly — e.g. a `Buf<18432>` receiving a
    /// 16 KB TLS record doubles 16384 → 32768, allocating 32 KB to hold an
    /// 18 KB-capped buffer. On a memory-tight target that wasted ~14 KB per
    /// buffer is the difference between fitting and OOMing. Clamping to `N`
    /// keeps the footprint honest while preserving amortized (doubling) growth.
    #[inline]
    fn reserve_clamped(&mut self, additional: usize) {
        if let Storage::Heap(v) = &mut self.storage {
            let needed = v.len() + additional;
            if needed <= v.capacity() {
                return;
            }
            let target = v.capacity().saturating_mul(2).max(needed).min(N);
            v.reserve_exact(target - v.len());
        }
    }

    /// Append bytes to the visible contents, respecting the `N` capacity bound
    /// (which includes any hidden tail). A hidden tail stays at the end: new
    /// bytes are inserted before it.
    ///
    /// Returns `Err(())` if the result would exceed `N` bytes (for the `Static`
    /// variant, also if it would exceed the backing slice).
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), ()> {
        let hidden = self.hidden;
        match &mut self.storage {
            Storage::Heap(_) => {
                if self.phys_len() + data.len() > N {
                    return Err(());
                }
                self.reserve_clamped(data.len());
                if let Storage::Heap(v) = &mut self.storage {
                    v.extend_from_slice(data);
                    if hidden > 0 && !data.is_empty() {
                        // [vis | hidden | data] -> [vis | data | hidden]
                        let vis = v.len() - hidden - data.len();
                        v[vis..].rotate_left(hidden);
                    }
                }
                Ok(())
            }
            Storage::Static { mem, len } => {
                let cap = N.min(mem.len());
                if *len + data.len() > cap {
                    return Err(());
                }
                let vis = *len - hidden;
                if hidden > 0 && !data.is_empty() {
                    mem.copy_within(vis..*len, vis + data.len());
                }
                mem[vis..vis + data.len()].copy_from_slice(data);
                *len += data.len();
                Ok(())
            }
        }
    }

    /// Push a single byte, respecting the `N` capacity bound.
    ///
    /// Returns `Err(byte)` if the buffer is full.
    pub fn push(&mut self, byte: u8) -> Result<(), u8> {
        self.extend_from_slice(core::slice::from_ref(&byte))
            .map_err(|_| byte)
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    /// Release unused heap capacity. No-op for the `Static` variant.
    #[inline]
    pub fn shrink_to_fit(&mut self) {
        if let Storage::Heap(v) = &mut self.storage {
            v.shrink_to_fit();
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        let vis = self.len();
        match &self.storage {
            Storage::Heap(v) => &v[..vis],
            Storage::Static { mem, .. } => &mem[..vis],
        }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let vis = self.len();
        match &mut self.storage {
            Storage::Heap(v) => &mut v[..vis],
            Storage::Static { mem, .. } => &mut mem[..vis],
        }
    }
}

/// Cloning always produces a heap-backed copy: a `'static mut` slice is a
/// unique borrow and cannot be duplicated. The contents and logical length are
/// preserved, including any hidden tail.
#[cfg(feature = "alloc")]
impl<const N: usize> Clone for Buf<N> {
    fn clone(&self) -> Self {
        let phys = self.phys_len();
        let contents: &[u8] = match &self.storage {
            Storage::Heap(v) => v,
            Storage::Static { mem, .. } => &mem[..phys],
        };
        Self {
            storage: Storage::Heap(alloc::vec::Vec::from(contents)),
            hidden: self.hidden,
        }
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> core::ops::Deref for Buf<N> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> core::ops::DerefMut for Buf<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> AsRef<[u8]> for Buf<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> AsMut<[u8]> for Buf<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// Common operations on byte buffers, abstracting over heapless and alloc backends.
pub trait BufExt {
    fn buf_len(&self) -> usize;
    fn buf_is_empty(&self) -> bool {
        self.buf_len() == 0
    }
    fn buf_clear(&mut self);
    fn buf_truncate(&mut self, len: usize);
    fn buf_extend_from_slice(&mut self, data: &[u8]) -> Result<(), crate::error::Error>;
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error>;
    fn buf_as_slice(&self) -> &[u8];
    fn buf_as_mut_slice(&mut self) -> &mut [u8];
    /// Drain `n` bytes from the front by shifting remaining data forward.
    fn buf_drain_front(&mut self, n: usize);
}

impl<const N: usize> BufExt for heapless::Vec<u8, N> {
    fn buf_len(&self) -> usize {
        self.len()
    }
    fn buf_clear(&mut self) {
        self.clear();
    }
    fn buf_truncate(&mut self, len: usize) {
        self.truncate(len);
    }
    fn buf_extend_from_slice(&mut self, data: &[u8]) -> Result<(), crate::error::Error> {
        self.extend_from_slice(data)
            .map_err(|_| crate::error::Error::BufferTooSmall {
                needed: self.len() + data.len(),
            })
    }
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error> {
        self.push(byte)
            .map_err(|_| crate::error::Error::BufferTooSmall {
                needed: self.len() + 1,
            })
    }
    fn buf_as_slice(&self) -> &[u8] {
        self
    }
    fn buf_as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
    fn buf_drain_front(&mut self, n: usize) {
        self.copy_within(n.., 0);
        self.truncate(self.len() - n);
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> BufExt for Buf<N> {
    fn buf_len(&self) -> usize {
        self.len()
    }
    fn buf_clear(&mut self) {
        self.clear();
    }
    fn buf_truncate(&mut self, len: usize) {
        self.truncate(len);
    }
    fn buf_extend_from_slice(&mut self, data: &[u8]) -> Result<(), crate::error::Error> {
        let needed = self.len() + data.len();
        self.extend_from_slice(data)
            .map_err(|_| crate::error::Error::BufferTooSmall { needed })
    }
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error> {
        let needed = self.len() + 1;
        self.push(byte)
            .map_err(|_| crate::error::Error::BufferTooSmall { needed })
    }
    fn buf_as_slice(&self) -> &[u8] {
        self
    }
    fn buf_as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
    fn buf_drain_front(&mut self, n: usize) {
        let len = self.len();
        self.as_mut_slice().copy_within(n.., 0);
        self.truncate(len - n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buf_enforces_capacity_bound() {
        let mut buf: Buf<8> = Buf::new();
        assert!(buf.extend_from_slice(&[1, 2, 3, 4]).is_ok());
        assert_eq!(buf.len(), 4);
        assert!(buf.extend_from_slice(&[5, 6, 7, 8]).is_ok());
        assert_eq!(buf.len(), 8);
        // Should fail — would exceed capacity of 8
        assert!(buf.extend_from_slice(&[9]).is_err());
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn buf_push_enforces_bound() {
        let mut buf: Buf<2> = Buf::new();
        assert!(buf.push(1).is_ok());
        assert!(buf.push(2).is_ok());
        assert!(buf.push(3).is_err());
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn buf_clear_and_reuse() {
        let mut buf: Buf<4> = Buf::new();
        assert!(buf.extend_from_slice(&[1, 2, 3, 4]).is_ok());
        assert!(buf.extend_from_slice(&[5]).is_err());
        buf.clear();
        assert!(buf.extend_from_slice(&[5, 6, 7, 8]).is_ok());
        assert_eq!(&buf[..], &[5, 6, 7, 8]);
    }

    #[test]
    fn buf_drain_front() {
        let mut buf: Buf<8> = Buf::new();
        let _ = buf.extend_from_slice(&[1, 2, 3, 4, 5]);
        buf.buf_drain_front(2);
        assert_eq!(&buf[..], &[3, 4, 5]);
        assert_eq!(buf.len(), 3);
        // Space freed — can add more
        assert!(buf.extend_from_slice(&[6, 7, 8, 9, 10]).is_ok());
        assert_eq!(buf.len(), 8);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn buf_hide_tail_preserves_bytes_across_drain_and_extend() {
        let mut buf: Buf<16> = Buf::new();
        let _ = buf.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        buf.hide_tail(2); // hide [5, 6]
        assert_eq!(&buf[..], &[1, 2, 3, 4]);
        assert_eq!(buf.len(), 4);

        // Front-drain two visible bytes; the hidden tail must follow the
        // visible end through the truncate.
        buf.buf_drain_front(2);
        assert_eq!(&buf[..], &[3, 4]);

        // Appends insert before the hidden tail.
        let _ = buf.extend_from_slice(&[7, 8]);
        assert_eq!(&buf[..], &[3, 4, 7, 8]);

        assert_eq!(buf.unhide_tail(), 2);
        assert_eq!(&buf[..], &[3, 4, 7, 8, 5, 6]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn buf_hide_tail_counts_against_capacity() {
        let mut buf: Buf<8> = Buf::new();
        let _ = buf.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        buf.hide_tail(4);
        // Visible len is 2, but physical occupancy is 6 of 8: two more fit.
        assert!(buf.extend_from_slice(&[7, 8]).is_ok());
        assert!(buf.push(9).is_err());
        buf.unhide_tail();
        assert_eq!(&buf[..], &[1, 2, 7, 8, 3, 4, 5, 6]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn buf_hide_tail_clear_drops_hidden() {
        let mut buf: Buf<8> = Buf::new();
        let _ = buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.hide_tail(2);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.unhide_tail(), 0);
        assert!(buf.extend_from_slice(&[9; 8]).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn buf_hide_tail_static_backing() {
        extern crate std;
        let mem: &'static mut [u8] = std::vec::Vec::leak(std::vec![0u8; 16]);
        let mut buf: Buf<16> = Buf::from_static(mem);
        let _ = buf.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        buf.hide_tail(3); // hide [4, 5, 6]
        assert_eq!(&buf[..], &[1, 2, 3]);
        buf.buf_drain_front(1);
        let _ = buf.extend_from_slice(&[7]);
        assert_eq!(&buf[..], &[2, 3, 7]);
        buf.unhide_tail();
        assert_eq!(&buf[..], &[2, 3, 7, 4, 5, 6]);
        // take_static still recovers the full slice and resets state.
        let slice = buf.take_static().unwrap();
        assert_eq!(slice.len(), 16);
        assert!(buf.is_empty());
    }

    #[test]
    fn buf_slice_access() {
        let mut buf: Buf<16> = Buf::new();
        let _ = buf.extend_from_slice(b"hello");
        assert_eq!(&buf[..], b"hello");
        assert_eq!(buf.as_slice(), b"hello");
        assert!(!buf.is_empty());
        buf.truncate(3);
        assert_eq!(&buf[..], b"hel");
    }
}
