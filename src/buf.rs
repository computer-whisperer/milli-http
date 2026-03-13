//! Bounded byte buffer — heapless by default, heap-backed with `alloc` feature.
//!
//! `Buf<N>` is the canonical buffer type for I/O buffers in milli-http.
//! Without the `alloc` feature, it is backed by `heapless::Vec<u8, N>` (inline storage).
//! With `alloc`, it is a heap-backed buffer with capacity capped at `N`.

#[cfg(not(feature = "alloc"))]
pub type Buf<const N: usize> = heapless::Vec<u8, N>;

/// Heap-backed byte buffer with capacity bounded by `N`.
///
/// API matches `heapless::Vec<u8, N>` so callers work identically regardless
/// of the `alloc` feature. The buffer starts empty and grows on demand, but
/// will never exceed `N` bytes.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Buf<const N: usize> {
    inner: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Self {
            inner: alloc::vec::Vec::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Append bytes, respecting the `N` capacity bound.
    ///
    /// Returns `Err(())` if the result would exceed `N` bytes.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), ()> {
        if self.inner.len() + data.len() > N {
            return Err(());
        }
        self.inner.extend_from_slice(data);
        Ok(())
    }

    /// Push a single byte, respecting the `N` capacity bound.
    ///
    /// Returns `Err(byte)` if the buffer is full.
    pub fn push(&mut self, byte: u8) -> Result<(), u8> {
        if self.inner.len() >= N {
            return Err(byte);
        }
        self.inner.push(byte);
        Ok(())
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    /// Release unused heap capacity.
    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.inner.shrink_to_fit();
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> core::ops::Deref for Buf<N> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> core::ops::DerefMut for Buf<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> AsRef<[u8]> for Buf<N> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> AsMut<[u8]> for Buf<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
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
        self.extend_from_slice(data)
            .map_err(|_| crate::error::Error::BufferTooSmall {
                needed: self.inner.len() + data.len(),
            })
    }
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error> {
        self.push(byte)
            .map_err(|_| crate::error::Error::BufferTooSmall {
                needed: self.inner.len() + 1,
            })
    }
    fn buf_as_slice(&self) -> &[u8] {
        self
    }
    fn buf_as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
    fn buf_drain_front(&mut self, n: usize) {
        self.inner.copy_within(n.., 0);
        self.inner.truncate(self.inner.len() - n);
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
