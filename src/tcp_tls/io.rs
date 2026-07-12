//! I/O buffers for TLS connections.
//!
//! `TlsIo` holds borrowed references to the three buffers a TLS connection
//! needs.  `TlsIoBufs` is a convenience owning wrapper for standalone use.
//!
//! There is deliberately no separate decrypted-plaintext buffer: records are
//! decrypted **in place** inside `recv_buf`, which holds the plaintext ready
//! for the application as its visible prefix and any not-yet-decrypted
//! ciphertext as a hidden tail (see [`crate::buf::Buf::hide_tail`]).

use crate::buf::{Buf, BufExt};
use crate::error::Error;

/// Borrowed I/O buffers for a TLS connection.
///
/// `BUF`: buffer capacity (should be >= 18432 for one max-size TLS record + header).
pub struct TlsIo<'a, const BUF: usize> {
    /// Network receive buffer. Visible prefix: decrypted plaintext for the
    /// application. Hidden tail: encrypted data not yet decrypted.
    pub recv_buf: &'a mut Buf<BUF>,
    /// Encrypted data to send to the network.
    pub send_buf: &'a mut Buf<BUF>,
    /// Application data queued for encryption and sending.
    pub app_send_buf: &'a mut Buf<BUF>,
}

impl<'a, const BUF: usize> TlsIo<'a, BUF> {
    /// Drain `n` bytes from the front of `recv_buf`.
    pub fn drain_recv(&mut self, n: usize) {
        self.recv_buf.copy_within(n.., 0);
        self.recv_buf.truncate(self.recv_buf.len() - n);
    }

    /// Append data to `send_buf`, checking capacity.
    pub fn queue_send(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.send_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: self.send_buf.len() + data.len(),
            });
        }
        self.send_buf.buf_try_reserve(data.len())?;
        let _ = self.send_buf.extend_from_slice(data);
        Ok(())
    }
}

/// Owning I/O buffers for standalone TLS use.
///
/// For composed stacks (TLS + HTTP/2, TLS + HTTP/1.1), construct a [`TlsIo`]
/// with shared buffer references instead.
pub struct TlsIoBufs<const BUF: usize = 18432> {
    pub recv_buf: Buf<BUF>,
    pub send_buf: Buf<BUF>,
    pub app_send_buf: Buf<BUF>,
}

impl<const BUF: usize> TlsIoBufs<BUF> {
    /// Create empty buffers.
    pub fn new() -> Self {
        Self {
            recv_buf: Buf::new(),
            send_buf: Buf::new(),
            app_send_buf: Buf::new(),
        }
    }

    /// Borrow all buffers as a [`TlsIo`].
    pub fn as_io(&mut self) -> TlsIo<'_, BUF> {
        TlsIo {
            recv_buf: &mut self.recv_buf,
            send_buf: &mut self.send_buf,
            app_send_buf: &mut self.app_send_buf,
        }
    }
}
