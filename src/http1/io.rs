//! I/O buffers for HTTP/1.1 connections.

use crate::buf::{Buf, BufExt};
use crate::error::Error;

/// Borrowed I/O buffers for an HTTP/1.1 connection.
pub struct Http1Io<'a, const BUF: usize> {
    pub recv_buf: &'a mut Buf<BUF>,
    pub send_buf: &'a mut Buf<BUF>,
}

impl<'a, const BUF: usize> Http1Io<'a, BUF> {
    pub fn drain_recv(&mut self, n: usize) {
        self.recv_buf.copy_within(n.., 0);
        self.recv_buf.truncate(self.recv_buf.len() - n);
    }

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

/// Owning I/O buffers for standalone HTTP/1.1 use.
pub struct Http1IoBufs<const BUF: usize = 8192> {
    pub recv_buf: Buf<BUF>,
    pub send_buf: Buf<BUF>,
}

impl<const BUF: usize> Http1IoBufs<BUF> {
    pub fn new() -> Self {
        Self {
            recv_buf: Buf::new(),
            send_buf: Buf::new(),
        }
    }

    pub fn as_io(&mut self) -> Http1Io<'_, BUF> {
        Http1Io {
            recv_buf: &mut self.recv_buf,
            send_buf: &mut self.send_buf,
        }
    }
}
