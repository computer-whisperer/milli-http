//! I/O buffers for QUIC stream data.

use super::{StreamRecvBuf, StreamSendEntry};

/// Borrowed stream I/O buffers for a QUIC connection.
///
/// Callers provide these on every method that reads or writes stream data.
pub struct QuicStreamIo<
    'a,
    const MAX_STREAMS: usize,
    const STREAM_BUF: usize,
    const SEND_QUEUE: usize,
> {
    #[cfg(not(feature = "alloc"))]
    pub send_queue: &'a mut heapless::Vec<StreamSendEntry<STREAM_BUF>, SEND_QUEUE>,
    #[cfg(feature = "alloc")]
    pub send_queue: &'a mut alloc::vec::Vec<StreamSendEntry<STREAM_BUF>>,

    #[cfg(not(feature = "alloc"))]
    pub recv_bufs: &'a mut [Option<StreamRecvBuf<STREAM_BUF>>; MAX_STREAMS],
    #[cfg(feature = "alloc")]
    pub recv_bufs: &'a mut alloc::vec::Vec<Option<StreamRecvBuf<STREAM_BUF>>>,
}

/// Owning stream I/O buffers for standalone QUIC use.
pub struct QuicStreamIoBufs<
    const MAX_STREAMS: usize = 32,
    const STREAM_BUF: usize = 1024,
    const SEND_QUEUE: usize = 16,
> {
    #[cfg(not(feature = "alloc"))]
    pub send_queue: heapless::Vec<StreamSendEntry<STREAM_BUF>, SEND_QUEUE>,
    #[cfg(feature = "alloc")]
    pub send_queue: alloc::vec::Vec<StreamSendEntry<STREAM_BUF>>,

    #[cfg(not(feature = "alloc"))]
    pub recv_bufs: [Option<StreamRecvBuf<STREAM_BUF>>; MAX_STREAMS],
    #[cfg(feature = "alloc")]
    pub recv_bufs: alloc::vec::Vec<Option<StreamRecvBuf<STREAM_BUF>>>,
}

impl<const MAX_STREAMS: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>
    QuicStreamIoBufs<MAX_STREAMS, STREAM_BUF, SEND_QUEUE>
{
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            send_queue: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            send_queue: alloc::vec::Vec::new(),

            #[cfg(not(feature = "alloc"))]
            recv_bufs: core::array::from_fn(|_| None),
            #[cfg(feature = "alloc")]
            recv_bufs: alloc::vec::Vec::new(),
        }
    }

    pub fn as_io(&mut self) -> QuicStreamIo<'_, MAX_STREAMS, STREAM_BUF, SEND_QUEUE> {
        QuicStreamIo {
            send_queue: &mut self.send_queue,
            recv_bufs: &mut self.recv_bufs,
        }
    }
}
