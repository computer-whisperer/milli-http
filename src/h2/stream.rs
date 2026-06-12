//! HTTP/2 stream state machine (RFC 9113 §5.1).

use crate::buf::Buf;

/// HTTP/2 stream states (RFC 9113 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2StreamState {
    Idle,
    Open,
    ReservedLocal,
    ReservedRemote,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// An HTTP/2 stream.
///
/// Generic parameters:
/// - `HDRBUF`: max bytes for HPACK-encoded header block
/// - `DATABUF`: max bytes for buffered body data
#[derive(Debug)]
pub struct H2Stream<const HDRBUF: usize = 2048, const DATABUF: usize = 4096> {
    pub id: u64,
    pub state: H2StreamState,
    pub send_window: i32,
    pub recv_window: i32,
    pub headers_data: Buf<HDRBUF>,
    pub headers_received: bool,
    pub data_buf: Buf<DATABUF>,
    pub data_available: bool,
    pub fin_received: bool,
    pub fin_sent: bool,
    /// Receive-window credit (bytes consumed via `recv_body`) that could not
    /// be sent yet because the send buffer was full. The WINDOW_UPDATE is
    /// retried from `generate_output`; `recv_window` is only raised once the
    /// frame is actually queued, so the advertised window never desyncs from
    /// what the peer has been told.
    pub pending_recv_credit: u32,
    /// RST_STREAM error code queued by `discard_body` but not yet sent
    /// because the send buffer was full. Retried from `generate_output`
    /// (same deferral pattern as `pending_recv_credit`); the stream slot is
    /// retained until the frame actually goes out, so a cancel is never
    /// silently lost to a full buffer.
    pub pending_rst: Option<u32>,
}

impl<const HDRBUF: usize, const DATABUF: usize> H2Stream<HDRBUF, DATABUF> {
    pub fn new(id: u64, initial_send_window: i32, initial_recv_window: i32) -> Self {
        Self {
            id,
            state: H2StreamState::Idle,
            send_window: initial_send_window,
            recv_window: initial_recv_window,
            headers_data: Buf::new(),
            headers_received: false,
            data_buf: Buf::new(),
            data_available: false,
            fin_received: false,
            fin_sent: false,
            pending_recv_credit: 0,
            pending_rst: None,
        }
    }

    /// Transition to Open state (when HEADERS sent or received).
    pub fn open(&mut self) {
        if self.state == H2StreamState::Idle {
            self.state = H2StreamState::Open;
        }
    }

    /// Process an END_STREAM flag received from the peer.
    pub fn recv_end_stream(&mut self) {
        self.fin_received = true;
        match self.state {
            H2StreamState::Open => self.state = H2StreamState::HalfClosedRemote,
            H2StreamState::HalfClosedLocal => self.state = H2StreamState::Closed,
            _ => {}
        }
    }

    /// Process an END_STREAM flag sent by us.
    pub fn send_end_stream(&mut self) {
        self.fin_sent = true;
        match self.state {
            H2StreamState::Open => self.state = H2StreamState::HalfClosedLocal,
            H2StreamState::HalfClosedRemote => self.state = H2StreamState::Closed,
            _ => {}
        }
    }

    /// Whether the stream can receive data.
    pub fn can_recv(&self) -> bool {
        matches!(
            self.state,
            H2StreamState::Open | H2StreamState::HalfClosedLocal
        )
    }

    /// Whether the stream can send data.
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            H2StreamState::Open | H2StreamState::HalfClosedRemote
        )
    }

    /// Reset this stream to Closed.
    pub fn reset(&mut self) {
        self.state = H2StreamState::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_lifecycle_normal() {
        let mut s = H2Stream::<2048, 4096>::new(1, 65535, 65535);
        assert_eq!(s.state, H2StreamState::Idle);

        s.open();
        assert_eq!(s.state, H2StreamState::Open);
        assert!(s.can_send());
        assert!(s.can_recv());

        s.send_end_stream();
        assert_eq!(s.state, H2StreamState::HalfClosedLocal);
        assert!(!s.can_send());
        assert!(s.can_recv());

        s.recv_end_stream();
        assert_eq!(s.state, H2StreamState::Closed);
        assert!(!s.can_send());
        assert!(!s.can_recv());
    }

    #[test]
    fn stream_recv_first() {
        let mut s = H2Stream::<2048, 4096>::new(2, 65535, 65535);
        s.open();
        s.recv_end_stream();
        assert_eq!(s.state, H2StreamState::HalfClosedRemote);
        s.send_end_stream();
        assert_eq!(s.state, H2StreamState::Closed);
    }

    #[test]
    fn stream_reset() {
        let mut s = H2Stream::<2048, 4096>::new(1, 65535, 65535);
        s.open();
        s.reset();
        assert_eq!(s.state, H2StreamState::Closed);
    }
}
