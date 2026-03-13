use crate::error::{Error, TransportError};

/// Connection-level flow controller.
pub struct FlowController {
    // Send side (limited by peer's MAX_DATA)
    send_max_data: u64,
    send_data_offset: u64,
    send_blocked: bool,

    // Recv side (we advertise MAX_DATA to peer)
    recv_max_data: u64,
    recv_max_data_next: u64,
    recv_data_offset: u64,
    recv_initial_window: u64,

    // Stream count limits
    max_streams_bidi_local: u64,
    max_streams_uni_local: u64,
    max_streams_bidi_remote: u64,
    max_streams_uni_remote: u64,
    next_max_streams_bidi_remote: u64,
    next_max_streams_uni_remote: u64,
    closed_bidi_remote: u64,
    closed_uni_remote: u64,
}

impl FlowController {
    pub fn new(
        initial_max_data: u64,
        initial_max_streams_bidi: u64,
        initial_max_streams_uni: u64,
    ) -> Self {
        Self {
            // Send side: starts at 0, peer will tell us via MAX_DATA in transport params
            send_max_data: 0,
            send_data_offset: 0,
            send_blocked: false,

            // Recv side: we advertise initial_max_data to the peer
            recv_max_data: initial_max_data,
            recv_max_data_next: initial_max_data,
            recv_data_offset: 0,
            recv_initial_window: initial_max_data,

            // Stream count: peer limits start at 0 until they tell us
            max_streams_bidi_local: 0,
            max_streams_uni_local: 0,
            max_streams_bidi_remote: initial_max_streams_bidi,
            max_streams_uni_remote: initial_max_streams_uni,
            next_max_streams_bidi_remote: initial_max_streams_bidi,
            next_max_streams_uni_remote: initial_max_streams_uni,
            closed_bidi_remote: 0,
            closed_uni_remote: 0,
        }
    }

    // --- Send side ---

    /// How many bytes can we send right now?
    pub fn send_capacity(&self) -> u64 {
        self.send_max_data.saturating_sub(self.send_data_offset)
    }

    /// Record bytes sent. Returns error if exceeding limit.
    pub fn on_send(&mut self, bytes: u64) -> Result<(), Error> {
        let new_offset = self.send_data_offset + bytes;
        if new_offset > self.send_max_data {
            self.send_blocked = true;
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.send_data_offset = new_offset;
        if self.send_data_offset == self.send_max_data {
            self.send_blocked = true;
        }
        Ok(())
    }

    /// Peer sent MAX_DATA. Update our send limit.
    pub fn handle_max_data(&mut self, max_data: u64) {
        if max_data > self.send_max_data {
            self.send_max_data = max_data;
            self.send_blocked = false;
        }
    }

    /// Are we blocked by connection-level flow control?
    pub fn is_send_blocked(&self) -> bool {
        self.send_blocked
    }

    // --- Recv side ---

    /// Record bytes received. Returns error if peer exceeds our limit.
    pub fn on_recv(&mut self, bytes: u64) -> Result<(), Error> {
        let new_offset = self.recv_data_offset + bytes;
        if new_offset > self.recv_max_data {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.recv_data_offset = new_offset;
        Ok(())
    }

    /// Should we send a MAX_DATA update? Returns new limit if so.
    /// Auto-update when remaining window drops below 50% of initial.
    pub fn should_send_max_data(&self) -> Option<u64> {
        let remaining = self.recv_max_data.saturating_sub(self.recv_data_offset);
        if remaining < self.recv_initial_window / 2 {
            let next = self.recv_data_offset + self.recv_initial_window;
            if next > self.recv_max_data {
                return Some(next);
            }
        }
        None
    }

    /// Mark MAX_DATA as sent.
    pub fn max_data_sent(&mut self) {
        if let Some(next) = self.should_send_max_data() {
            self.recv_max_data = next;
            self.recv_max_data_next = next;
        }
    }

    // --- Stream count ---

    /// Can we open another bidi stream?
    pub fn can_open_bidi(&self, current_count: u64) -> bool {
        current_count < self.max_streams_bidi_local
    }

    /// Can we open another uni stream?
    pub fn can_open_uni(&self, current_count: u64) -> bool {
        current_count < self.max_streams_uni_local
    }

    /// Peer sent MAX_STREAMS.
    pub fn handle_max_streams(&mut self, bidirectional: bool, max_streams: u64) {
        if bidirectional {
            if max_streams > self.max_streams_bidi_local {
                self.max_streams_bidi_local = max_streams;
            }
        } else if max_streams > self.max_streams_uni_local {
            self.max_streams_uni_local = max_streams;
        }
    }

    /// Should we send a MAX_STREAMS update? Returns (bidirectional, new_limit) if so.
    pub fn should_send_max_streams(&self) -> Option<(bool, u64)> {
        // Check bidi: if closed streams >= 50% of our advertised limit, bump it
        if self.closed_bidi_remote > 0 {
            let consumed = self
                .next_max_streams_bidi_remote
                .saturating_sub(self.closed_bidi_remote);
            let remaining = self.max_streams_bidi_remote.saturating_sub(consumed);
            let _ = remaining; // remaining accounting unused in simple version
            let new_limit = self.max_streams_bidi_remote + self.closed_bidi_remote;
            if new_limit > self.next_max_streams_bidi_remote {
                return Some((true, new_limit));
            }
        }

        // Check uni
        if self.closed_uni_remote > 0 {
            let new_limit = self.max_streams_uni_remote + self.closed_uni_remote;
            if new_limit > self.next_max_streams_uni_remote {
                return Some((false, new_limit));
            }
        }

        None
    }

    /// Mark MAX_STREAMS as sent.
    pub fn max_streams_sent(&mut self, bidirectional: bool) {
        if bidirectional {
            let new_limit = self.max_streams_bidi_remote + self.closed_bidi_remote;
            self.next_max_streams_bidi_remote = new_limit;
            self.max_streams_bidi_remote = new_limit;
            self.closed_bidi_remote = 0;
        } else {
            let new_limit = self.max_streams_uni_remote + self.closed_uni_remote;
            self.next_max_streams_uni_remote = new_limit;
            self.max_streams_uni_remote = new_limit;
            self.closed_uni_remote = 0;
        }
    }

    /// A remote stream was fully closed; update accounting for auto MAX_STREAMS.
    pub fn on_remote_stream_closed(&mut self, bidirectional: bool) {
        if bidirectional {
            self.closed_bidi_remote += 1;
        } else {
            self.closed_uni_remote += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_fc() -> FlowController {
        FlowController::new(10000, 4, 2)
    }

    // -- Send side --

    #[test]
    fn send_capacity_initial() {
        let fc = default_fc();
        // send_max_data starts at 0 since peer hasn't told us their limit yet
        assert_eq!(fc.send_capacity(), 0);
    }

    #[test]
    fn send_after_max_data() {
        let mut fc = default_fc();
        fc.handle_max_data(5000);
        assert_eq!(fc.send_capacity(), 5000);
        assert!(!fc.is_send_blocked());

        fc.on_send(3000).unwrap();
        assert_eq!(fc.send_capacity(), 2000);
        assert!(!fc.is_send_blocked());
    }

    #[test]
    fn send_up_to_limit_then_blocked() {
        let mut fc = default_fc();
        fc.handle_max_data(1000);

        fc.on_send(1000).unwrap();
        assert!(fc.is_send_blocked());
        assert_eq!(fc.send_capacity(), 0);

        // Exceeding returns error
        assert_eq!(
            fc.on_send(1).unwrap_err(),
            Error::Transport(TransportError::FlowControlError)
        );
    }

    #[test]
    fn send_unblocked_by_max_data() {
        let mut fc = default_fc();
        fc.handle_max_data(1000);
        fc.on_send(1000).unwrap();
        assert!(fc.is_send_blocked());

        fc.handle_max_data(2000);
        assert!(!fc.is_send_blocked());
        assert_eq!(fc.send_capacity(), 1000);

        fc.on_send(500).unwrap();
        assert_eq!(fc.send_capacity(), 500);
    }

    #[test]
    fn max_data_monotonic() {
        let mut fc = default_fc();
        fc.handle_max_data(5000);
        assert_eq!(fc.send_capacity(), 5000);

        // Lower value is ignored
        fc.handle_max_data(3000);
        assert_eq!(fc.send_capacity(), 5000);
    }

    // -- Recv side --

    #[test]
    fn recv_within_limit() {
        let mut fc = default_fc();
        fc.on_recv(5000).unwrap();
        fc.on_recv(5000).unwrap();
    }

    #[test]
    fn recv_exceeds_limit() {
        let mut fc = default_fc();
        fc.on_recv(10000).unwrap();
        assert_eq!(
            fc.on_recv(1).unwrap_err(),
            Error::Transport(TransportError::FlowControlError)
        );
    }

    #[test]
    fn should_send_max_data_triggers_at_50_percent() {
        let mut fc = FlowController::new(1000, 4, 2);
        // initial window=1000, threshold=500

        // Receive 400 -> remaining=600 > 500 -> no update
        fc.on_recv(400).unwrap();
        assert!(fc.should_send_max_data().is_none());

        // Receive 200 more -> total=600, remaining=400 < 500 -> trigger
        fc.on_recv(200).unwrap();
        let new_limit = fc.should_send_max_data().unwrap();
        assert_eq!(new_limit, 600 + 1000); // recv_data_offset + initial_window
    }

    #[test]
    fn max_data_sent_updates_limit() {
        let mut fc = FlowController::new(1000, 4, 2);
        fc.on_recv(600).unwrap();
        assert!(fc.should_send_max_data().is_some());

        fc.max_data_sent();
        // After sending, the limit is updated
        assert_eq!(fc.recv_max_data, 1600);

        // Now we have more capacity
        fc.on_recv(500).unwrap(); // total = 1100, remaining = 500 = exactly 50%
        // Remaining 500 is not < 500, so no update
        assert!(fc.should_send_max_data().is_none());

        // One more byte tips it
        fc.on_recv(1).unwrap(); // total = 1101, remaining = 499 < 500
        assert!(fc.should_send_max_data().is_some());
    }

    // -- Stream count --

    #[test]
    fn can_open_bidi_respects_limit() {
        let mut fc = default_fc();
        // Initially 0 because peer hasn't told us
        assert!(!fc.can_open_bidi(0));

        fc.handle_max_streams(true, 3);
        assert!(fc.can_open_bidi(0));
        assert!(fc.can_open_bidi(1));
        assert!(fc.can_open_bidi(2));
        assert!(!fc.can_open_bidi(3));
    }

    #[test]
    fn can_open_uni_respects_limit() {
        let mut fc = default_fc();
        assert!(!fc.can_open_uni(0));

        fc.handle_max_streams(false, 2);
        assert!(fc.can_open_uni(0));
        assert!(fc.can_open_uni(1));
        assert!(!fc.can_open_uni(2));
    }

    #[test]
    fn max_streams_monotonic() {
        let mut fc = default_fc();
        fc.handle_max_streams(true, 10);
        assert!(fc.can_open_bidi(9));

        // Lower value is ignored
        fc.handle_max_streams(true, 5);
        assert!(fc.can_open_bidi(9));
    }

    // -- Auto MAX_STREAMS --

    #[test]
    fn auto_max_streams_after_close() {
        let mut fc = default_fc(); // initial bidi remote = 4, uni remote = 2

        // No closed streams yet
        assert!(fc.should_send_max_streams().is_none());

        // Close a remote bidi stream
        fc.on_remote_stream_closed(true);
        let (bidi, new_limit) = fc.should_send_max_streams().unwrap();
        assert!(bidi);
        assert_eq!(new_limit, 5); // 4 + 1

        fc.max_streams_sent(true);
        assert!(fc.should_send_max_streams().is_none());
    }

    #[test]
    fn auto_max_streams_uni() {
        let mut fc = default_fc(); // uni remote = 2

        fc.on_remote_stream_closed(false);
        let (bidi, new_limit) = fc.should_send_max_streams().unwrap();
        assert!(!bidi);
        assert_eq!(new_limit, 3); // 2 + 1

        fc.max_streams_sent(false);
        assert!(fc.should_send_max_streams().is_none());
    }

    #[test]
    fn auto_max_streams_multiple_closes() {
        let mut fc = default_fc();

        fc.on_remote_stream_closed(true);
        fc.on_remote_stream_closed(true);
        fc.on_remote_stream_closed(true);

        let (bidi, new_limit) = fc.should_send_max_streams().unwrap();
        assert!(bidi);
        assert_eq!(new_limit, 7); // 4 + 3

        fc.max_streams_sent(true);
        assert!(fc.should_send_max_streams().is_none());
    }

    // -- Combined scenarios --

    #[test]
    fn send_recv_independent() {
        let mut fc = default_fc();
        fc.handle_max_data(5000);

        // Can send and receive independently
        fc.on_send(3000).unwrap();
        fc.on_recv(4000).unwrap();

        assert_eq!(fc.send_capacity(), 2000);
    }

    // -----------------------------------------------------------------------
    // Phase 13: Resource exhaustion resistance tests
    // -----------------------------------------------------------------------

    #[test]
    fn flow_control_prevents_buffer_overrun() {
        let mut fc = FlowController::new(100, 4, 2);
        // Can receive up to 100 bytes
        fc.on_recv(50).unwrap();
        fc.on_recv(50).unwrap();
        // Any more should be rejected
        assert_eq!(
            fc.on_recv(1).unwrap_err(),
            Error::Transport(TransportError::FlowControlError)
        );
    }

    #[test]
    fn maximum_window_sizes() {
        // Very large initial window
        let mut fc = FlowController::new(u64::MAX / 2, 100, 100);
        // Should be able to receive large amounts
        fc.on_recv(1_000_000).unwrap();
        fc.on_recv(1_000_000_000).unwrap();
    }

    #[test]
    fn send_exceeds_max_data_exactly_at_boundary() {
        let mut fc = FlowController::new(1000, 4, 2);
        fc.handle_max_data(100);
        // Send exactly to the limit
        fc.on_send(100).unwrap();
        assert!(fc.is_send_blocked());
        assert_eq!(fc.send_capacity(), 0);
        // One more byte should fail
        assert!(fc.on_send(1).is_err());
    }

    #[test]
    fn recv_exactly_at_limit() {
        let mut fc = FlowController::new(1000, 4, 2);
        fc.on_recv(1000).unwrap();
        // Exactly at limit should succeed, one more should fail
        assert!(fc.on_recv(1).is_err());
    }

    #[test]
    fn zero_initial_max_data() {
        let fc = FlowController::new(0, 0, 0);
        assert_eq!(fc.send_capacity(), 0);
        assert_eq!(fc.recv_max_data, 0);
    }
}
