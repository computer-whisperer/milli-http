//! HTTP/2 flow control (RFC 9113 §5.2).
//!
//! Tracks connection-level and per-stream flow control windows.

use crate::error::Error;

/// Flow control window tracker.
#[derive(Debug)]
pub struct FlowController {
    /// Current window size (can go negative for shrinking via SETTINGS).
    window: i32,
    /// Initial window size for new streams.
    initial_window: i32,
}

impl FlowController {
    /// Create a new flow controller with the given initial window size.
    pub fn new(initial_window: i32) -> Self {
        Self {
            window: initial_window,
            initial_window,
        }
    }

    /// Current available window.
    pub fn window(&self) -> i32 {
        self.window
    }

    /// Initial window size.
    pub fn initial_window(&self) -> i32 {
        self.initial_window
    }

    /// Consume `n` bytes from the window (for sending data).
    /// Returns error if not enough window available.
    pub fn consume(&mut self, n: u32) -> Result<(), Error> {
        // Guard against truncation: n > i32::MAX can't fit
        if n > i32::MAX as u32 {
            return Err(Error::InvalidState);
        }
        let n_i32 = n as i32;
        if self.window < n_i32 {
            // RFC 9113 §6.9.1: receiving more than the advertised window is a
            // flow-control violation, not a generic protocol error.
            return Err(Error::Http2(crate::error::H2Error::FlowControlError));
        }
        self.window -= n_i32;
        Ok(())
    }

    /// Add `n` bytes back to the window (received WINDOW_UPDATE).
    pub fn replenish(&mut self, n: u32) -> Result<(), Error> {
        let new_window = self.window as i64 + n as i64;
        if new_window > 0x7fff_ffff {
            return Err(Error::InvalidState); // Flow control overflow
        }
        self.window = new_window as i32;
        Ok(())
    }

    /// Update the initial window size (from SETTINGS).
    /// Adjusts the current window by the delta.
    pub fn update_initial_window(&mut self, new_initial: i32) {
        let delta = new_initial - self.initial_window;
        self.window += delta;
        self.initial_window = new_initial;
    }
}

/// Default initial window size (RFC 9113 §6.9.2).
pub const DEFAULT_INITIAL_WINDOW_SIZE: i32 = 65535;

/// Default connection-level flow control window (same as stream).
pub const DEFAULT_CONNECTION_WINDOW_SIZE: i32 = 65535;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_flow_control() {
        let mut fc = FlowController::new(65535);
        assert_eq!(fc.window(), 65535);

        fc.consume(1000).unwrap();
        assert_eq!(fc.window(), 64535);

        fc.replenish(1000).unwrap();
        assert_eq!(fc.window(), 65535);
    }

    #[test]
    fn consume_more_than_window_fails() {
        let mut fc = FlowController::new(100);
        assert!(fc.consume(101).is_err());
    }

    #[test]
    fn replenish_overflow_fails() {
        let mut fc = FlowController::new(0x7fff_ffff);
        assert!(fc.replenish(1).is_err());
    }

    #[test]
    fn update_initial_window() {
        let mut fc = FlowController::new(65535);
        fc.consume(10000).unwrap();
        assert_eq!(fc.window(), 55535);

        // Increase initial by 10000
        fc.update_initial_window(75535);
        assert_eq!(fc.window(), 65535);
    }

    #[test]
    fn window_can_go_negative_from_settings() {
        let mut fc = FlowController::new(65535);
        fc.update_initial_window(0);
        assert_eq!(fc.window(), 0);
        fc.update_initial_window(-100);
        assert_eq!(fc.window(), -100);
    }

    #[test]
    fn exhaust_then_replenish() {
        let mut fc = FlowController::new(100);
        fc.consume(100).unwrap();
        assert_eq!(fc.window(), 0);

        // Window exhausted — further consume fails
        assert!(fc.consume(1).is_err());

        // Replenish partially and consume again
        fc.replenish(50).unwrap();
        assert_eq!(fc.window(), 50);
        fc.consume(50).unwrap();
        assert_eq!(fc.window(), 0);
    }
}
