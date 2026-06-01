use crate::Instant;
use crate::crypto::Level;
use crate::error::Error;

/// Metadata for a sent packet awaiting acknowledgment.
#[derive(Debug, Clone, Copy)]
pub struct SentPacket {
    pub pn: u64,
    pub level: Level,
    pub time_sent: Instant,
    pub size: u16,
    pub ack_eliciting: bool,
    pub in_flight: bool,
}

/// Result of processing an ACK frame.
pub struct AckResult {
    pub newly_acked: heapless::Vec<SentPacket, 32>,
    pub largest_newly_acked: Option<SentPacket>,
}

/// Fixed-capacity tracker of sent-but-unacked packets.
///
/// `entries` is kept **dense** (no holes): packets are appended on send and
/// removed with `swap_remove` on ack/loss. Storage order is therefore not PN
/// order — no consumer depends on order — but every operation costs
/// O(in-flight count) rather than O(N), and sends are O(1) appends.
pub struct SentPacketTracker<const N: usize = 128> {
    #[cfg(not(feature = "alloc"))]
    entries: heapless::Vec<SentPacket, N>,
    #[cfg(feature = "alloc")]
    entries: alloc::vec::Vec<SentPacket>,
}

impl<const N: usize> Default for SentPacketTracker<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SentPacketTracker<N> {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            entries: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            entries: alloc::vec::Vec::new(),
        }
    }

    /// Record a sent packet.
    pub fn on_packet_sent(&mut self, pkt: SentPacket) -> Result<(), Error> {
        if self.entries.len() >= N {
            return Err(Error::BufferTooSmall { needed: N + 1 });
        }
        // Capacity is guaranteed by the check above.
        let _ = self.entries.push(pkt);
        Ok(())
    }

    /// Process an ACK: mark packets as acknowledged.
    /// `ranges` contains additional (gap, ack_range) pairs beyond the first range.
    pub fn on_ack_received(
        &mut self,
        level: Level,
        largest_ack: u64,
        first_ack_range: u64,
        ranges: &[(u64, u64)],
    ) -> AckResult {
        // Build the set of acked packet number ranges.
        // First range: [largest_ack - first_ack_range, largest_ack]
        let mut acked_ranges: heapless::Vec<(u64, u64), 32> = heapless::Vec::new();

        let first_lo = largest_ack.saturating_sub(first_ack_range);
        let _ = acked_ranges.push((first_lo, largest_ack));

        // Process additional gap+range pairs per RFC 9000 §19.3.1.
        let mut smallest = first_lo;
        for &(gap, ack_range) in ranges {
            // gap: number of unacknowledged packets after the previous range's smallest.
            // The next range's largest = smallest - gap - 2
            if smallest < gap + 2 {
                break;
            }
            let range_largest = smallest - gap - 2;
            let range_smallest = range_largest.saturating_sub(ack_range);
            let _ = acked_ranges.push((range_smallest, range_largest));
            smallest = range_smallest;
        }

        let mut result = AckResult {
            newly_acked: heapless::Vec::new(),
            largest_newly_acked: None,
        };

        let mut i = 0;
        while i < self.entries.len() {
            let pkt = self.entries[i];
            let is_acked = pkt.level == level
                && acked_ranges
                    .iter()
                    .any(|&(lo, hi)| pkt.pn >= lo && pkt.pn <= hi);
            if is_acked {
                let _ = result.newly_acked.push(pkt);
                match result.largest_newly_acked {
                    None => result.largest_newly_acked = Some(pkt),
                    Some(prev) if pkt.pn > prev.pn => {
                        result.largest_newly_acked = Some(pkt);
                    }
                    _ => {}
                }
                // Remove without preserving order; re-check the swapped-in entry.
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }

        result
    }

    /// Get all packets in a given space that were sent before `before`.
    pub fn sent_before(&self, level: Level, before: Instant) -> impl Iterator<Item = &SentPacket> {
        self.entries
            .iter()
            .filter(move |p| p.level == level && p.time_sent < before)
    }

    /// Get all packets with PN less than threshold in a given space.
    pub fn sent_below_pn(
        &self,
        level: Level,
        pn_threshold: u64,
    ) -> impl Iterator<Item = &SentPacket> {
        self.entries
            .iter()
            .filter(move |p| p.level == level && p.pn < pn_threshold)
    }

    /// Remove a packet (after declaring it lost or acked).
    pub fn remove(&mut self, level: Level, pn: u64) -> Option<SentPacket> {
        let pos = self
            .entries
            .iter()
            .position(|p| p.level == level && p.pn == pn)?;
        Some(self.entries.swap_remove(pos))
    }

    /// Drop all packets in a packet number space.
    pub fn drop_space(&mut self, level: Level) {
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].level == level {
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Number of tracked packets.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Any ack-eliciting packets in flight for this space?
    pub fn has_ack_eliciting_in_flight(&self, level: Level) -> bool {
        self.entries
            .iter()
            .any(|p| p.level == level && p.ack_eliciting && p.in_flight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkt(pn: u64, level: Level, time_sent: Instant, size: u16) -> SentPacket {
        SentPacket {
            pn,
            level,
            time_sent,
            size,
            ack_eliciting: true,
            in_flight: true,
        }
    }

    /// Dense storage uses `swap_remove`, which reorders entries. Verify that
    /// across several partial acks the *exact* set of remaining packets is
    /// preserved (no loss or duplication from the reordering).
    #[test]
    fn dense_partial_acks_preserve_set() {
        let mut tracker = SentPacketTracker::<32>::new();
        for pn in 0..10u64 {
            tracker
                .on_packet_sent(make_pkt(pn, Level::Application, pn * 10, 100))
                .unwrap();
        }
        // Ack a scattered middle range: largest=7, first_range=2 -> {5,6,7}.
        let r = tracker.on_ack_received(Level::Application, 7, 2, &[]);
        assert_eq!(r.newly_acked.len(), 3);
        assert_eq!(tracker.count(), 7);

        // Remaining must be exactly {0,1,2,3,4,8,9}.
        let mut remaining: heapless::Vec<u64, 32> = tracker
            .sent_below_pn(Level::Application, u64::MAX)
            .map(|p| p.pn)
            .collect();
        remaining.sort_unstable();
        assert_eq!(remaining.as_slice(), &[0, 1, 2, 3, 4, 8, 9]);

        // Ack the rest and confirm the tracker drains exactly.
        let r2 = tracker.on_ack_received(Level::Application, 9, 9, &[]);
        assert_eq!(r2.newly_acked.len(), 7);
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn track_and_ack_packets() {
        let mut tracker = SentPacketTracker::<16>::new();
        assert_eq!(tracker.count(), 0);

        tracker
            .on_packet_sent(make_pkt(0, Level::Initial, 100, 1200))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Initial, 200, 1200))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(2, Level::Initial, 300, 1200))
            .unwrap();
        assert_eq!(tracker.count(), 3);

        // ACK packets 0-2
        let result = tracker.on_ack_received(Level::Initial, 2, 2, &[]);
        assert_eq!(result.newly_acked.len(), 3);
        assert_eq!(result.largest_newly_acked.unwrap().pn, 2);
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn ack_with_gaps() {
        let mut tracker = SentPacketTracker::<16>::new();
        for pn in 0..6 {
            tracker
                .on_packet_sent(make_pkt(pn, Level::Application, pn * 100, 100))
                .unwrap();
        }
        assert_eq!(tracker.count(), 6);

        // ACK largest=5, first_range=0 (acks just 5),
        // then gap=1, range=1 (acks 2-3)
        // gap means: skip (gap+1) packets below the previous range's smallest.
        // Previous smallest = 5. gap=1 => skip 2 PNs (4 and 3... no, let's recalculate).
        // Actually: previous smallest = 5 (largest_ack - first_ack_range = 5 - 0 = 5).
        // gap=1 means range_largest = 5 - 1 - 2 = 2, range_smallest = 2 - 1 = 1.
        // So this ACKs: {5} and {1, 2}
        let result = tracker.on_ack_received(Level::Application, 5, 0, &[(1, 1)]);
        assert_eq!(result.newly_acked.len(), 3);
        let acked_pns: heapless::Vec<u64, 32> = result.newly_acked.iter().map(|p| p.pn).collect();
        assert!(acked_pns.contains(&5));
        assert!(acked_pns.contains(&1));
        assert!(acked_pns.contains(&2));
        assert_eq!(tracker.count(), 3); // 0, 3, 4 remain
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn capacity_limit() {
        let mut tracker = SentPacketTracker::<4>::new();
        for pn in 0..4 {
            tracker
                .on_packet_sent(make_pkt(pn, Level::Initial, pn * 100, 100))
                .unwrap();
        }
        let err = tracker.on_packet_sent(make_pkt(4, Level::Initial, 400, 100));
        assert!(err.is_err());
    }

    #[test]
    fn sent_before_filtering() {
        let mut tracker = SentPacketTracker::<16>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Initial, 100, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Initial, 200, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(2, Level::Initial, 300, 100))
            .unwrap();

        let before_250: heapless::Vec<&SentPacket, 16> =
            tracker.sent_before(Level::Initial, 250).collect();
        assert_eq!(before_250.len(), 2);
        assert!(before_250.iter().all(|p| p.time_sent < 250));
    }

    #[test]
    fn sent_below_pn_filtering() {
        let mut tracker = SentPacketTracker::<16>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Application, 100, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Application, 200, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(5, Level::Application, 300, 100))
            .unwrap();

        let below_3: heapless::Vec<&SentPacket, 16> =
            tracker.sent_below_pn(Level::Application, 3).collect();
        assert_eq!(below_3.len(), 2);
    }

    #[test]
    fn drop_space_removes_all() {
        let mut tracker = SentPacketTracker::<16>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Initial, 100, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Handshake, 200, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(2, Level::Application, 300, 100))
            .unwrap();
        assert_eq!(tracker.count(), 3);

        tracker.drop_space(Level::Initial);
        assert_eq!(tracker.count(), 2);
        assert!(!tracker.has_ack_eliciting_in_flight(Level::Initial));
        assert!(tracker.has_ack_eliciting_in_flight(Level::Handshake));
    }

    #[test]
    fn has_ack_eliciting_in_flight_correctness() {
        let mut tracker = SentPacketTracker::<16>::new();
        assert!(!tracker.has_ack_eliciting_in_flight(Level::Initial));

        tracker
            .on_packet_sent(make_pkt(0, Level::Initial, 100, 100))
            .unwrap();
        assert!(tracker.has_ack_eliciting_in_flight(Level::Initial));
        assert!(!tracker.has_ack_eliciting_in_flight(Level::Handshake));

        // Add a non-ack-eliciting packet
        let mut non_ae = make_pkt(1, Level::Handshake, 200, 100);
        non_ae.ack_eliciting = false;
        tracker.on_packet_sent(non_ae).unwrap();
        assert!(!tracker.has_ack_eliciting_in_flight(Level::Handshake));
    }

    #[test]
    fn remove_packet() {
        let mut tracker = SentPacketTracker::<16>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Initial, 100, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Initial, 200, 100))
            .unwrap();

        let removed = tracker.remove(Level::Initial, 0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pn, 0);
        assert_eq!(tracker.count(), 1);

        // Removing again returns None
        assert!(tracker.remove(Level::Initial, 0).is_none());
    }

    #[test]
    fn ack_wrong_level_is_noop() {
        let mut tracker = SentPacketTracker::<16>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Initial, 100, 100))
            .unwrap();

        let result = tracker.on_ack_received(Level::Application, 0, 0, &[]);
        assert_eq!(result.newly_acked.len(), 0);
        assert_eq!(tracker.count(), 1);
    }
}
