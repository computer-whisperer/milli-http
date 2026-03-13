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
pub struct SentPacketTracker<const N: usize = 128> {
    #[cfg(not(feature = "alloc"))]
    entries: [Option<SentPacket>; N],
    #[cfg(feature = "alloc")]
    entries: alloc::vec::Vec<Option<SentPacket>>,
    count: usize,
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
            entries: [None; N],
            #[cfg(feature = "alloc")]
            entries: alloc::vec::Vec::new(),
            count: 0,
        }
    }

    /// Record a sent packet.
    pub fn on_packet_sent(&mut self, pkt: SentPacket) -> Result<(), Error> {
        // Find an empty slot.
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(pkt);
                self.count += 1;
                return Ok(());
            }
        }
        #[cfg(not(feature = "alloc"))]
        return Err(Error::BufferTooSmall { needed: N + 1 });
        #[cfg(feature = "alloc")]
        {
            if self.entries.len() >= N {
                return Err(Error::BufferTooSmall { needed: N + 1 });
            }
            self.entries.push(Some(pkt));
            self.count += 1;
            Ok(())
        }
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

        for slot in self.entries.iter_mut() {
            if let Some(pkt) = slot {
                if pkt.level != level {
                    continue;
                }
                // Check if this packet's PN falls in any acked range.
                let pn = pkt.pn;
                let is_acked = acked_ranges.iter().any(|&(lo, hi)| pn >= lo && pn <= hi);
                if is_acked {
                    let p = *pkt;
                    let _ = result.newly_acked.push(p);
                    match result.largest_newly_acked {
                        None => result.largest_newly_acked = Some(p),
                        Some(ref prev) if p.pn > prev.pn => {
                            result.largest_newly_acked = Some(p);
                        }
                        _ => {}
                    }
                    *slot = None;
                    self.count -= 1;
                }
            }
        }

        result
    }

    /// Get all packets in a given space that were sent before `before`.
    pub fn sent_before(&self, level: Level, before: Instant) -> impl Iterator<Item = &SentPacket> {
        self.entries.iter().filter_map(move |slot| {
            slot.as_ref()
                .filter(|p| p.level == level && p.time_sent < before)
        })
    }

    /// Get all packets with PN less than threshold in a given space.
    pub fn sent_below_pn(
        &self,
        level: Level,
        pn_threshold: u64,
    ) -> impl Iterator<Item = &SentPacket> {
        self.entries.iter().filter_map(move |slot| {
            slot.as_ref()
                .filter(|p| p.level == level && p.pn < pn_threshold)
        })
    }

    /// Remove a packet (after declaring it lost or acked).
    pub fn remove(&mut self, level: Level, pn: u64) -> Option<SentPacket> {
        for slot in self.entries.iter_mut() {
            if let Some(pkt) = slot
                && pkt.level == level
                && pkt.pn == pn
            {
                let p = *pkt;
                *slot = None;
                self.count -= 1;
                return Some(p);
            }
        }
        None
    }

    /// Drop all packets in a packet number space.
    pub fn drop_space(&mut self, level: Level) {
        for slot in self.entries.iter_mut() {
            if let Some(pkt) = slot
                && pkt.level == level
            {
                *slot = None;
                self.count -= 1;
            }
        }
    }

    /// Number of tracked packets.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Any ack-eliciting packets in flight for this space?
    pub fn has_ack_eliciting_in_flight(&self, level: Level) -> bool {
        self.entries.iter().any(|slot| {
            slot.as_ref()
                .is_some_and(|p| p.level == level && p.ack_eliciting && p.in_flight)
        })
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
