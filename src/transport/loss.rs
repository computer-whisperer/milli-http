use crate::Instant;
use crate::crypto::Level;
use crate::transport::recovery::SentPacketTracker;

/// Time threshold for loss detection: 9/8 (RFC 9002 §6.1.2).
const TIME_THRESHOLD_NUM: u64 = 9;
const TIME_THRESHOLD_DEN: u64 = 8;

/// Packet number threshold for loss detection (RFC 9002 §6.1.1).
const PACKET_THRESHOLD: u64 = 3;

/// Minimum RTT granularity: 1ms in microseconds.
const GRANULARITY: u64 = 1_000;

/// Default initial RTT: 333ms in microseconds (RFC 9002 §6.2.2).
const DEFAULT_INITIAL_RTT: u64 = 333_000;

fn space_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::Application => 2,
    }
}

pub struct LossDetector {
    /// Largest packet number acknowledged in each space.
    largest_acked: [Option<u64>; 3],

    /// Smoothed RTT estimate (microseconds).
    smoothed_rtt: Option<u64>,
    /// RTT variance (microseconds).
    rttvar: u64,
    /// Minimum observed RTT (microseconds).
    min_rtt: u64,
    /// Most recent RTT sample (microseconds).
    latest_rtt: u64,

    /// PTO backoff exponent.
    pto_count: u32,

    /// Time of last ack-eliciting packet sent per space.
    time_of_last_ack_eliciting: [Option<Instant>; 3],

    /// Max ack delay advertised by peer (microseconds).
    max_ack_delay: u64,

    /// Loss timer deadline per space (set by detect_lost_packets).
    loss_time: [Option<Instant>; 3],
}

impl LossDetector {
    pub fn new(max_ack_delay_us: u64) -> Self {
        Self {
            largest_acked: [None; 3],
            smoothed_rtt: None,
            rttvar: 0,
            min_rtt: u64::MAX,
            latest_rtt: 0,
            pto_count: 0,
            time_of_last_ack_eliciting: [None; 3],
            max_ack_delay: max_ack_delay_us,
            loss_time: [None; 3],
        }
    }

    /// Update RTT estimates from a newly-acked packet (RFC 9002 §5.3).
    pub fn update_rtt(&mut self, latest_rtt: u64, ack_delay: u64, handshake_confirmed: bool) {
        self.latest_rtt = latest_rtt;

        if self.min_rtt == u64::MAX || latest_rtt < self.min_rtt {
            self.min_rtt = latest_rtt;
        }

        match self.smoothed_rtt {
            None => {
                // First RTT sample.
                self.smoothed_rtt = Some(latest_rtt);
                self.rttvar = latest_rtt / 2;
            }
            Some(srtt) => {
                // Limit ack_delay: only apply if handshake is confirmed,
                // and cap at max_ack_delay. Don't subtract below min_rtt.
                let adjusted_rtt = if handshake_confirmed {
                    let capped_delay = ack_delay.min(self.max_ack_delay);
                    if latest_rtt > self.min_rtt + capped_delay {
                        latest_rtt - capped_delay
                    } else {
                        latest_rtt
                    }
                } else {
                    latest_rtt
                };

                // EWMA update.
                let rttvar_sample = srtt.abs_diff(adjusted_rtt);
                self.rttvar = (3 * self.rttvar + rttvar_sample) / 4;
                self.smoothed_rtt = Some((7 * srtt + adjusted_rtt) / 8);
            }
        }
    }

    /// Record that the largest PN in a space was acked.
    pub fn on_ack_received(&mut self, level: Level, largest_acked: u64) {
        let idx = space_index(level);
        match self.largest_acked[idx] {
            None => self.largest_acked[idx] = Some(largest_acked),
            Some(prev) if largest_acked > prev => {
                self.largest_acked[idx] = Some(largest_acked);
            }
            _ => {}
        }
    }

    /// Detect lost packets based on time and PN thresholds (RFC 9002 §6.1).
    /// Returns (lost_pns, loss_timer_deadline).
    pub fn detect_lost_packets<const N: usize>(
        &mut self,
        level: Level,
        tracker: &SentPacketTracker<N>,
        now: Instant,
    ) -> (heapless::Vec<u64, 64>, Option<Instant>) {
        let idx = space_index(level);
        let largest_acked = match self.largest_acked[idx] {
            Some(la) => la,
            None => return (heapless::Vec::new(), None),
        };

        // Compute the loss delay: 9/8 * max(smoothed_rtt, latest_rtt).
        let rtt_base = self.smoothed_rtt().max(self.latest_rtt);
        let loss_delay = (rtt_base * TIME_THRESHOLD_NUM / TIME_THRESHOLD_DEN).max(GRANULARITY);

        let lost_send_time = now.saturating_sub(loss_delay);

        let mut lost_pns: heapless::Vec<u64, 64> = heapless::Vec::new();
        let mut loss_time: Option<Instant> = None;

        // Check all packets below largest_acked in this space.
        for pkt in tracker.sent_below_pn(level, largest_acked + 1) {
            // Only consider packets below largest_acked.
            if pkt.pn > largest_acked {
                continue;
            }

            // PN threshold: declared lost if largest_acked - pn >= PACKET_THRESHOLD.
            if largest_acked >= pkt.pn + PACKET_THRESHOLD {
                if lost_pns.push(pkt.pn).is_err() {
                    // Capacity full — remaining losses will be caught on next detection cycle.
                    break;
                }
                continue;
            }

            // Time threshold: declared lost if sent more than loss_delay ago.
            if pkt.time_sent <= lost_send_time {
                if lost_pns.push(pkt.pn).is_err() {
                    break;
                }
                continue;
            }

            // Not yet lost, but set loss timer for when it will be.
            let deadline = pkt.time_sent + loss_delay;
            loss_time = Some(match loss_time {
                None => deadline,
                Some(prev) => prev.min(deadline),
            });
        }

        self.loss_time[idx] = loss_time;
        (lost_pns, loss_time)
    }

    /// Compute the PTO duration (RFC 9002 §6.2.1).
    /// PTO = smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay
    pub fn pto_duration(&self) -> u64 {
        let srtt = self.smoothed_rtt();
        let rttvar = if self.smoothed_rtt.is_some() {
            self.rttvar
        } else {
            // When no RTT samples, use initial_rtt/2 as rttvar.
            DEFAULT_INITIAL_RTT / 2
        };
        srtt + (4 * rttvar).max(GRANULARITY) + self.max_ack_delay
    }

    /// Get the PTO timeout. Returns deadline if there are ack-eliciting packets in flight.
    pub fn pto_timeout<const N: usize>(&self, tracker: &SentPacketTracker<N>) -> Option<Instant> {
        let pto = self.pto_duration() * (1u64 << self.pto_count.min(62));

        // Find the most recent ack-eliciting send time across all spaces.
        let mut earliest: Option<Instant> = None;
        for &space_time in &self.time_of_last_ack_eliciting {
            if let Some(t) = space_time {
                // Only consider spaces that still have ack-eliciting packets in flight.
                // We check all three spaces; the caller should have updated time_of_last_ack_eliciting.
                earliest = Some(match earliest {
                    None => t,
                    Some(prev) => prev.min(t),
                });
            }
        }

        // Check if any space has ack-eliciting packets in flight.
        let has_ae = [Level::Initial, Level::Handshake, Level::Application]
            .iter()
            .any(|&l| tracker.has_ack_eliciting_in_flight(l));

        if !has_ae {
            return None;
        }

        // Use the most recent ack-eliciting send time.
        let mut most_recent: Option<Instant> = None;
        for &space_time in &self.time_of_last_ack_eliciting {
            if let Some(t) = space_time {
                most_recent = Some(match most_recent {
                    None => t,
                    Some(prev) => prev.max(t),
                });
            }
        }

        most_recent.map(|t| t + pto)
    }

    /// A PTO fired. Increment backoff.
    pub fn on_pto(&mut self) {
        self.pto_count += 1;
    }

    /// Reset PTO count (e.g., after receiving an ack).
    pub fn reset_pto_count(&mut self) {
        self.pto_count = 0;
    }

    /// Get the next timer deadline (min of loss timer and PTO).
    pub fn next_timeout<const N: usize>(&self, tracker: &SentPacketTracker<N>) -> Option<Instant> {
        // Find earliest loss timer across all spaces.
        let loss_timer = self.loss_time.iter().filter_map(|t| *t).min();

        let pto = self.pto_timeout(tracker);

        match (loss_timer, pto) {
            (Some(l), Some(p)) => Some(l.min(p)),
            (Some(l), None) => Some(l),
            (None, Some(p)) => Some(p),
            (None, None) => None,
        }
    }

    /// Get smoothed_rtt. Returns 333ms default if no samples.
    pub fn smoothed_rtt(&self) -> u64 {
        self.smoothed_rtt.unwrap_or(DEFAULT_INITIAL_RTT)
    }

    /// Get min_rtt.
    pub fn min_rtt(&self) -> u64 {
        self.min_rtt
    }

    /// Get latest_rtt.
    pub fn latest_rtt(&self) -> u64 {
        self.latest_rtt
    }

    /// Record time of last ack-eliciting packet sent.
    pub fn on_ack_eliciting_sent(&mut self, level: Level, now: Instant) {
        self.time_of_last_ack_eliciting[space_index(level)] = Some(now);
    }

    /// Drop a packet number space (Initial/Handshake completed).
    pub fn drop_space(&mut self, level: Level) {
        let idx = space_index(level);
        self.largest_acked[idx] = None;
        self.time_of_last_ack_eliciting[idx] = None;
        self.loss_time[idx] = None;
    }

    /// Get the current PTO count.
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::recovery::SentPacket;

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
    fn default_rtt_when_no_samples() {
        let ld = LossDetector::new(25_000);
        assert_eq!(ld.smoothed_rtt(), 333_000);
    }

    #[test]
    fn first_rtt_sample_sets_smoothed() {
        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(100_000, 0, false);
        assert_eq!(ld.smoothed_rtt(), 100_000);
        assert_eq!(ld.rttvar, 50_000); // latest_rtt / 2
        assert_eq!(ld.min_rtt, 100_000);
    }

    #[test]
    fn subsequent_rtt_samples_use_ewma() {
        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(100_000, 0, false); // srtt=100k, rttvar=50k
        ld.update_rtt(120_000, 0, false);
        // rttvar_sample = |100_000 - 120_000| = 20_000
        // rttvar = (3*50_000 + 20_000) / 4 = 42_500
        assert_eq!(ld.rttvar, 42_500);
        // srtt = (7*100_000 + 120_000) / 8 = 102_500
        assert_eq!(ld.smoothed_rtt(), 102_500);
    }

    #[test]
    fn rtt_with_ack_delay_capped() {
        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(100_000, 0, false); // first sample
        // Now with ack_delay=50_000, but max_ack_delay=25_000, handshake_confirmed=true
        // adjusted_rtt = 120_000 - 25_000 = 95_000 (since 120k > min_rtt(100k) + 25k = 125k? No.
        // min_rtt = 100_000. 120_000 > 100_000 + 25_000 = 125_000? No, 120k < 125k.
        // So adjusted_rtt = 120_000 (no subtraction since not > min_rtt + capped_delay).
        ld.update_rtt(120_000, 50_000, true);
        // No ack_delay subtracted since 120k <= 100k + 25k = 125k.
        // srtt = (7*100_000 + 120_000) / 8 = 102_500
        assert_eq!(ld.smoothed_rtt(), 102_500);

        // Now test where ack_delay does get subtracted.
        let mut ld2 = LossDetector::new(25_000);
        ld2.update_rtt(100_000, 0, false); // min_rtt=100k
        // latest_rtt=200_000, ack_delay=50_000, capped to 25_000
        // 200_000 > 100_000 + 25_000 = 125_000, so adjusted = 200_000 - 25_000 = 175_000
        ld2.update_rtt(200_000, 50_000, true);
        // srtt = (7*100_000 + 175_000) / 8 = 109_375
        assert_eq!(ld2.smoothed_rtt(), 109_375);
    }

    #[test]
    fn packet_number_threshold_loss() {
        let mut tracker = SentPacketTracker::<32>::new();
        // Send packets 0..5
        for pn in 0..5 {
            tracker
                .on_packet_sent(make_pkt(pn, Level::Application, 1000 + pn * 1000, 100))
                .unwrap();
        }

        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(50_000, 0, false);
        ld.on_ack_received(Level::Application, 4);

        // Remove acked packet 4 from tracker.
        tracker.remove(Level::Application, 4);

        let now = 1_000_000; // well after everything was sent
        let (lost, _timer) = ld.detect_lost_packets(Level::Application, &tracker, now);
        // Packets 0, 1 should be lost by PN threshold (4 - 0 >= 3, 4 - 1 >= 3).
        // Packet 2: 4 - 2 = 2 < 3, but time threshold may apply.
        assert!(lost.contains(&0));
        assert!(lost.contains(&1));
    }

    #[test]
    fn time_threshold_loss() {
        let mut tracker = SentPacketTracker::<32>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Application, 1_000, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Application, 2_000, 100))
            .unwrap();

        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(10_000, 0, false); // srtt=10_000
        ld.on_ack_received(Level::Application, 1);
        tracker.remove(Level::Application, 1);

        // loss_delay = max(10_000, 10_000) * 9/8 = 11_250
        // lost_send_time = now - 11_250
        // Packet 0 sent at 1_000. For it to be lost, now - 11_250 >= 1_000 => now >= 12_250.
        let (lost, timer) = ld.detect_lost_packets(Level::Application, &tracker, 12_250);
        assert!(lost.contains(&0));
        assert!(timer.is_none()); // all declared lost, no pending timer

        // Just before the threshold, packet should not be lost yet.
        let mut tracker2 = SentPacketTracker::<32>::new();
        tracker2
            .on_packet_sent(make_pkt(0, Level::Application, 1_000, 100))
            .unwrap();
        let mut ld2 = LossDetector::new(25_000);
        ld2.update_rtt(10_000, 0, false);
        ld2.on_ack_received(Level::Application, 1);

        let (lost2, timer2) = ld2.detect_lost_packets(Level::Application, &tracker2, 12_000);
        // 1 - 0 = 1 < 3 (no PN threshold), and 12_000 - 11_250 = 750 < 1_000 (packet 0 sent at 1000).
        // lost_send_time = 12_000 - 11_250 = 750. pkt.time_sent = 1_000 > 750. Not lost.
        assert!(lost2.is_empty());
        assert!(timer2.is_some()); // loss timer should be set
    }

    #[test]
    fn pto_duration_calculation() {
        let mut ld = LossDetector::new(25_000);
        // No RTT samples: use default 333ms, rttvar = 333ms/2 = 166_500
        // PTO = 333_000 + max(4*166_500, 1_000) + 25_000 = 333_000 + 666_000 + 25_000 = 1_024_000
        assert_eq!(ld.pto_duration(), 1_024_000);

        ld.update_rtt(100_000, 0, false);
        // srtt=100_000, rttvar=50_000
        // PTO = 100_000 + max(200_000, 1_000) + 25_000 = 325_000
        assert_eq!(ld.pto_duration(), 325_000);
    }

    #[test]
    fn pto_backoff() {
        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(100_000, 0, false);
        assert_eq!(ld.pto_count, 0);

        let base_pto = ld.pto_duration(); // 325_000

        let mut tracker = SentPacketTracker::<16>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Application, 1000, 100))
            .unwrap();
        ld.on_ack_eliciting_sent(Level::Application, 1000);

        let timeout0 = ld.pto_timeout(&tracker).unwrap();
        assert_eq!(timeout0, 1000 + base_pto); // no backoff

        ld.on_pto();
        assert_eq!(ld.pto_count, 1);
        let timeout1 = ld.pto_timeout(&tracker).unwrap();
        assert_eq!(timeout1, 1000 + base_pto * 2); // 2^1

        ld.on_pto();
        assert_eq!(ld.pto_count, 2);
        let timeout2 = ld.pto_timeout(&tracker).unwrap();
        assert_eq!(timeout2, 1000 + base_pto * 4); // 2^2

        ld.reset_pto_count();
        assert_eq!(ld.pto_count, 0);
    }

    #[test]
    fn loss_timer_deadline() {
        let mut tracker = SentPacketTracker::<32>::new();
        tracker
            .on_packet_sent(make_pkt(0, Level::Application, 1_000, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(1, Level::Application, 2_000, 100))
            .unwrap();
        tracker
            .on_packet_sent(make_pkt(2, Level::Application, 3_000, 100))
            .unwrap();

        let mut ld = LossDetector::new(25_000);
        ld.update_rtt(10_000, 0, false);
        ld.on_ack_received(Level::Application, 2);
        tracker.remove(Level::Application, 2);

        // loss_delay = 11_250
        // Packet 0: sent at 1_000. 2-0=2 < 3. Not PN lost.
        //   time check: now=5_000, lost_send_time = 5000 - 11250 = underflow → 0. 1000 > 0 → not lost.
        //   deadline = 1_000 + 11_250 = 12_250
        // Packet 1: sent at 2_000. 2-1=1 < 3. Not PN lost.
        //   deadline = 2_000 + 11_250 = 13_250
        let (lost, timer) = ld.detect_lost_packets(Level::Application, &tracker, 5_000);
        assert!(lost.is_empty());
        assert_eq!(timer, Some(12_250)); // earliest deadline
    }

    #[test]
    fn drop_space_clears_state() {
        let mut ld = LossDetector::new(25_000);
        ld.on_ack_received(Level::Initial, 5);
        ld.on_ack_eliciting_sent(Level::Initial, 1000);
        ld.loss_time[0] = Some(5000);

        ld.drop_space(Level::Initial);
        assert_eq!(ld.largest_acked[0], None);
        assert_eq!(ld.time_of_last_ack_eliciting[0], None);
        assert_eq!(ld.loss_time[0], None);
    }

    #[test]
    fn no_pto_without_ack_eliciting_in_flight() {
        let ld = LossDetector::new(25_000);
        let tracker = SentPacketTracker::<16>::new();
        assert!(ld.pto_timeout(&tracker).is_none());
    }
}
