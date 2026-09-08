//! Shared move-timing calibration.
//!
//! Smart cubes report move timestamps from their own oscillator, and some of
//! them run measurably fast or slow — GAN Gen1 is off by about 5%. Solve times
//! therefore cannot come from the cube's clock directly; they are corrected
//! against the host clock, which is the reference source.
//!
//! This logic used to live inline in the native connection handler, which meant
//! the web build reported raw uncalibrated cube time. It is transport-agnostic,
//! so both backends share it.

use crate::common::TimedMove;
use instant::{Duration, Instant};

/// Gap between moves beyond which calibration is not updated. Cubes with a
/// narrow timestamp encoding can wrap or saturate across a long idle period, so
/// the elapsed real time is used directly instead of adjusting the ratio.
const CALIBRATION_RESET_SECS: u64 = 30;

pub(crate) struct ClockCalibration {
    start_time: Option<Instant>,
    last_move_time: Option<Instant>,
    current_duration: Duration,
    total_raw_ticks: u64,
    total_real_ticks: u64,
    clock_ratio: f64,
    clock_ratio_range: (f64, f64),
}

impl ClockCalibration {
    pub(crate) fn new(clock_ratio: f64, clock_ratio_range: (f64, f64)) -> Self {
        Self {
            start_time: None,
            last_move_time: None,
            current_duration: Duration::from_secs(0),
            total_raw_ticks: 0,
            total_real_ticks: 0,
            clock_ratio,
            clock_ratio_range,
        }
    }

    /// Rewrite a batch of cube-reported moves so their inter-move deltas track
    /// real time, and fold the batch into the running clock-ratio estimate.
    pub(crate) fn adjust(&mut self, moves: Vec<TimedMove>) -> Vec<TimedMove> {
        let now = Instant::now();
        let mut last_duration = self.current_duration;

        // Check length of time since last move
        let mut calibration_reset = false;
        if let Some(last_move_time) = self.last_move_time {
            let delta = now - last_move_time;
            if delta.as_secs() > CALIBRATION_RESET_SECS {
                calibration_reset = true;
                self.current_duration += delta;
            }
        }

        // Go through the move list and adjust the timing information
        let mut adjusted_moves = Vec::new();
        let mut new_raw_ticks = 0;
        for raw_move in moves {
            let mv = raw_move.move_();
            let raw_time = raw_move.time();

            if !calibration_reset {
                new_raw_ticks += raw_time;

                // Adjust delta using clock ratio. This will be adjusted over
                // time to be calibrated to real time.
                let adjusted_delta = Duration::from_nanos(
                    ((raw_time as u64 * 1_000_000) as f64 / self.clock_ratio) as u64,
                );
                self.current_duration += adjusted_delta;
            }

            let adjusted_time =
                self.current_duration.as_millis() - last_duration.as_millis();
            last_duration = self.current_duration;
            adjusted_moves.push(TimedMove::new(mv, adjusted_time as u32));
        }

        // Update calibration state
        if let Some(start_time) = self.start_time {
            if calibration_reset {
                // Calibration is being reset because of too much time between
                // moves. Measure from this move forward.
                self.start_time = Some(now);
                self.total_raw_ticks = 0;
                self.total_real_ticks = 0;
            } else {
                // Update the calibration with the number of milliseconds
                // reported in the raw data and the number of milliseconds that
                // have actually passed.
                self.total_raw_ticks += new_raw_ticks as u64;
                self.total_real_ticks = (now - start_time).as_millis() as u64;

                let computed_clock_ratio =
                    (self.total_raw_ticks as f64) / (self.total_real_ticks as f64);

                // Clamp ratio to a range for sanity check
                self.clock_ratio = computed_clock_ratio
                    .max(self.clock_ratio_range.0)
                    .min(self.clock_ratio_range.1);
            }
        } else {
            // First move, record start time
            self.start_time = Some(now);
        }

        self.last_move_time = Some(now);
        adjusted_moves
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{CubeFace, Move};

    fn mv(time: u32) -> TimedMove {
        TimedMove::new(Move::from_face_and_rotation(CubeFace::Top, 1).unwrap(), time)
    }

    #[test]
    fn first_batch_passes_through_at_unit_ratio() {
        let mut cal = ClockCalibration::new(1.0, (0.98, 1.02));
        let out = cal.adjust(vec![mv(0), mv(500), mv(250)]);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].time(), 0);
        assert_eq!(out[1].time(), 500);
        assert_eq!(out[2].time(), 250);
    }

    #[test]
    fn slow_cube_clock_is_scaled_up() {
        // A cube whose clock runs slow (ratio < 1) under-reports elapsed time,
        // so adjusted deltas must be larger than the raw ones.
        let mut cal = ClockCalibration::new(0.95, (0.9, 1.1));
        let out = cal.adjust(vec![mv(0), mv(950)]);
        assert!(
            out[1].time() > 950,
            "expected scaled-up delta, got {}",
            out[1].time()
        );
    }

    #[test]
    fn ratio_stays_clamped_to_range() {
        // Feed absurd raw ticks; the estimate must not escape the range.
        let mut cal = ClockCalibration::new(1.0, (0.98, 1.02));
        for _ in 0..10 {
            cal.adjust(vec![mv(100_000)]);
        }
        assert!(cal.clock_ratio >= 0.98 && cal.clock_ratio <= 1.02);
    }

    #[test]
    fn move_count_is_preserved() {
        let mut cal = ClockCalibration::new(1.0, (0.98, 1.02));
        assert_eq!(cal.adjust(vec![]).len(), 0);
        assert_eq!(cal.adjust(vec![mv(10), mv(20), mv(30), mv(40)]).len(), 4);
    }
}
