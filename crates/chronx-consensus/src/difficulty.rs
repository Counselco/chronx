use chronx_core::constants::{POW_INITIAL_DIFFICULTY, POW_MAX_DIFFICULTY, POW_MIN_DIFFICULTY};

/// Configuration and state for dynamic PoW difficulty adjustment.
///
/// Target: one transaction solve every ~10 seconds on average.
/// Difficulty adjusts every `window_size` transactions using a
/// simple ratio: new_difficulty = old * (target_ms / actual_avg_ms).
#[derive(Debug, Clone)]
pub struct DifficultyConfig {
    /// Current difficulty (leading zero bits required in SHA3-256 hash).
    pub current: u8,
    /// Target solve time in milliseconds.
    pub target_solve_ms: u64,
    /// Number of transactions per adjustment window.
    pub window_size: u32,
    /// Timestamps (ms) of transactions in the current window.
    window_samples: Vec<u64>,
}

impl Default for DifficultyConfig {
    fn default() -> Self {
        Self {
            current: POW_INITIAL_DIFFICULTY,
            target_solve_ms: 10_000, // 10 seconds
            window_size: 100,
            window_samples: Vec::new(),
        }
    }
}

impl DifficultyConfig {
    pub fn new(initial_difficulty: u8, target_solve_ms: u64, window_size: u32) -> Self {
        Self {
            current: initial_difficulty,
            target_solve_ms,
            window_size,
            window_samples: Vec::new(),
        }
    }

    /// Record a new transaction solve timestamp (Unix ms).
    /// Returns the new difficulty if an adjustment was triggered.
    pub fn record_solve(&mut self, timestamp_ms: u64) -> Option<u8> {
        self.window_samples.push(timestamp_ms);
        if self.window_samples.len() >= self.window_size as usize {
            let new_diff = adjust_difficulty(self);
            self.current = new_diff;
            self.window_samples.clear();
            return Some(new_diff);
        }
        None
    }
}

/// Compute a new difficulty from the current window of solve timestamps.
pub fn adjust_difficulty(config: &DifficultyConfig) -> u8 {
    let samples = &config.window_samples;
    if samples.len() < 2 {
        return config.current;
    }

    // Average gap between consecutive solves (ms).
    let mut total_gap = 0u64;
    for i in 1..samples.len() {
        total_gap += samples[i].saturating_sub(samples[i - 1]);
    }
    let avg_gap_ms = total_gap / (samples.len() as u64 - 1);

    if avg_gap_ms == 0 {
        return (config.current + 1).min(POW_MAX_DIFFICULTY);
    }

    // Scale difficulty proportionally: if solves are too fast, increase; too slow, decrease.
    // Use integer arithmetic: new = current * target / actual, clamped.
    let scaled = (config.current as u64)
        .saturating_mul(config.target_solve_ms)
        / avg_gap_ms;

    let new_diff = scaled.clamp(POW_MIN_DIFFICULTY as u64, POW_MAX_DIFFICULTY as u64) as u8;
    new_diff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_increases_when_too_fast() {
        let mut cfg = DifficultyConfig::new(20, 10_000, 4);
        // Simulates solves every 1 second (too fast).
        let result = cfg.record_solve(0);
        assert!(result.is_none());
        cfg.record_solve(1_000);
        cfg.record_solve(2_000);
        let new_diff = cfg.record_solve(3_000).unwrap();
        assert!(new_diff > 20, "difficulty should increase when solving too fast");
        assert!(new_diff <= POW_MAX_DIFFICULTY);
    }

    #[test]
    fn difficulty_decreases_when_too_slow() {
        let mut cfg = DifficultyConfig::new(20, 10_000, 4);
        // Simulates solves every 60 seconds (too slow).
        cfg.record_solve(0);
        cfg.record_solve(60_000);
        cfg.record_solve(120_000);
        let new_diff = cfg.record_solve(180_000).unwrap();
        assert!(new_diff < 20, "difficulty should decrease when solving too slow");
        assert!(new_diff >= POW_MIN_DIFFICULTY);
    }
}
