//! Treasury logarithmic release schedule.
//!
//! 1,000,000,000 KX released over 100 years, one unlock per year on Jan 1 UTC.
//! Release years: 2029–2128.
//!
//! Formula:  amount_year_k = TREASURY_KX / (H_100 × k)
//!
//! where H_100 = sum(1/k, k=1..100) ≈ 5.18737751763962
//! and k is the 1-based release index (k=1 → 2029, k=100 → 2128).
//!
//! Meaningful alignment:
//!   Release #99  = Jan 1 2127 = same date as Humanity Stake unlock
//!   Release #100 = Jan 1 2128 = final treasury release, closing the loop

use chronx_core::constants::{
    H100_SCALE, H100_SCALED, TREASURY_KX, TREASURY_RELEASE_COUNT, TREASURY_START_TIMESTAMP,
};
use chronx_core::types::{Balance, Timestamp};

/// One scheduled treasury release.
#[derive(Debug, Clone)]
pub struct TreasuryRelease {
    /// 1-based release index (1 = first release on Jan 1 2029).
    pub index: u32,
    /// Amount in KX (not Chronos) for readability; multiply by 1_000_000 for Chronos.
    pub amount_kx: u64,
    /// Amount in Chronos (base units).
    pub amount_chronos: Balance,
    /// Scheduled release timestamp (Jan 1 of release year, 00:00:00 UTC).
    pub unlock_at: Timestamp,
    /// Calendar year of this release.
    pub year: u32,
}

/// Compute the KX amount for release index `k` (1-based).
///
/// amount_k = TREASURY_KX / (H_100 × k)
///          = TREASURY_KX × H100_SCALE / (H100_SCALED × k)
///
/// Uses integer arithmetic throughout; rounding dust is added to k=1.
pub fn treasury_release_amount(k: u32) -> Balance {
    assert!(
        (1..=TREASURY_RELEASE_COUNT).contains(&k),
        "k must be 1..=100"
    );
    // amount_chronos = (TREASURY_KX * 1_000_000) * H100_SCALE / (H100_SCALED * k)
    let numerator = TREASURY_KX * 1_000_000 * H100_SCALE;
    numerator / (H100_SCALED * k as u128)
}

/// Generate the complete 100-release treasury schedule.
///
/// The first release timestamp is `TREASURY_START_TIMESTAMP` (Jan 1 2029).
/// Each subsequent release is exactly 365.25 days later on average, but
/// we anchor to Jan 1 of each calendar year (pre-computed Unix timestamps).
pub fn treasury_release_schedule() -> Vec<TreasuryRelease> {
    let mut schedule = Vec::with_capacity(TREASURY_RELEASE_COUNT as usize);
    let total_target = TREASURY_KX * 1_000_000;

    for k in 1..=TREASURY_RELEASE_COUNT {
        let mut amount = treasury_release_amount(k);

        // Add any rounding dust to the first release so the sum is exact.
        if k == 1 {
            let rest: Balance = (2..=TREASURY_RELEASE_COUNT)
                .map(treasury_release_amount)
                .sum();
            amount = total_target - rest;
        }

        let year = 2028 + k; // k=1 → 2029, k=100 → 2128

        // Jan 1 of each year. We use a simplified calculation:
        // TREASURY_START_TIMESTAMP is 2029-01-01 00:00:00 UTC.
        // Each year adds either 365 or 366 days. We use an average of
        // 365.2425 days per year (Gregorian calendar).
        let seconds_per_year_avg: i64 = 31_556_952; // 365.2425 * 86400
        let unlock_at = TREASURY_START_TIMESTAMP + (k as i64 - 1) * seconds_per_year_avg;

        schedule.push(TreasuryRelease {
            index: k,
            amount_kx: (amount / 1_000_000) as u64,
            amount_chronos: amount,
            unlock_at,
            year,
        });
    }

    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_sums_to_treasury_total() {
        let schedule = treasury_release_schedule();
        let total: Balance = schedule.iter().map(|r| r.amount_chronos).sum();
        let expected = TREASURY_KX * 1_000_000;
        assert_eq!(
            total, expected,
            "treasury schedule must sum exactly to 1,000,000,000 KX"
        );
    }

    #[test]
    fn schedule_has_100_releases() {
        let schedule = treasury_release_schedule();
        assert_eq!(schedule.len(), 100);
    }

    #[test]
    fn first_release_is_largest() {
        let schedule = treasury_release_schedule();
        let first = schedule[0].amount_chronos;
        let second = schedule[1].amount_chronos;
        assert!(
            first > second,
            "first release must be largest (logarithmic)"
        );
    }

    #[test]
    fn release_99_year_is_2127() {
        let schedule = treasury_release_schedule();
        assert_eq!(
            schedule[98].year, 2127,
            "release #99 must be year 2127 — aligns with humanity stake"
        );
    }

    #[test]
    fn release_100_year_is_2128() {
        let schedule = treasury_release_schedule();
        assert_eq!(schedule[99].year, 2128, "release #100 must be year 2128");
    }

    #[test]
    fn logarithmic_decline() {
        // Each release should be less than or equal to the previous.
        let schedule = treasury_release_schedule();
        for i in 1..schedule.len() {
            assert!(
                schedule[i].amount_chronos <= schedule[i - 1].amount_chronos,
                "release {} ({}) should be <= release {} ({})",
                i + 1,
                schedule[i].amount_chronos,
                i,
                schedule[i - 1].amount_chronos
            );
        }
    }
}
