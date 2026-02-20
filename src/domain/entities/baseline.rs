use serde::{Deserialize, Serialize};

/// Baseline statistics for a system metric at a specific hour of the day.
///
/// Used for anomaly detection: alerts can fire when a metric exceeds
/// `mean + 2 * stddev` for the current hour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    /// Hour of day (0–23).
    pub hour_of_day: u8,
    /// Metric name (e.g. `ram_percent`, `cpu_load`, `swap_percent`).
    pub metric: String,
    /// Running mean of observed values.
    pub mean: f64,
    /// Population standard deviation of observed values.
    pub stddev: f64,
    /// Number of samples collected.
    pub sample_count: u64,
}

impl Baseline {
    #[must_use]
    pub const fn new(
        hour_of_day: u8,
        metric: String,
        mean: f64,
        stddev: f64,
        sample_count: u64,
    ) -> Self {
        Self {
            hour_of_day,
            metric,
            mean,
            stddev,
            sample_count,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn baseline_new_creates_valid_instance() {
        let b = Baseline::new(14, "ram_percent".to_string(), 65.5, 10.2, 100);
        assert_eq!(b.hour_of_day, 14);
        assert_eq!(b.metric, "ram_percent");
        assert!((b.mean - 65.5).abs() < f64::EPSILON);
        assert!((b.stddev - 10.2).abs() < f64::EPSILON);
        assert_eq!(b.sample_count, 100);
    }

    #[test]
    fn baseline_serialization_roundtrip() {
        let b = Baseline::new(0, "cpu_load".to_string(), 2.5, 0.8, 42);
        let json = serde_json::to_string(&b).expect("serialize");
        let deserialized: Baseline = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(b, deserialized);
    }

    #[test]
    fn baseline_clone_preserves_values() {
        let b = Baseline::new(23, "swap_percent".to_string(), 15.0, 5.0, 200);
        let cloned = b.clone();
        assert_eq!(b, cloned);
    }
}
