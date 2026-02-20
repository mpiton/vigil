use chrono::Timelike;

use crate::domain::entities::baseline::Baseline;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::ports::store::{BaselineStore, StoreError};

/// Extractor function: takes a snapshot and returns a metric value.
type MetricExtractor = fn(&SystemSnapshot) -> f64;

/// Metric extractors for baseline tracking.
const BASELINE_METRICS: &[(&str, MetricExtractor)] = &[
    ("ram_percent", |s| s.memory.usage_percent),
    ("cpu_load", |s| f64::from(s.cpu.global_usage_percent)),
    ("swap_percent", |s| s.memory.swap_percent),
];

/// Update baselines incrementally using Welford's online algorithm.
///
/// For each tracked metric, reads the current baseline for the snapshot's
/// hour of day, computes the updated mean and standard deviation, and
/// persists the result.
///
/// # Errors
///
/// Returns `StoreError` if any read or write operation fails.
#[allow(clippy::cast_possible_truncation)]
pub fn update_baselines(
    store: &dyn BaselineStore,
    snapshot: &SystemSnapshot,
) -> Result<(), StoreError> {
    // hour() returns 0–23, always fits in u8
    let hour = snapshot.timestamp.hour() as u8;

    for &(metric_name, extract_fn) in BASELINE_METRICS {
        let value = extract_fn(snapshot);
        let existing = store.get_baseline(metric_name, hour)?;

        let updated = existing.map_or_else(
            || Baseline::new(hour, metric_name.to_string(), value, 0.0, 1),
            |b| welford_update(hour, metric_name, value, &b),
        );

        store.save_baseline(&updated)?;
    }
    Ok(())
}

/// Apply one step of Welford's online algorithm to update a baseline.
#[allow(clippy::cast_precision_loss)]
fn welford_update(hour: u8, metric_name: &str, value: f64, b: &Baseline) -> Baseline {
    let new_count = b.sample_count + 1;
    let delta = value - b.mean;
    let new_mean = b.mean + delta / new_count as f64;
    let delta2 = value - new_mean;
    // Reconstruct M2 from population stddev: M2 = stddev^2 * count
    let old_m2 = b.stddev.mul_add(b.stddev, 0.0) * b.sample_count as f64;
    let new_m2 = delta.mul_add(delta2, old_m2);
    let new_stddev = if new_count > 1 {
        (new_m2 / new_count as f64).sqrt()
    } else {
        0.0
    };
    Baseline::new(
        hour,
        metric_name.to_string(),
        new_mean,
        new_stddev,
        new_count,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::infrastructure::persistence::in_memory_store::InMemoryStore;
    use chrono::Utc;

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 4000,
                available_mb: 12384,
                swap_total_mb: 8192,
                swap_used_mb: 0,
                usage_percent: 50.0,
                swap_percent: 10.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 30.0,
                per_core_usage: vec![30.0],
                core_count: 4,
                load_avg_1m: 1.0,
                load_avg_5m: 0.8,
                load_avg_15m: 0.5,
            },
            processes: vec![],
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[test]
    fn update_baselines_creates_new_entries() {
        let store = InMemoryStore::new();
        let snapshot = make_snapshot();
        let result = update_baselines(&store, &snapshot);
        assert!(result.is_ok());
        let all = store.get_all_baselines().expect("get_all_baselines");
        assert_eq!(all.len(), 3);
    }

    #[allow(clippy::cast_possible_truncation)]
    #[test]
    fn update_baselines_increments_sample_count() {
        let store = InMemoryStore::new();
        let snapshot = make_snapshot();
        update_baselines(&store, &snapshot).expect("first update");
        update_baselines(&store, &snapshot).expect("second update");
        let hour = snapshot.timestamp.hour() as u8;
        let baseline = store
            .get_baseline("ram_percent", hour)
            .expect("get_baseline")
            .expect("some");
        assert_eq!(baseline.sample_count, 2);
    }

    #[allow(clippy::cast_possible_truncation)]
    #[test]
    fn update_baselines_first_entry_has_zero_stddev() {
        let store = InMemoryStore::new();
        let snapshot = make_snapshot();
        update_baselines(&store, &snapshot).expect("update");
        let hour = snapshot.timestamp.hour() as u8;
        let baseline = store
            .get_baseline("cpu_load", hour)
            .expect("get_baseline")
            .expect("some");
        assert_eq!(baseline.sample_count, 1);
        assert!((baseline.stddev - 0.0).abs() < f64::EPSILON);
    }
}
