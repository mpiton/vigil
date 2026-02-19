use serde::{Deserialize, Serialize};

/// Set of thresholds for system resource monitoring
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdSet {
    /// RAM usage percentage that triggers a warning
    pub ram_warning: f64,
    /// RAM usage percentage that triggers a critical alert
    pub ram_critical: f64,
    /// Swap usage percentage that triggers a warning
    pub swap_warning: f64,
    /// Swap usage percentage that triggers a critical alert
    pub swap_critical: f64,
    /// CPU usage percentage that triggers a warning
    pub cpu_warning: f64,
    /// CPU usage percentage that triggers a critical alert
    pub cpu_critical: f64,
    /// Disk usage percentage that triggers a warning
    pub disk_warning: f64,
    /// Disk usage percentage that triggers a critical alert
    pub disk_critical: f64,
    /// CPU load factor: alert when `load_avg_5m` > factor * `core_count`
    pub cpu_load_factor: f64,
    /// Maximum number of duplicate processes before alerting
    pub max_duplicate_processes: usize,
}

impl Default for ThresholdSet {
    fn default() -> Self {
        Self {
            ram_warning: 80.0,
            ram_critical: 95.0,
            swap_warning: 50.0,
            swap_critical: 80.0,
            cpu_warning: 85.0,
            cpu_critical: 95.0,
            disk_warning: 85.0,
            disk_critical: 95.0,
            cpu_load_factor: 1.5,
            max_duplicate_processes: 5,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_thresholds_are_reasonable() {
        let t = ThresholdSet::default();
        assert!(t.ram_warning < t.ram_critical);
        assert!(t.swap_warning < t.swap_critical);
        assert!(t.cpu_warning < t.cpu_critical);
        assert!(t.disk_warning < t.disk_critical);
    }

    #[test]
    fn serde_roundtrip() {
        let original = ThresholdSet::default();
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ThresholdSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }
}
