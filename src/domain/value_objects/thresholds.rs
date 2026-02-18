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
    pub cpu_warning: f32,
    /// CPU usage percentage that triggers a critical alert
    pub cpu_critical: f32,
    /// Disk usage percentage that triggers a warning
    pub disk_warning: f64,
    /// Disk usage percentage that triggers a critical alert
    pub disk_critical: f64,
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
        assert!((original.ram_warning - deserialized.ram_warning).abs() < f64::EPSILON);
        assert!((original.ram_critical - deserialized.ram_critical).abs() < f64::EPSILON);
    }
}
