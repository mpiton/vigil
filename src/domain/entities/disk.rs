use serde::{Deserialize, Serialize};

/// Information about a mounted disk/partition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mount_point: String,
    pub total_gb: f64,
    pub available_gb: f64,
    pub usage_percent: f64,
    pub filesystem: String,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let disk = DiskInfo {
            mount_point: "/".to_string(),
            total_gb: 500.0,
            available_gb: 200.0,
            usage_percent: 60.0,
            filesystem: "ext4".to_string(),
        };
        let json = serde_json::to_string(&disk).expect("serialize");
        let deserialized: DiskInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.mount_point, "/");
        assert!((deserialized.total_gb - 500.0).abs() < f64::EPSILON);
    }
}
