use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::disk::DiskInfo;
use super::journal::JournalEntry;
use super::process::ProcessInfo;

/// Complete system snapshot at a point in time
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: DateTime<Utc>,
    pub memory: MemoryInfo,
    pub cpu: CpuInfo,
    pub processes: Vec<ProcessInfo>,
    pub disks: Vec<DiskInfo>,
    pub journal_entries: Vec<JournalEntry>,
}

/// System memory usage information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub swap_total_mb: u64,
    pub swap_used_mb: u64,
    pub usage_percent: f64,
    pub swap_percent: f64,
}

/// CPU usage information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CpuInfo {
    pub global_usage_percent: f32,
    pub per_core_usage: Vec<f32>,
    pub core_count: usize,
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub load_avg_15m: f64,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn memory_info_serde_roundtrip() {
        let mem = MemoryInfo {
            total_mb: 16384,
            used_mb: 8000,
            available_mb: 8384,
            swap_total_mb: 8192,
            swap_used_mb: 100,
            usage_percent: 48.8,
            swap_percent: 1.2,
        };
        let json = serde_json::to_string(&mem).expect("serialize");
        let deserialized: MemoryInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.total_mb, 16384);
    }

    #[test]
    fn cpu_info_serde_roundtrip() {
        let cpu = CpuInfo {
            global_usage_percent: 45.5,
            per_core_usage: vec![50.0, 40.0, 45.0, 47.0],
            core_count: 4,
            load_avg_1m: 1.5,
            load_avg_5m: 1.2,
            load_avg_15m: 1.0,
        };
        let json = serde_json::to_string(&cpu).expect("serialize");
        let deserialized: CpuInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.core_count, 4);
    }

    #[test]
    fn system_snapshot_serde_roundtrip() {
        let snapshot = SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8000,
                available_mb: 8384,
                swap_total_mb: 8192,
                swap_used_mb: 100,
                usage_percent: 48.8,
                swap_percent: 1.2,
            },
            cpu: CpuInfo {
                global_usage_percent: 45.5,
                per_core_usage: vec![50.0, 40.0],
                core_count: 2,
                load_avg_1m: 1.5,
                load_avg_5m: 1.2,
                load_avg_15m: 1.0,
            },
            processes: vec![],
            disks: vec![],
            journal_entries: vec![],
        };
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let deserialized: SystemSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.cpu.core_count, 2);
        assert!(deserialized.processes.is_empty());
    }
}
