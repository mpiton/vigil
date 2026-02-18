use std::sync::Mutex;

use sysinfo::Disks;

use crate::domain::entities::disk::DiskInfo;
use crate::domain::ports::collector::CollectionError;

const BYTES_PER_GB: f64 = 1_073_741_824.0;

/// Filesystem types to exclude from disk metrics.
const PSEUDO_FILESYSTEMS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "sysfs",
    "proc",
    "cgroup2",
    "overlay",
    "squashfs",
    "efivarfs",
    "bpf",
    "hugetlbfs",
    "mqueue",
    "pstore",
    "securityfs",
    "debugfs",
    "tracefs",
    "fusectl",
    "rpc_pipefs",
];

/// Collects disk usage information using the `sysinfo` crate.
///
/// Filters out pseudo-filesystems and zero-size disks, returning only
/// real mounted partitions with their usage metrics.
pub struct DiskCollector {
    disks: Mutex<Disks>,
}

impl DiskCollector {
    /// Creates a new collector with a pre-refreshed disk list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            disks: Mutex::new(Disks::new_with_refreshed_list()),
        }
    }

    /// Collects disk information for all real filesystems.
    ///
    /// Refreshes the disk list to pick up newly mounted/unmounted volumes,
    /// then filters out pseudo-filesystems and zero-size disks.
    ///
    /// # Errors
    ///
    /// Returns `CollectionError::MetricsUnavailable` if the internal mutex is poisoned.
    #[allow(clippy::cast_precision_loss)]
    pub fn collect(&self) -> Result<Vec<DiskInfo>, CollectionError> {
        let mut disks = self
            .disks
            .lock()
            .map_err(|e| CollectionError::MetricsUnavailable(format!("disk lock poisoned: {e}")))?;
        disks.refresh();

        Ok(disks
            .iter()
            .filter(|d| {
                let fs = d.file_system().to_string_lossy();
                !PSEUDO_FILESYSTEMS.iter().any(|&pseudo| fs == pseudo) && d.total_space() > 0
            })
            .map(|disk| {
                let total = disk.total_space();
                let available = disk.available_space();
                let used = total.saturating_sub(available);
                let usage_percent = ((used as f64 / total as f64) * 100.0).clamp(0.0, 100.0);

                DiskInfo {
                    mount_point: disk.mount_point().to_string_lossy().to_string(),
                    total_gb: total as f64 / BYTES_PER_GB,
                    available_gb: available as f64 / BYTES_PER_GB,
                    usage_percent,
                    filesystem: disk.file_system().to_string_lossy().to_string(),
                }
            })
            .collect())
    }
}

impl Default for DiskCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_disk_info() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");
        assert!(!disks.is_empty(), "should have at least one disk");
    }

    #[test]
    fn disks_exclude_pseudo_filesystems() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");

        for disk in &disks {
            assert!(
                !PSEUDO_FILESYSTEMS.contains(&disk.filesystem.as_str()),
                "pseudo-filesystem {fs} should be filtered",
                fs = disk.filesystem
            );
        }
    }

    #[test]
    fn disks_have_positive_total_space() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");

        for disk in &disks {
            assert!(
                disk.total_gb > 0.0,
                "disk {mp} should have positive total space",
                mp = disk.mount_point
            );
        }
    }

    #[test]
    fn disks_usage_percent_in_valid_range() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");

        for disk in &disks {
            assert!(
                (0.0..=100.0).contains(&disk.usage_percent),
                "disk {mp} usage {pct}% should be in [0, 100]",
                mp = disk.mount_point,
                pct = disk.usage_percent
            );
        }
    }

    #[test]
    fn disks_available_does_not_exceed_total() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");

        for disk in &disks {
            assert!(
                disk.available_gb <= disk.total_gb,
                "disk {mp}: available ({avail} GB) should not exceed total ({total} GB)",
                mp = disk.mount_point,
                avail = disk.available_gb,
                total = disk.total_gb
            );
        }
    }

    #[test]
    fn disks_have_non_empty_mount_point() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");

        for disk in &disks {
            assert!(
                !disk.mount_point.is_empty(),
                "disk should have a non-empty mount point"
            );
        }
    }

    #[test]
    fn disks_have_non_empty_filesystem() {
        let collector = DiskCollector::new();
        let disks = collector.collect().expect("collect should succeed");

        for disk in &disks {
            assert!(
                !disk.filesystem.is_empty(),
                "disk {mp} should have a non-empty filesystem type",
                mp = disk.mount_point
            );
        }
    }

    #[test]
    fn default_creates_valid_collector() {
        let collector = DiskCollector::default();
        let disks = collector.collect().expect("default collector should work");
        assert!(!disks.is_empty());
    }

    #[test]
    fn collect_returns_error_on_poisoned_mutex() {
        let collector = DiskCollector::new();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = collector.disks.lock().expect("not yet poisoned");
            panic!("intentional panic to poison the mutex");
        }));

        let result = collector.collect();
        assert!(result.is_err(), "collect should fail on poisoned mutex");
    }

    #[test]
    fn successive_collects_return_consistent_results() {
        let collector = DiskCollector::new();
        let first = collector.collect().expect("first collect should succeed");
        let second = collector.collect().expect("second collect should succeed");

        assert_eq!(
            first.len(),
            second.len(),
            "successive collects should return same number of disks"
        );
    }
}
