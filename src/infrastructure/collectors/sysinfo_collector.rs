use std::sync::Mutex;

use sysinfo::{Disks, System};

use crate::domain::entities::{
    disk::DiskInfo,
    process::{ProcessInfo, ProcessState},
    snapshot::{CpuInfo, MemoryInfo, SystemSnapshot},
};
use crate::domain::ports::collector::{CollectionError, SystemCollector};

const BYTES_PER_MB: u64 = 1_048_576;
const BYTES_PER_GB: f64 = 1_073_741_824.0;

/// Filesystem types to exclude from disk metrics.
const PSEUDO_FILESYSTEMS: &[&str] = &["tmpfs", "devtmpfs", "sysfs", "proc", "cgroup2", "overlay"];

/// Collects system metrics using the `sysinfo` crate.
///
/// Uses `Mutex<System>` for interior mutability since the `SystemCollector`
/// trait requires `&self` but `sysinfo::System` needs `&mut self` for refresh.
pub struct SysinfoCollector {
    sys: Mutex<System>,
}

impl SysinfoCollector {
    /// Creates a new collector with pre-initialized system data.
    #[must_use]
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys: Mutex::new(sys),
        }
    }
}

impl Default for SysinfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCollector for SysinfoCollector {
    fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
        let mut sys = self.sys.lock().map_err(|e| {
            CollectionError::MetricsUnavailable(format!("system lock poisoned: {e}"))
        })?;
        sys.refresh_all();

        let memory = collect_memory(&sys);
        let cpu = collect_cpu(&sys);
        let processes = collect_processes(&sys);
        drop(sys);

        let disks_data = Disks::new_with_refreshed_list();
        let disks = collect_disks(&disks_data);

        Ok(SystemSnapshot {
            timestamp: chrono::Utc::now(),
            memory,
            cpu,
            processes,
            disks,
            journal_entries: Vec::new(),
        })
    }
}

#[allow(clippy::cast_precision_loss)]
fn collect_memory(sys: &System) -> MemoryInfo {
    let total = sys.total_memory();
    let used = sys.used_memory();
    let available = sys.available_memory();
    let swap_total = sys.total_swap();
    let swap_used = sys.used_swap();

    let usage_percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let swap_percent = if swap_total > 0 {
        (swap_used as f64 / swap_total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total / BYTES_PER_MB,
        used_mb: used / BYTES_PER_MB,
        available_mb: available / BYTES_PER_MB,
        swap_total_mb: swap_total / BYTES_PER_MB,
        swap_used_mb: swap_used / BYTES_PER_MB,
        usage_percent,
        swap_percent,
    }
}

#[allow(clippy::cast_precision_loss)]
fn collect_cpu(sys: &System) -> CpuInfo {
    let cpus = sys.cpus();
    let per_core_usage: Vec<f32> = cpus.iter().map(sysinfo::Cpu::cpu_usage).collect();
    let core_count = u32::try_from(cpus.len()).unwrap_or(u32::MAX);

    let global_usage = if core_count > 0 {
        per_core_usage.iter().sum::<f32>() / core_count as f32
    } else {
        0.0
    };

    let load_avg = System::load_average();

    CpuInfo {
        global_usage_percent: global_usage,
        per_core_usage,
        core_count,
        load_avg_1m: load_avg.one,
        load_avg_5m: load_avg.five,
        load_avg_15m: load_avg.fifteen,
    }
}

fn collect_processes(sys: &System) -> Vec<ProcessInfo> {
    sys.processes()
        .values()
        .map(|proc_info| {
            let state = map_process_status(proc_info.status());

            let cmdline = proc_info
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ");

            let ppid = proc_info.parent().map_or(0, sysinfo::Pid::as_u32);

            let user = proc_info
                .user_id()
                .map_or_else(|| "unknown".to_string(), |uid| uid.to_string());

            let open_fds = count_open_fds(proc_info.pid().as_u32());

            ProcessInfo {
                pid: proc_info.pid().as_u32(),
                ppid,
                name: proc_info.name().to_string_lossy().to_string(),
                cmdline: if cmdline.is_empty() {
                    format!("[{}]", proc_info.name().to_string_lossy())
                } else {
                    cmdline
                },
                state,
                cpu_percent: proc_info.cpu_usage(),
                rss_mb: proc_info.memory() / BYTES_PER_MB,
                vms_mb: proc_info.virtual_memory() / BYTES_PER_MB,
                user,
                start_time: proc_info.start_time(),
                open_fds,
            }
        })
        .collect()
}

#[allow(clippy::cast_precision_loss)]
fn collect_disks(disks: &Disks) -> Vec<DiskInfo> {
    disks
        .iter()
        .filter(|d| {
            let fs = d.file_system().to_string_lossy();
            !PSEUDO_FILESYSTEMS.iter().any(|&pseudo| fs == pseudo) && d.total_space() > 0
        })
        .map(|disk| {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);

            let usage_percent = if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            DiskInfo {
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                total_gb: total as f64 / BYTES_PER_GB,
                available_gb: available as f64 / BYTES_PER_GB,
                usage_percent,
                filesystem: disk.file_system().to_string_lossy().to_string(),
            }
        })
        .collect()
}

const fn map_process_status(status: sysinfo::ProcessStatus) -> ProcessState {
    match status {
        sysinfo::ProcessStatus::Run => ProcessState::Running,
        sysinfo::ProcessStatus::Sleep
        | sysinfo::ProcessStatus::Idle
        | sysinfo::ProcessStatus::UninterruptibleDiskSleep
        | sysinfo::ProcessStatus::Parked
        | sysinfo::ProcessStatus::Waking
        | sysinfo::ProcessStatus::Wakekill => ProcessState::Sleeping,
        sysinfo::ProcessStatus::Zombie => ProcessState::Zombie,
        sysinfo::ProcessStatus::Stop | sysinfo::ProcessStatus::Tracing => ProcessState::Stopped,
        sysinfo::ProcessStatus::Dead => ProcessState::Dead,
        _ => ProcessState::Unknown,
    }
}

fn count_open_fds(pid: u32) -> u64 {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_or(0, |entries| entries.filter_map(Result::ok).count() as u64)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_valid_snapshot() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        assert!(snapshot.memory.total_mb > 0, "total RAM should be > 0");
        assert!(snapshot.memory.usage_percent >= 0.0);
        assert!(snapshot.memory.usage_percent <= 100.0);
        assert!(snapshot.cpu.core_count > 0, "should have at least 1 core");
        assert!(
            !snapshot.processes.is_empty(),
            "should have at least 1 process"
        );
        assert!(
            snapshot.journal_entries.is_empty(),
            "journal should be empty"
        );
    }

    #[test]
    fn cpu_core_count_matches_per_core_vec() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        assert_eq!(
            snapshot.cpu.per_core_usage.len(),
            snapshot.cpu.core_count as usize
        );
    }

    #[test]
    fn processes_include_self() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        let my_pid = std::process::id();
        let me = snapshot.processes.iter().find(|p| p.pid == my_pid);
        assert!(me.is_some(), "should find own process (pid {my_pid})");

        let me = me.expect("verified above");
        assert!(!me.name.is_empty(), "process name should not be empty");
    }

    #[test]
    fn disks_exclude_pseudo_filesystems() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        for disk in &snapshot.disks {
            assert!(
                !PSEUDO_FILESYSTEMS.contains(&disk.filesystem.as_str()),
                "pseudo-filesystem {fs} should be filtered",
                fs = disk.filesystem
            );
        }
    }

    #[test]
    fn process_state_mapping() {
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Run),
            ProcessState::Running
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Sleep),
            ProcessState::Sleeping
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Idle),
            ProcessState::Sleeping
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::UninterruptibleDiskSleep),
            ProcessState::Sleeping
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Zombie),
            ProcessState::Zombie
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Stop),
            ProcessState::Stopped
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Dead),
            ProcessState::Dead
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Tracing),
            ProcessState::Stopped
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Parked),
            ProcessState::Sleeping
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Waking),
            ProcessState::Sleeping
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Wakekill),
            ProcessState::Sleeping
        );
    }

    #[test]
    fn fd_count_for_own_process() {
        let my_pid = std::process::id();
        let fds = count_open_fds(my_pid);
        assert!(fds > 0, "own process should have open file descriptors");
    }

    #[test]
    fn fd_count_returns_zero_for_invalid_pid() {
        let fds = count_open_fds(u32::MAX);
        assert_eq!(fds, 0, "invalid pid should return 0 fds");
    }

    #[test]
    fn memory_bytes_to_mb_conversion() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        // used + available should be in reasonable range relative to total
        assert!(
            snapshot.memory.used_mb <= snapshot.memory.total_mb,
            "used_mb ({used}) should not exceed total_mb ({total})",
            used = snapshot.memory.used_mb,
            total = snapshot.memory.total_mb
        );
    }

    #[test]
    fn swap_percent_zero_when_no_swap() {
        // If swap_total is 0, swap_percent should be 0.0
        // This tests the division-by-zero guard
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        if snapshot.memory.swap_total_mb == 0 {
            assert!(
                (snapshot.memory.swap_percent - 0.0).abs() < f64::EPSILON,
                "swap_percent should be 0 when no swap"
            );
        }
    }

    #[test]
    fn default_creates_valid_collector() {
        let collector = SysinfoCollector::default();
        let snapshot = collector.collect().expect("default collector should work");
        assert!(snapshot.memory.total_mb > 0);
    }
}
