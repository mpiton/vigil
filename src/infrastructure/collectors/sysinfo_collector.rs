use std::sync::Mutex;

use sysinfo::System;

use super::disk_collector::DiskCollector;
use crate::domain::entities::{
    process::{ProcessInfo, ProcessState},
    snapshot::{CpuInfo, MemoryInfo, SystemSnapshot},
};
use crate::domain::ports::collector::{CollectionError, SystemCollector};

const BYTES_PER_MB: u64 = 1_048_576;

/// Returns `(numerator / denominator) * 100.0`, or `0.0` when `denominator` is zero.
#[allow(clippy::cast_precision_loss)]
fn safe_percent(numerator: u64, denominator: u64) -> f64 {
    if denominator > 0 {
        (numerator as f64 / denominator as f64) * 100.0
    } else {
        0.0
    }
}

/// Returns the arithmetic mean of `per_core` usages, or `0.0` when the slice is empty.
#[allow(clippy::cast_precision_loss)]
fn avg_cpu_usage(per_core: &[f32]) -> f32 {
    let count = per_core.len();
    if count > 0 {
        per_core.iter().sum::<f32>() / count as f32
    } else {
        0.0
    }
}

/// Collects system metrics using the `sysinfo` crate.
///
/// Uses `Mutex<System>` for interior mutability since the `SystemCollector`
/// trait requires `&self` but `sysinfo::System` needs `&mut self` for refresh.
pub struct SysinfoCollector {
    sys: Mutex<System>,
    disk_collector: DiskCollector,
}

impl SysinfoCollector {
    /// Creates a new collector with pre-initialized system data.
    #[must_use]
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys: Mutex::new(sys),
            disk_collector: DiskCollector::new(),
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

        let disks = self.disk_collector.collect()?;

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

fn collect_memory(sys: &System) -> MemoryInfo {
    let total = sys.total_memory();
    let used = sys.used_memory();
    let available = sys.available_memory();
    let swap_total = sys.total_swap();
    let swap_used = sys.used_swap();

    MemoryInfo {
        total_mb: total / BYTES_PER_MB,
        used_mb: used / BYTES_PER_MB,
        available_mb: available / BYTES_PER_MB,
        swap_total_mb: swap_total / BYTES_PER_MB,
        swap_used_mb: swap_used / BYTES_PER_MB,
        usage_percent: safe_percent(used, total),
        swap_percent: safe_percent(swap_used, swap_total),
    }
}

fn collect_cpu(sys: &System) -> CpuInfo {
    let cpus = sys.cpus();
    let per_core_usage: Vec<f32> = cpus.iter().map(sysinfo::Cpu::cpu_usage).collect();
    let core_count = u32::try_from(cpus.len()).unwrap_or(u32::MAX);
    let global_usage = avg_cpu_usage(&per_core_usage);

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

/// Counts open file descriptors for a process by reading `/proc/<pid>/fd`.
///
/// Linux-only: returns 0 on other platforms or if the directory is unreadable.
#[cfg(target_os = "linux")]
fn count_open_fds(pid: u32) -> u64 {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_or(0, |entries| entries.filter_map(Result::ok).count() as u64)
}

#[cfg(not(target_os = "linux"))]
fn count_open_fds(_pid: u32) -> u64 {
    0
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
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::Unknown(999)),
            ProcessState::Unknown
        );
        assert_eq!(
            map_process_status(sysinfo::ProcessStatus::LockBlocked),
            ProcessState::Unknown
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
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
    fn safe_percent_returns_zero_for_zero_denominator() {
        assert!((safe_percent(100, 0) - 0.0).abs() < f64::EPSILON);
        assert!((safe_percent(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_percent_computes_correctly() {
        assert!((safe_percent(50, 100) - 50.0).abs() < f64::EPSILON);
        assert!((safe_percent(1, 4) - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn avg_cpu_usage_returns_zero_for_empty_slice() {
        assert!((avg_cpu_usage(&[]) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn avg_cpu_usage_computes_mean() {
        let usage = avg_cpu_usage(&[10.0, 20.0, 30.0]);
        assert!((usage - 20.0).abs() < f32::EPSILON);
    }

    #[test]
    fn collect_returns_error_on_poisoned_mutex() {
        let collector = SysinfoCollector::new();

        // Poison the mutex by panicking while holding the lock guard.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = collector.sys.lock().expect("not yet poisoned");
            panic!("intentional panic to poison the mutex");
        }));

        let result = collector.collect();
        assert!(result.is_err(), "collect should fail on poisoned mutex");
    }

    #[test]
    fn default_creates_valid_collector() {
        let collector = SysinfoCollector::default();
        let snapshot = collector.collect().expect("default collector should work");
        assert!(snapshot.memory.total_mb > 0);
    }

    #[test]
    fn kernel_threads_have_bracket_wrapped_names() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");

        // Kernel threads have empty cmd() so their cmdline is wrapped in brackets
        assert!(
            snapshot
                .processes
                .iter()
                .any(|p| p.cmdline.starts_with('[') && p.cmdline.ends_with(']')),
            "should have kernel threads with bracket-wrapped names"
        );
    }

    #[test]
    fn snapshot_includes_disks() {
        let collector = SysinfoCollector::new();
        let snapshot = collector.collect().expect("collect should succeed");
        // May be empty in container environments; validate entries if present.
        for disk in &snapshot.disks {
            assert!(disk.total_gb > 0.0, "real disk should have positive size");
        }
    }
}
