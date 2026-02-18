use anyhow::{Context, Result};
use std::collections::HashMap;
use sysinfo::{Disks, System};

use crate::types::*;

/// Collects a full system snapshot using sysinfo + /proc
pub struct SystemCollector {
    sys: System,
    disks: Disks,
}

impl SystemCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        Self { sys, disks }
    }

    /// Refresh all data sources and return a complete snapshot
    pub fn collect(&mut self) -> Result<SystemSnapshot> {
        self.sys.refresh_all();
        self.disks.refresh(true);

        let memory = self.collect_memory();
        let cpu = self.collect_cpu();
        let processes = self.collect_processes();
        let disks = self.collect_disks();

        // Journal entries collected separately (requires journalctl)
        let journal_entries = self.collect_journal().unwrap_or_default();

        Ok(SystemSnapshot {
            timestamp: chrono::Utc::now(),
            memory,
            cpu,
            processes,
            disks,
            journal_entries,
        })
    }

    fn collect_memory(&self) -> MemoryInfo {
        let total = self.sys.total_memory();
        let used = self.sys.used_memory();
        let available = self.sys.available_memory();
        let swap_total = self.sys.total_swap();
        let swap_used = self.sys.used_swap();

        let total_mb = total / 1_048_576;
        let used_mb = used / 1_048_576;

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
            total_mb,
            used_mb,
            available_mb: available / 1_048_576,
            swap_total_mb: swap_total / 1_048_576,
            swap_used_mb: swap_used / 1_048_576,
            usage_percent,
            swap_percent,
        }
    }

    fn collect_cpu(&self) -> CpuInfo {
        let cpus = self.sys.cpus();
        let per_core_usage: Vec<f32> = cpus.iter().map(|c| c.cpu_usage()).collect();
        let core_count = cpus.len();

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

    fn collect_processes(&self) -> Vec<ProcessInfo> {
        self.sys
            .processes()
            .values()
            .map(|proc| {
                let state = match proc.status() {
                    sysinfo::ProcessStatus::Run => ProcessState::Running,
                    sysinfo::ProcessStatus::Sleep
                    | sysinfo::ProcessStatus::Idle
                    | sysinfo::ProcessStatus::UninterruptibleDiskSleep => ProcessState::Sleeping,
                    sysinfo::ProcessStatus::Zombie => ProcessState::Zombie,
                    sysinfo::ProcessStatus::Stop => ProcessState::Stopped,
                    sysinfo::ProcessStatus::Dead => ProcessState::Dead,
                    _ => ProcessState::Unknown,
                };

                let cmdline = proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");

                let ppid = proc.parent().map(|p| p.as_u32()).unwrap_or(0);

                let user = proc
                    .user_id()
                    .map(|uid| uid.to_string())
                    .unwrap_or_else(|| "unknown".into());

                // Count open FDs via /proc/<pid>/fd
                let open_fds = std::fs::read_dir(format!("/proc/{}/fd", proc.pid().as_u32()))
                    .map(|entries| entries.count())
                    .unwrap_or(0);

                ProcessInfo {
                    pid: proc.pid().as_u32(),
                    ppid,
                    name: proc.name().to_string_lossy().to_string(),
                    cmdline: if cmdline.is_empty() {
                        format!("[{}]", proc.name().to_string_lossy())
                    } else {
                        cmdline
                    },
                    state,
                    cpu_percent: proc.cpu_usage(),
                    rss_mb: proc.memory() / 1_048_576,
                    vms_mb: proc.virtual_memory() / 1_048_576,
                    user,
                    start_time: proc.start_time(),
                    open_fds,
                }
            })
            .collect()
    }

    fn collect_disks(&self) -> Vec<DiskInfo> {
        self.disks
            .iter()
            .filter(|d| {
                let fs = d.file_system().to_string_lossy();
                // Filter out pseudo-filesystems
                !["tmpfs", "devtmpfs", "sysfs", "proc", "cgroup2", "overlay"]
                    .iter()
                    .any(|&pseudo| fs == pseudo)
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
                    total_gb: total as f64 / 1_073_741_824.0,
                    available_gb: available as f64 / 1_073_741_824.0,
                    usage_percent,
                    filesystem: disk.file_system().to_string_lossy().to_string(),
                }
            })
            .collect()
    }

    /// Collect recent warning/error journal entries via journalctl
    fn collect_journal(&self) -> Result<Vec<JournalEntry>> {
        let output = std::process::Command::new("journalctl")
            .args([
                "--since",
                "5 min ago",
                "--priority",
                "warning",
                "--output",
                "json",
                "--no-pager",
            ])
            .output()
            .context("Failed to run journalctl")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut entries = Vec::new();

        for line in stdout.lines() {
            if let Ok(entry) = serde_json::from_str::<HashMap<String, serde_json::Value>>(line) {
                let message = entry
                    .get("MESSAGE")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let unit = entry
                    .get("_SYSTEMD_UNIT")
                    .or_else(|| entry.get("SYSLOG_IDENTIFIER"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let priority = entry
                    .get("PRIORITY")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u8>().ok())
                    .unwrap_or(6);

                if !message.is_empty() {
                    entries.push(JournalEntry {
                        timestamp: chrono::Utc::now(),
                        priority,
                        unit,
                        message,
                    });
                }
            }
        }

        Ok(entries)
    }
}
