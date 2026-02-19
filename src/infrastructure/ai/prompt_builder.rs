use std::fmt::Write;

use crate::domain::entities::{Alert, SystemSnapshot};

pub struct PromptBuilder;

impl PromptBuilder {
    #[must_use]
    pub fn build(snapshot: &SystemSnapshot, alerts: &[Alert]) -> String {
        let mut prompt = String::with_capacity(4096);

        prompt.push_str(
            "You are Vigil, an AI-powered Linux system health analyzer. \
             Analyze the following system state and provide a diagnostic.\n\n",
        );

        let mem = &snapshot.memory;
        let _ = write!(
            prompt,
            "## System Memory\n\
             - total_mb: {}\n\
             - used_mb: {}\n\
             - available_mb: {}\n\
             - usage_percent: {:.1}%\n\
             - swap_total_mb: {}\n\
             - swap_used_mb: {}\n\
             - swap_percent: {:.1}%\n\n",
            mem.total_mb,
            mem.used_mb,
            mem.available_mb,
            mem.usage_percent,
            mem.swap_total_mb,
            mem.swap_used_mb,
            mem.swap_percent,
        );

        let cpu = &snapshot.cpu;
        let _ = write!(
            prompt,
            "## CPU\n\
             - global_usage_percent: {:.1}%\n\
             - core_count: {}\n\
             - load_avg_1m: {:.2}\n\
             - load_avg_5m: {:.2}\n\
             - load_avg_15m: {:.2}\n\n",
            cpu.global_usage_percent,
            cpu.core_count,
            cpu.load_avg_1m,
            cpu.load_avg_5m,
            cpu.load_avg_15m,
        );

        prompt.push_str("## Top Processes (by memory)\n");
        let mut top_procs: Vec<&_> = snapshot.processes.iter().collect();
        top_procs.sort_unstable_by(|a, b| b.rss_mb.cmp(&a.rss_mb));
        for proc in top_procs.iter().take(5) {
            let _ = writeln!(
                prompt,
                "- PID {} {}: {} MB RAM, {:.1}% CPU ({})",
                proc.pid, proc.name, proc.rss_mb, proc.cpu_percent, proc.state,
            );
        }
        prompt.push('\n');

        prompt.push_str("## Disks\n");
        for disk in &snapshot.disks {
            let _ = writeln!(
                prompt,
                "- {}: {:.1}% used, {:.1} GB free ({})",
                disk.mount_point, disk.usage_percent, disk.available_gb, disk.filesystem,
            );
        }
        prompt.push('\n');

        prompt.push_str("## Recent Journal Entries\n");
        for entry in snapshot.journal_entries.iter().rev().take(10) {
            let _ = writeln!(
                prompt,
                "- [{}] {}: {}",
                entry.priority, entry.unit, entry.message,
            );
        }
        prompt.push('\n');

        prompt.push_str("## Active Alerts\n");
        for alert in alerts {
            let _ = writeln!(
                prompt,
                "- [{}] {}: {} — {}",
                alert.severity, alert.rule, alert.title, alert.details,
            );
        }
        prompt.push('\n');

        prompt.push_str(
            "Respond ONLY with a JSON object matching this exact structure:\n\
             {\"summary\": \"one-line diagnostic summary\", \
             \"details\": \"detailed analysis and recommendations\", \
             \"severity\": \"Low|Medium|High|Critical\", \
             \"confidence\": 0.85}\n",
        );

        prompt
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::domain::entities::alert::{Alert, SuggestedAction};
    use crate::domain::entities::{
        CpuInfo, DiskInfo, JournalEntry, MemoryInfo, ProcessInfo, ProcessState, SystemSnapshot,
    };
    use crate::domain::value_objects::{ActionRisk, Severity};

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 12000,
                available_mb: 4384,
                swap_total_mb: 8192,
                swap_used_mb: 512,
                usage_percent: 73.2,
                swap_percent: 6.3,
            },
            cpu: CpuInfo {
                global_usage_percent: 55.3,
                per_core_usage: vec![60.0, 50.0, 55.0, 56.0],
                core_count: 4,
                load_avg_1m: 2.1,
                load_avg_5m: 1.8,
                load_avg_15m: 1.5,
            },
            processes: vec![
                ProcessInfo {
                    pid: 1001,
                    ppid: 1,
                    name: "firefox".to_string(),
                    cmdline: "/usr/bin/firefox".to_string(),
                    state: ProcessState::Running,
                    cpu_percent: 15.2,
                    rss_mb: 2048,
                    vms_mb: 4096,
                    user: "user".to_string(),
                    start_time: 1000,
                    open_fds: 200,
                },
                ProcessInfo {
                    pid: 1002,
                    ppid: 1,
                    name: "code".to_string(),
                    cmdline: "/usr/bin/code".to_string(),
                    state: ProcessState::Sleeping,
                    cpu_percent: 8.5,
                    rss_mb: 1024,
                    vms_mb: 2048,
                    user: "user".to_string(),
                    start_time: 1100,
                    open_fds: 150,
                },
            ],
            disks: vec![DiskInfo {
                mount_point: "/".to_string(),
                total_gb: 500.0,
                available_gb: 120.5,
                usage_percent: 75.9,
                filesystem: "ext4".to_string(),
            }],
            journal_entries: vec![JournalEntry {
                timestamp: Utc::now(),
                priority: 3,
                unit: "sshd.service".to_string(),
                message: "Connection accepted".to_string(),
            }],
        }
    }

    fn make_alert() -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity: Severity::High,
            rule: "ram_critical".to_string(),
            title: "High memory usage".to_string(),
            details: "RAM usage at 95%".to_string(),
            suggested_actions: vec![SuggestedAction {
                description: "Kill heavy process".to_string(),
                command: "kill -9 1234".to_string(),
                risk: ActionRisk::Dangerous,
            }],
        }
    }

    #[test]
    fn prompt_contains_memory_metrics() {
        let snapshot = make_snapshot();
        let prompt = PromptBuilder::build(&snapshot, &[]);
        assert!(prompt.contains("12000"));
        assert!(prompt.contains("16384"));
        assert!(prompt.contains("4384"));
        assert!(prompt.contains("73.2"));
    }

    #[test]
    fn prompt_contains_cpu_metrics() {
        let snapshot = make_snapshot();
        let prompt = PromptBuilder::build(&snapshot, &[]);
        assert!(prompt.contains("2.10"));
        assert!(prompt.contains("1.80"));
        assert!(prompt.contains("1.50"));
        assert!(prompt.contains("core_count: 4"));
    }

    #[test]
    fn prompt_contains_alerts() {
        let snapshot = make_snapshot();
        let alert = make_alert();
        let prompt = PromptBuilder::build(&snapshot, &[alert]);
        assert!(prompt.contains("High memory usage"));
        assert!(prompt.contains("ram_critical"));
        assert!(prompt.contains("HIGH"));
    }

    #[test]
    fn prompt_handles_empty_alerts() {
        let snapshot = make_snapshot();
        let prompt = PromptBuilder::build(&snapshot, &[]);
        assert!(prompt.contains("## Active Alerts"));
    }

    #[test]
    fn prompt_handles_empty_processes() {
        let mut snapshot = make_snapshot();
        snapshot.processes.clear();
        let prompt = PromptBuilder::build(&snapshot, &[]);
        assert!(prompt.contains("## Top Processes (by memory)"));
    }

    #[test]
    fn prompt_contains_json_format_instruction() {
        let snapshot = make_snapshot();
        let prompt = PromptBuilder::build(&snapshot, &[]);
        assert!(prompt.contains("JSON"));
        assert!(prompt.contains("summary"));
        assert!(prompt.contains("severity"));
    }
}
