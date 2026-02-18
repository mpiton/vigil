use std::cmp::Ordering;
use std::fmt::Write;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::process::ProcessInfo;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

fn top_processes_by_cpu(snapshot: &SystemSnapshot, n: usize) -> Vec<&ProcessInfo> {
    let mut procs: Vec<&ProcessInfo> = snapshot.processes.iter().collect();
    procs.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(Ordering::Equal)
    });
    procs.truncate(n);
    procs
}

pub struct CpuOverloadRule;

impl Rule for CpuOverloadRule {
    fn name(&self) -> &'static str {
        "cpu_overload"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        let cpu = &snapshot.cpu;
        let max_load = thresholds.cpu_load_factor * f64::from(cpu.core_count);

        if cpu.load_avg_5m >= max_load {
            let top = top_processes_by_cpu(snapshot, 5);

            let mut details = String::from("Top consommateurs CPU :\n");
            for p in &top {
                let _ = writeln!(
                    details,
                    "  PID {} ({}) — CPU {:.1}%, RAM {} MB",
                    p.pid, p.name, p.cpu_percent, p.rss_mb
                );
            }

            vec![Alert {
                timestamp: snapshot.timestamp,
                severity: Severity::High,
                rule: "cpu_overload".to_string(),
                title: format!(
                    "CPU surchargé : load {:.2}/{:.2}/{:.2} ({} cœurs, seuil: {:.1})",
                    cpu.load_avg_1m, cpu.load_avg_5m, cpu.load_avg_15m, cpu.core_count, max_load,
                ),
                details,
                suggested_actions: vec![],
            }]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use chrono::Utc;

    fn make_process(pid: u32, name: &str, cpu_percent: f32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            name: name.to_string(),
            cmdline: format!("/usr/bin/{name}"),
            state: ProcessState::Running,
            cpu_percent,
            rss_mb: 100,
            vms_mb: 200,
            user: "user".to_string(),
            start_time: 0,
            open_fds: 10,
        }
    }

    fn make_snapshot(
        load_avg_1m: f64,
        load_avg_5m: f64,
        load_avg_15m: f64,
        core_count: u32,
        processes: Vec<ProcessInfo>,
    ) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8192,
                available_mb: 8192,
                swap_total_mb: 0,
                swap_used_mb: 0,
                usage_percent: 50.0,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 50.0,
                per_core_usage: vec![50.0; core_count as usize],
                core_count,
                load_avg_1m,
                load_avg_5m,
                load_avg_15m,
            },
            processes,
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[test]
    fn rule_name() {
        assert_eq!(CpuOverloadRule.name(), "cpu_overload");
    }

    #[test]
    fn no_alert_when_load_low() {
        let rule = CpuOverloadRule;
        // default factor 1.5, 4 cores → threshold 6.0; load 3.0 < 6.0
        let snapshot = make_snapshot(2.0, 3.0, 2.5, 4, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_when_load_high() {
        let rule = CpuOverloadRule;
        // default factor 1.5, 4 cores → threshold 6.0; load 7.0 > 6.0
        let snapshot = make_snapshot(7.5, 7.0, 6.5, 4, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].rule, "cpu_overload");
    }

    #[test]
    fn alert_at_exact_threshold() {
        let rule = CpuOverloadRule;
        // default factor 1.5, 4 cores → threshold 6.0; load == 6.0 triggers (uses >=)
        let snapshot = make_snapshot(6.0, 6.0, 6.0, 4, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn alert_includes_top_processes() {
        let rule = CpuOverloadRule;
        let processes = vec![
            make_process(100, "firefox", 80.0),
            make_process(101, "chrome", 60.0),
            make_process(102, "vscode", 40.0),
            make_process(103, "slack", 20.0),
            make_process(104, "docker", 10.0),
            make_process(105, "node", 5.0),
        ];
        // 4 cores, factor 1.5 → threshold 6.0; load 8.0 > 6.0
        let snapshot = make_snapshot(8.0, 8.0, 7.0, 4, processes);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let details = &alerts[0].details;
        assert!(details.contains("firefox"));
        assert!(details.contains("chrome"));
        assert!(details.contains("vscode"));
        assert!(details.contains("slack"));
        assert!(details.contains("docker"));
        assert!(!details.contains("node"));
    }

    #[test]
    fn alert_scales_with_core_count() {
        let rule = CpuOverloadRule;
        // 8 cores, factor 1.5 → threshold 12.0
        // load 11.9 should NOT trigger
        let snapshot_below = make_snapshot(11.0, 11.9, 10.0, 8, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot_below, &thresholds);
        assert!(alerts.is_empty());

        // load 12.1 should trigger
        let snapshot_above = make_snapshot(12.5, 12.1, 11.0, 8, vec![]);
        let alerts = rule.evaluate(&snapshot_above, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("8 cœurs"));
        assert!(alerts[0].title.contains("12.0"));
    }
}
