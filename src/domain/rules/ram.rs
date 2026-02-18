use std::fmt::Write;

use chrono::Utc;

use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::process::ProcessInfo;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

fn top_processes_by_ram(snapshot: &SystemSnapshot, n: usize) -> Vec<&ProcessInfo> {
    let mut procs: Vec<&ProcessInfo> = snapshot.processes.iter().collect();
    procs.sort_by(|a, b| b.rss_mb.cmp(&a.rss_mb));
    procs.truncate(n);
    procs
}

pub struct RamWarningRule;

impl Rule for RamWarningRule {
    fn name(&self) -> &'static str {
        "ram_warning"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        if snapshot.memory.usage_percent >= thresholds.ram_warning
            && snapshot.memory.usage_percent < thresholds.ram_critical
        {
            vec![Alert {
                timestamp: Utc::now(),
                severity: Severity::High,
                rule: "ram_warning".to_string(),
                title: format!(
                    "RAM élevée : {:.1}% utilisée ({}/{} MB)",
                    snapshot.memory.usage_percent,
                    snapshot.memory.used_mb,
                    snapshot.memory.total_mb
                ),
                details: format!(
                    "Utilisation mémoire au-dessus du seuil d'alerte ({:.0}%)",
                    thresholds.ram_warning
                ),
                suggested_actions: vec![SuggestedAction {
                    description: "Libérer le cache mémoire".to_string(),
                    command: "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches".to_string(),
                    risk: ActionRisk::Safe,
                }],
            }]
        } else {
            vec![]
        }
    }
}

pub struct RamCriticalRule;

impl Rule for RamCriticalRule {
    fn name(&self) -> &'static str {
        "ram_critical"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        if snapshot.memory.usage_percent >= thresholds.ram_critical {
            let top = top_processes_by_ram(snapshot, 5);

            let mut details = String::from("Top consommateurs RAM :\n");
            for p in &top {
                let _ = writeln!(
                    details,
                    "  PID {} ({}) — {} MB, CPU {:.1}%",
                    p.pid, p.name, p.rss_mb, p.cpu_percent
                );
            }

            let suggested_actions = top
                .iter()
                .filter(|p| p.pid > 1)
                .map(|p| SuggestedAction {
                    description: format!("Terminer {} (PID {})", p.name, p.pid),
                    command: format!("kill {}", p.pid),
                    risk: ActionRisk::Moderate,
                })
                .collect();

            vec![Alert {
                timestamp: Utc::now(),
                severity: Severity::Critical,
                rule: "ram_critical".to_string(),
                title: format!(
                    "RAM critique : {:.1}% utilisée ({}/{} MB)",
                    snapshot.memory.usage_percent,
                    snapshot.memory.used_mb,
                    snapshot.memory.total_mb
                ),
                details,
                suggested_actions,
            }]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};

    fn make_process(pid: u32, name: &str, rss_mb: u64, cpu_percent: f32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            name: name.to_string(),
            cmdline: format!("/usr/bin/{name}"),
            state: ProcessState::Running,
            cpu_percent,
            rss_mb,
            vms_mb: rss_mb * 2,
            user: "user".to_string(),
            start_time: 0,
            open_fds: 10,
        }
    }

    fn make_snapshot_with_ram(
        usage_percent: f64,
        used_mb: u64,
        total_mb: u64,
        processes: Vec<ProcessInfo>,
    ) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb,
                used_mb,
                available_mb: total_mb - used_mb,
                swap_total_mb: 0,
                swap_used_mb: 0,
                usage_percent,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 10.0,
                per_core_usage: vec![10.0],
                core_count: 1,
                load_avg_1m: 0.5,
                load_avg_5m: 0.4,
                load_avg_15m: 0.3,
            },
            processes,
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[test]
    fn warning_rule_below_threshold() {
        let rule = RamWarningRule;
        let snapshot = make_snapshot_with_ram(50.0, 8192, 16384, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn warning_rule_at_exact_threshold() {
        let rule = RamWarningRule;
        let snapshot = make_snapshot_with_ram(80.0, 13107, 16384, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn warning_rule_at_warning_level() {
        let rule = RamWarningRule;
        let snapshot = make_snapshot_with_ram(85.0, 13926, 16384, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].title.contains("85.0%"));
        assert_eq!(alerts[0].suggested_actions.len(), 1);
        assert_eq!(alerts[0].suggested_actions[0].risk, ActionRisk::Safe);
    }

    #[test]
    fn warning_rule_does_not_trigger_at_critical() {
        let rule = RamWarningRule;
        let snapshot = make_snapshot_with_ram(96.0, 15729, 16384, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn critical_rule_below_threshold() {
        let rule = RamCriticalRule;
        let snapshot = make_snapshot_with_ram(50.0, 8192, 16384, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn critical_rule_at_critical_level() {
        let rule = RamCriticalRule;
        let snapshot = make_snapshot_with_ram(96.0, 15729, 16384, vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert!(alerts[0].title.contains("96.0%"));
    }

    #[test]
    fn critical_rule_includes_top_processes() {
        let rule = RamCriticalRule;
        let processes = vec![
            make_process(100, "firefox", 2000, 10.0),
            make_process(101, "chrome", 1800, 8.0),
            make_process(102, "vscode", 1500, 5.0),
            make_process(103, "slack", 1200, 3.0),
            make_process(104, "docker", 1000, 2.0),
            make_process(105, "node", 800, 1.0),
            make_process(106, "rust-analyzer", 600, 0.5),
        ];
        let snapshot = make_snapshot_with_ram(96.0, 15729, 16384, processes);
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
        assert!(!details.contains("rust-analyzer"));
    }

    #[test]
    fn critical_rule_suggests_kill_actions() {
        let rule = RamCriticalRule;
        let processes = vec![
            make_process(100, "firefox", 2000, 10.0),
            make_process(101, "chrome", 1800, 8.0),
        ];
        let snapshot = make_snapshot_with_ram(96.0, 15729, 16384, processes);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let actions = &alerts[0].suggested_actions;
        assert_eq!(actions.len(), 2);
        assert!(actions[0].command.contains("kill 100"));
        assert!(actions[1].command.contains("kill 101"));
        assert_eq!(actions[0].risk, ActionRisk::Moderate);
    }

    #[test]
    fn critical_rule_skips_pid_1() {
        let rule = RamCriticalRule;
        let processes = vec![
            make_process(1, "init", 500, 0.1),
            make_process(100, "firefox", 2000, 10.0),
        ];
        let snapshot = make_snapshot_with_ram(96.0, 15729, 16384, processes);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let actions = &alerts[0].suggested_actions;
        assert_eq!(actions.len(), 1);
        assert!(actions[0].command.contains("kill 100"));
        assert!(!actions[0].command.contains("kill 1 "));
    }
}
