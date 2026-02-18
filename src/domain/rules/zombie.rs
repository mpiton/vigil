use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::process::ProcessState;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

pub struct ZombieProcessRule;

impl Rule for ZombieProcessRule {
    fn name(&self) -> &'static str {
        "zombie_processes"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
        let zombies: Vec<&_> = snapshot
            .processes
            .iter()
            .filter(|p| p.state == ProcessState::Zombie)
            .collect();

        if zombies.is_empty() {
            return vec![];
        }

        let details = zombies
            .iter()
            .map(|z| format!("  PID {} ({}) — parent PID {}", z.pid, z.name, z.ppid))
            .collect::<Vec<_>>()
            .join("\n");

        let mut seen_ppids = std::collections::HashSet::new();
        let suggested_actions = zombies
            .iter()
            .filter(|z| z.ppid > 1 && seen_ppids.insert(z.ppid))
            .map(|z| SuggestedAction {
                description: format!(
                    "Signaler le parent (PID {}) pour récolter le zombie",
                    z.ppid
                ),
                command: format!("kill -SIGCHLD {}", z.ppid),
                risk: ActionRisk::Safe,
            })
            .collect();

        vec![Alert {
            timestamp: snapshot.timestamp,
            severity: Severity::Medium,
            rule: "zombie_processes".to_string(),
            title: format!("{} processus zombie(s) détecté(s)", zombies.len()),
            details,
            suggested_actions,
        }]
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use chrono::Utc;

    fn make_process(pid: u32, ppid: u32, name: &str, state: ProcessState) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            cmdline: name.to_string(),
            state,
            cpu_percent: 0.0,
            rss_mb: 0,
            vms_mb: 0,
            user: "root".to_string(),
            start_time: 0,
            open_fds: 0,
        }
    }

    fn make_snapshot(processes: Vec<ProcessInfo>) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8000,
                available_mb: 8384,
                swap_total_mb: 8192,
                swap_used_mb: 0,
                usage_percent: 48.8,
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
    fn no_alert_when_no_zombies() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![
            make_process(1, 0, "init", ProcessState::Running),
            make_process(2, 1, "bash", ProcessState::Sleeping),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_when_zombies_found() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![
            make_process(1, 0, "init", ProcessState::Running),
            make_process(42, 1, "defunct", ProcessState::Zombie),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Medium);
        assert_eq!(alerts[0].rule, "zombie_processes");
    }

    #[test]
    fn alert_lists_all_zombies() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![
            make_process(10, 5, "zombie_a", ProcessState::Zombie),
            make_process(20, 7, "zombie_b", ProcessState::Zombie),
            make_process(30, 9, "zombie_c", ProcessState::Zombie),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let details = &alerts[0].details;
        assert!(details.contains("10"));
        assert!(details.contains("20"));
        assert!(details.contains("30"));
        assert!(details.contains("zombie_a"));
        assert!(details.contains("zombie_b"));
        assert!(details.contains("zombie_c"));
    }

    #[test]
    fn suggested_actions_target_parent() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![
            make_process(42, 100, "ghost", ProcessState::Zombie),
            make_process(43, 200, "phantom", ProcessState::Zombie),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let actions = &alerts[0].suggested_actions;
        assert_eq!(actions.len(), 2);
        assert!(actions[0].command.contains("100"));
        assert!(actions[1].command.contains("200"));
        assert_eq!(actions[0].risk, ActionRisk::Safe);
        assert_eq!(actions[1].risk, ActionRisk::Safe);
    }

    #[test]
    fn single_zombie() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![make_process(
            99,
            100,
            "lone_zombie",
            ProcessState::Zombie,
        )]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains('1'));
        assert_eq!(alerts[0].suggested_actions.len(), 1);
        assert_eq!(alerts[0].suggested_actions[0].command, "kill -SIGCHLD 100");
    }

    #[test]
    fn no_action_for_ppid_0_or_1() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![
            make_process(10, 0, "kernel_zombie", ProcessState::Zombie),
            make_process(11, 1, "init_zombie", ProcessState::Zombie),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "2 processus zombie(s) détecté(s)");
        assert!(alerts[0].suggested_actions.is_empty());
    }

    #[test]
    fn deduplicates_actions_by_ppid() {
        let rule = ZombieProcessRule;
        let snapshot = make_snapshot(vec![
            make_process(10, 100, "z1", ProcessState::Zombie),
            make_process(11, 100, "z2", ProcessState::Zombie),
            make_process(12, 200, "z3", ProcessState::Zombie),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].suggested_actions.len(), 2);
    }
}
