use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

pub struct OomKillerRule;

impl Rule for OomKillerRule {
    fn name(&self) -> &'static str {
        "oom_killer"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
        let oom_entries: Vec<&_> = snapshot
            .journal_entries
            .iter()
            .filter(|e| {
                let msg = e.message.to_lowercase();
                msg.contains("oom")
                    || msg.contains("out of memory")
                    || msg.contains("killed process")
            })
            .collect();

        if oom_entries.is_empty() {
            return vec![];
        }

        let details = oom_entries
            .iter()
            .take(5)
            .map(|e| format!("  [{}] {}", e.unit, e.message))
            .collect::<Vec<_>>()
            .join("\n");

        vec![Alert {
            timestamp: snapshot.timestamp,
            severity: Severity::Critical,
            rule: "oom_killer".to_string(),
            title: format!(
                "OOM Killer actif — {} événement(s) récent(s)",
                oom_entries.len()
            ),
            details,
            suggested_actions: vec![SuggestedAction {
                description: "Identifier le processus le plus gourmand".to_string(),
                command: "ps aux --sort=-%mem | head -10".to_string(),
                risk: ActionRisk::Safe,
            }],
        }]
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::journal::JournalEntry;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use chrono::Utc;

    fn make_journal_entry(unit: &str, message: &str) -> JournalEntry {
        JournalEntry {
            timestamp: Utc::now(),
            priority: 3,
            unit: unit.to_string(),
            message: message.to_string(),
        }
    }

    fn make_snapshot(journal_entries: Vec<JournalEntry>) -> SystemSnapshot {
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
            processes: vec![],
            disks: vec![],
            journal_entries,
        }
    }

    #[test]
    fn no_alert_when_no_oom_entries() {
        let rule = OomKillerRule;
        let snapshot = make_snapshot(vec![
            make_journal_entry("sshd.service", "Connection accepted from 192.168.1.1"),
            make_journal_entry("nginx.service", "Worker process started"),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_on_oom_keyword() {
        let rule = OomKillerRule;
        let snapshot = make_snapshot(vec![make_journal_entry(
            "kernel",
            "oom: process killed to free memory",
        )]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].rule, "oom_killer");
    }

    #[test]
    fn alert_on_out_of_memory() {
        let rule = OomKillerRule;
        let snapshot = make_snapshot(vec![make_journal_entry(
            "kernel",
            "Out of memory: Kill process 1234",
        )]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn alert_on_killed_process() {
        let rule = OomKillerRule;
        let snapshot = make_snapshot(vec![make_journal_entry(
            "kernel",
            "Killed process 5678 (firefox) total-vm:1024000kB",
        )]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn case_insensitive_matching() {
        let rule = OomKillerRule;
        let snapshot = make_snapshot(vec![
            make_journal_entry("kernel", "OOM killer invoked"),
            make_journal_entry("kernel", "Out Of Memory condition detected"),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn details_limited_to_five_entries() {
        let rule = OomKillerRule;
        let entries: Vec<JournalEntry> = (0..10)
            .map(|i| make_journal_entry("kernel", &format!("oom event number {i}")))
            .collect();
        let snapshot = make_snapshot(entries);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let details = &alerts[0].details;
        let line_count = details.lines().count();
        assert_eq!(line_count, 5);
    }

    #[test]
    fn title_shows_total_count() {
        let rule = OomKillerRule;
        let entries: Vec<JournalEntry> = (0..10)
            .map(|i| make_journal_entry("kernel", &format!("oom event number {i}")))
            .collect();
        let snapshot = make_snapshot(entries);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("10 événement(s)"));
    }
}
