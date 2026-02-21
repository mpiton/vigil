use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

pub struct DiskSpaceRule;

impl Rule for DiskSpaceRule {
    fn name(&self) -> &'static str {
        "disk_space_low"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for disk in &snapshot.disks {
            if disk.usage_percent >= thresholds.disk_warning {
                let severity = if disk.usage_percent >= thresholds.disk_critical {
                    Severity::Critical
                } else {
                    Severity::High
                };

                alerts.push(Alert {
                    timestamp: snapshot.timestamp,
                    severity,
                    rule: "disk_space_low".to_string(),
                    title: format!(
                        "Disk {} almost full: {:.1}% used ({:.1} GB free)",
                        disk.mount_point, disk.usage_percent, disk.available_gb
                    ),
                    details: format!(
                        "Mount point: {}\nFilesystem: {}\nTotal: {:.1} GB",
                        disk.mount_point, disk.filesystem, disk.total_gb
                    ),
                    suggested_actions: vec![
                        SuggestedAction {
                            description: "Clean system logs".to_string(),
                            command: "sudo journalctl --vacuum-size=500M".to_string(),
                            risk: ActionRisk::Safe,
                        },
                        SuggestedAction {
                            description: "Find large files".to_string(),
                            command: format!(
                                "du -sh '{}'/* 2>/dev/null | sort -rh | head -20",
                                disk.mount_point.replace('\'', "'\\''")
                            ),
                            risk: ActionRisk::Safe,
                        },
                    ],
                });
            }
        }

        alerts
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::disk::DiskInfo;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use chrono::Utc;

    fn make_disk(mount_point: &str, total_gb: f64, usage_percent: f64) -> DiskInfo {
        let available_gb = total_gb * (1.0 - usage_percent / 100.0);
        DiskInfo {
            mount_point: mount_point.to_string(),
            total_gb,
            available_gb,
            usage_percent,
            filesystem: "ext4".to_string(),
        }
    }

    fn make_snapshot(disks: Vec<DiskInfo>) -> SystemSnapshot {
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
            disks,
            journal_entries: vec![],
        }
    }

    #[test]
    fn rule_name() {
        assert_eq!(DiskSpaceRule.name(), "disk_space_low");
    }

    #[test]
    fn no_alert_when_disks_healthy() {
        let rule = DiskSpaceRule;
        let snapshot = make_snapshot(vec![make_disk("/", 500.0, 50.0)]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_when_disk_warning() {
        let rule = DiskSpaceRule;
        let snapshot = make_snapshot(vec![make_disk("/", 500.0, 90.0)]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].rule, "disk_space_low");
    }

    #[test]
    fn critical_when_almost_full() {
        let rule = DiskSpaceRule;
        // disk_critical default is 95.0, so 98% triggers Critical
        let snapshot = make_snapshot(vec![make_disk("/", 500.0, 98.0)]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn high_between_warning_and_critical() {
        let rule = DiskSpaceRule;
        // 90% is above disk_warning (85%) but below disk_critical (95%) → High
        let snapshot = make_snapshot(vec![make_disk("/", 500.0, 90.0)]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn critical_at_exact_critical_threshold() {
        let rule = DiskSpaceRule;
        let thresholds = ThresholdSet::default();
        // usage == disk_critical (95.0) → Critical (>= comparison)
        let snapshot = make_snapshot(vec![make_disk("/", 500.0, thresholds.disk_critical)]);
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn multiple_disks_multiple_alerts() {
        let rule = DiskSpaceRule;
        let snapshot = make_snapshot(vec![
            make_disk("/", 500.0, 90.0),
            make_disk("/home", 1000.0, 92.0),
        ]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn no_alert_when_no_disks() {
        let rule = DiskSpaceRule;
        let snapshot = make_snapshot(vec![]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn suggested_actions_include_mount_point() {
        let rule = DiskSpaceRule;
        let snapshot = make_snapshot(vec![make_disk("/data", 500.0, 90.0)]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let actions = &alerts[0].suggested_actions;
        assert_eq!(actions.len(), 2);
        assert!(actions[1].command.contains("/data"));
        assert_eq!(actions[0].risk, ActionRisk::Safe);
        assert_eq!(actions[1].risk, ActionRisk::Safe);
    }

    #[test]
    fn mount_point_shell_escaped() {
        let rule = DiskSpaceRule;
        let snapshot = make_snapshot(vec![make_disk("/mnt/my disk", 500.0, 90.0)]);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        let cmd = &alerts[0].suggested_actions[1].command;
        assert!(cmd.contains("'/mnt/my disk'"));
    }
}
