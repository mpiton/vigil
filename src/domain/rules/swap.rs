use crate::domain::entities::alert::Alert;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

pub struct SwapWarningRule;

impl Rule for SwapWarningRule {
    fn name(&self) -> &'static str {
        "swap_warning"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        let mem = &snapshot.memory;
        if mem.swap_total_mb > 0
            && mem.swap_percent >= thresholds.swap_warning
            && mem.swap_percent < thresholds.swap_critical
        {
            vec![Alert {
                timestamp: snapshot.timestamp,
                severity: Severity::High,
                rule: "swap_warning".to_string(),
                title: format!(
                    "High swap: {:.1}% ({}/{} MB)",
                    mem.swap_percent, mem.swap_used_mb, mem.swap_total_mb
                ),
                details: "The system is using a lot of swap, which degrades performance."
                    .to_string(),
                suggested_actions: vec![],
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
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use chrono::Utc;

    fn make_snapshot(swap_total_mb: u64, swap_used_mb: u64, swap_percent: f64) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8000,
                available_mb: 8384,
                swap_total_mb,
                swap_used_mb,
                usage_percent: 48.8,
                swap_percent,
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
            journal_entries: vec![],
        }
    }

    #[test]
    fn rule_name() {
        assert_eq!(SwapWarningRule.name(), "swap_warning");
    }

    #[test]
    fn no_alert_when_swap_low() {
        let rule = SwapWarningRule;
        let snapshot = make_snapshot(8192, 1000, 12.2);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_when_swap_high() {
        let rule = SwapWarningRule;
        let snapshot = make_snapshot(8192, 5734, 70.0);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].title.contains("70.0%"));
        assert!(alerts[0].suggested_actions.is_empty());
    }

    #[test]
    fn no_alert_when_no_swap() {
        let rule = SwapWarningRule;
        let snapshot = make_snapshot(0, 0, 99.9);
        let thresholds = ThresholdSet::default();
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_at_exact_threshold() {
        let rule = SwapWarningRule;
        let thresholds = ThresholdSet::default();
        let snapshot = make_snapshot(8192, 4096, thresholds.swap_warning);
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn no_alert_when_below_threshold() {
        let rule = SwapWarningRule;
        let thresholds = ThresholdSet::default();
        let snapshot = make_snapshot(8192, 4090, thresholds.swap_warning - 0.1);
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_at_critical_level() {
        let rule = SwapWarningRule;
        let thresholds = ThresholdSet::default();
        // swap_critical default 80.0 — warning should NOT fire at critical level
        let snapshot = make_snapshot(8192, 6553, thresholds.swap_critical);
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_just_below_critical() {
        let rule = SwapWarningRule;
        let thresholds = ThresholdSet::default();
        let snapshot = make_snapshot(8192, 6500, thresholds.swap_critical - 0.1);
        let alerts = rule.evaluate(&snapshot, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }
}
