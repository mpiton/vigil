pub mod cpu;
pub mod disk;
pub mod duplicates;
pub mod oom;
pub mod orphans;
pub mod ram;
pub mod swap;
pub mod zombie;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::thresholds::ThresholdSet;

/// A deterministic rule that evaluates a system snapshot and produces alerts.
/// Rules are pure functions: snapshot + thresholds in, alerts out. No I/O.
pub trait Rule: Send + Sync {
    /// Returns the unique name of this rule
    fn name(&self) -> &'static str;

    /// Evaluates the rule against a snapshot using the given thresholds
    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert>;
}

/// Returns all default Level 1 deterministic rules
#[must_use]
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ram::RamWarningRule),
        Box::new(ram::RamCriticalRule),
        Box::new(cpu::CpuOverloadRule),
        Box::new(swap::SwapWarningRule),
        Box::new(zombie::ZombieProcessRule),
        Box::new(disk::DiskSpaceRule),
        Box::new(oom::OomKillerRule),
    ]
}

/// Engine that runs a collection of rules against system snapshots
pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    #[must_use]
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }

    /// Analyzes a snapshot by running all rules, returning alerts sorted by severity (critical first)
    #[must_use]
    pub fn analyze(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self
            .rules
            .iter()
            .flat_map(|rule| rule.evaluate(snapshot, thresholds))
            .collect();
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::Alert;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::value_objects::severity::Severity;
    use chrono::Utc;

    fn make_snapshot() -> SystemSnapshot {
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
            journal_entries: vec![],
        }
    }

    struct NoopRule;
    impl Rule for NoopRule {
        fn name(&self) -> &'static str {
            "noop"
        }
        fn evaluate(&self, _: &SystemSnapshot, _: &ThresholdSet) -> Vec<Alert> {
            vec![]
        }
    }

    struct FixedAlertRule {
        severity: Severity,
    }
    impl Rule for FixedAlertRule {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn evaluate(&self, _: &SystemSnapshot, _: &ThresholdSet) -> Vec<Alert> {
            vec![Alert {
                timestamp: Utc::now(),
                severity: self.severity,
                rule: "fixed".to_string(),
                title: "Fixed alert".to_string(),
                details: String::new(),
                suggested_actions: vec![],
            }]
        }
    }

    #[test]
    fn engine_with_no_rules_returns_empty() {
        let engine = RuleEngine::new(vec![]);
        let alerts = engine.analyze(&make_snapshot(), &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn engine_with_noop_rule_returns_empty() {
        let noop = NoopRule;
        assert_eq!(noop.name(), "noop");
        let engine = RuleEngine::new(vec![Box::new(noop)]);
        let alerts = engine.analyze(&make_snapshot(), &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn engine_collects_alerts_from_single_rule() {
        let fixed = FixedAlertRule {
            severity: Severity::High,
        };
        assert_eq!(fixed.name(), "fixed");
        let engine = RuleEngine::new(vec![Box::new(fixed)]);
        let alerts = engine.analyze(&make_snapshot(), &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn engine_sorts_alerts_critical_first() {
        let engine = RuleEngine::new(vec![
            Box::new(FixedAlertRule {
                severity: Severity::Low,
            }),
            Box::new(FixedAlertRule {
                severity: Severity::Critical,
            }),
            Box::new(FixedAlertRule {
                severity: Severity::Medium,
            }),
        ]);
        let alerts = engine.analyze(&make_snapshot(), &ThresholdSet::default());
        assert_eq!(alerts.len(), 3);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[1].severity, Severity::Medium);
        assert_eq!(alerts[2].severity, Severity::Low);
    }

    #[test]
    fn engine_collects_from_multiple_rules() {
        let engine = RuleEngine::new(vec![
            Box::new(FixedAlertRule {
                severity: Severity::High,
            }),
            Box::new(FixedAlertRule {
                severity: Severity::Critical,
            }),
        ]);
        let alerts = engine.analyze(&make_snapshot(), &ThresholdSet::default());
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn default_rules_returns_all_level1_rules() {
        let rules = default_rules();
        assert_eq!(rules.len(), 7);
        let names: Vec<&str> = rules.iter().map(|r| r.name()).collect();
        assert!(names.contains(&"ram_warning"));
        assert!(names.contains(&"ram_critical"));
        assert!(names.contains(&"cpu_overload"));
        assert!(names.contains(&"swap_warning"));
        assert!(names.contains(&"zombie_processes"));
        assert!(names.contains(&"disk_space_low"));
        assert!(names.contains(&"oom_killer"));
    }

    #[test]
    fn default_rules_produce_no_alerts_on_healthy_snapshot() {
        let rules = default_rules();
        let engine = RuleEngine::new(rules);
        let alerts = engine.analyze(&make_snapshot(), &ThresholdSet::default());
        assert!(alerts.is_empty());
    }
}
