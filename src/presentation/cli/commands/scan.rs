use crate::domain::entities::alert::Alert;
use crate::domain::ports::collector::SystemCollector;
use crate::domain::rules::RuleEngine;
use crate::domain::value_objects::thresholds::ThresholdSet;
use crate::presentation::cli::formatters::alert_fmt;
use crate::presentation::cli::formatters::status_fmt::print_section_header;

/// Runs a one-shot system scan: collect metrics, evaluate rules, display alerts.
///
/// # Errors
///
/// Returns an error if metrics collection fails or JSON serialization fails.
pub fn run_scan(
    collector: &dyn SystemCollector,
    rule_engine: &RuleEngine,
    thresholds: &ThresholdSet,
    json: bool,
) -> anyhow::Result<()> {
    let snapshot = collector.collect()?;
    let alerts = rule_engine.analyze(&snapshot, thresholds);

    if json {
        print_alerts_json(&alerts)?;
    } else {
        print_alerts_human(&alerts);
    }

    Ok(())
}

fn print_alerts_json(alerts: &[Alert]) -> anyhow::Result<()> {
    let output = serde_json::to_string_pretty(alerts)?;
    println!("{output}");
    Ok(())
}

fn print_alerts_human(alerts: &[Alert]) {
    print_section_header("🔍 Scan système");
    if alerts.is_empty() {
        alert_fmt::print_no_alerts();
    } else {
        println!("{} alerte(s) détectée(s) :", alerts.len());
        alert_fmt::format_alerts(alerts);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::collector::CollectionError;
    use chrono::Utc;
    use colored::control;

    fn disable_colors() {
        control::set_override(false);
    }

    struct MockCollector {
        snapshot: SystemSnapshot,
    }

    impl SystemCollector for MockCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Ok(self.snapshot.clone())
        }
    }

    struct FailingCollector;

    impl SystemCollector for FailingCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Err(CollectionError::MetricsUnavailable("test error".into()))
        }
    }

    fn healthy_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 4000,
                available_mb: 12384,
                swap_total_mb: 8192,
                swap_used_mb: 0,
                usage_percent: 24.4,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 10.0,
                per_core_usage: vec![10.0],
                core_count: 4,
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
    fn scan_healthy_system_no_alerts() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let result = run_scan(&collector, &engine, &thresholds, false);
        assert!(result.is_ok());
    }

    #[test]
    fn scan_healthy_system_json_output() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let result = run_scan(&collector, &engine, &thresholds, true);
        assert!(result.is_ok());
    }

    #[test]
    fn scan_failing_collector_returns_error() {
        disable_colors();
        let collector = FailingCollector;
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let result = run_scan(&collector, &engine, &thresholds, false);
        assert!(result.is_err());
    }
}
