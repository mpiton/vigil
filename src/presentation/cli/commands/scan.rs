use crate::domain::entities::alert::Alert;
use crate::domain::ports::analyzer::AiAnalyzer;
use crate::domain::ports::collector::SystemCollector;
use crate::domain::ports::notifier::Notifier;
use crate::domain::rules::RuleEngine;
use crate::domain::value_objects::thresholds::ThresholdSet;
use crate::presentation::cli::formatters::alert_fmt;
use crate::presentation::cli::formatters::status_fmt::print_section_header;

/// Runs a one-shot system scan: collect metrics, evaluate rules, display alerts,
/// and optionally run AI analysis.
///
/// # Errors
///
/// Returns an error if metrics collection fails or JSON serialization fails.
pub async fn run_scan(
    collector: &dyn SystemCollector,
    rule_engine: &RuleEngine,
    thresholds: &ThresholdSet,
    analyzer: &dyn AiAnalyzer,
    notifier: &dyn Notifier,
    json: bool,
) -> anyhow::Result<()> {
    let snapshot = collector.collect()?;
    let alerts = rule_engine.analyze(&snapshot, thresholds);

    if json {
        print_alerts_json(&alerts)?;
    } else {
        print_alerts_human(&alerts);
    }

    if !alerts.is_empty() {
        match analyzer.analyze(&snapshot, &alerts).await {
            Ok(Some(diagnostic)) => {
                if let Err(e) = notifier.notify_ai_diagnostic(&diagnostic) {
                    tracing::warn!("failed to display AI diagnostic: {e}");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("AI analysis failed: {e}");
            }
        }
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
    use crate::domain::entities::diagnostic::AiDiagnostic;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::analyzer::AnalysisError;
    use crate::domain::ports::collector::CollectionError;
    use crate::domain::ports::notifier::NotificationError;
    use async_trait::async_trait;
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

    struct MockAnalyzer;

    #[async_trait]
    impl AiAnalyzer for MockAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(None)
        }
    }

    struct MockNotifier;

    impl Notifier for MockNotifier {
        fn notify(&self, _alert: &Alert) -> Result<(), NotificationError> {
            Ok(())
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
        ) -> Result<(), NotificationError> {
            Ok(())
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

    #[tokio::test]
    async fn scan_healthy_system_no_alerts() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            false,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn scan_healthy_system_json_output() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let result = run_scan(&collector, &engine, &thresholds, &analyzer, &notifier, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn scan_failing_collector_returns_error() {
        disable_colors();
        let collector = FailingCollector;
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            false,
        )
        .await;
        assert!(result.is_err());
    }
}
