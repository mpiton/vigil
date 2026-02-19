use serde::Serialize;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::ports::analyzer::AiAnalyzer;
use crate::domain::ports::collector::SystemCollector;
use crate::domain::ports::notifier::Notifier;
use crate::domain::rules::RuleEngine;
use crate::domain::value_objects::thresholds::ThresholdSet;
use crate::presentation::cli::formatters::alert_fmt;
use crate::presentation::cli::formatters::status_fmt::print_section_header;

#[derive(Serialize)]
struct ScanOutput<'a> {
    snapshot: &'a SystemSnapshot,
    alerts: &'a [Alert],
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<&'a AiDiagnostic>,
}

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
    ai: bool,
    json: bool,
) -> anyhow::Result<()> {
    let snapshot = collector.collect()?;
    let alerts = rule_engine.analyze(&snapshot, thresholds);

    let diagnostic = if ai && !alerts.is_empty() {
        match analyzer.analyze(&snapshot, &alerts).await {
            Ok(diag) => diag,
            Err(e) => {
                tracing::warn!("Analyse IA échouée : {e}");
                None
            }
        }
    } else {
        None
    };

    if json {
        print_scan_json(&snapshot, &alerts, diagnostic.as_ref())?;
    } else {
        print_scan_human(&alerts, diagnostic.as_ref(), notifier);
    }

    Ok(())
}

fn print_scan_json(
    snapshot: &SystemSnapshot,
    alerts: &[Alert],
    diagnostic: Option<&AiDiagnostic>,
) -> anyhow::Result<()> {
    let output = ScanOutput {
        snapshot,
        alerts,
        diagnostic,
    };
    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

fn print_scan_human(alerts: &[Alert], diagnostic: Option<&AiDiagnostic>, notifier: &dyn Notifier) {
    print_section_header("🔍 Scan système");
    if alerts.is_empty() {
        alert_fmt::print_no_alerts();
    } else {
        println!("{} alerte(s) détectée(s) :", alerts.len());
        for alert in alerts {
            if let Err(e) = notifier.notify(alert) {
                tracing::warn!("Échec de notification : {e}");
            }
        }
    }
    if let Some(diag) = diagnostic {
        if let Err(e) = notifier.notify_ai_diagnostic(diag) {
            tracing::warn!("Échec d'affichage du diagnostic IA : {e}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::SuggestedAction;
    use crate::domain::entities::diagnostic::AiDiagnostic;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::analyzer::AnalysisError;
    use crate::domain::ports::collector::CollectionError;
    use crate::domain::ports::notifier::NotificationError;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use crate::domain::value_objects::severity::Severity;
    use async_trait::async_trait;
    use chrono::Utc;
    use colored::control;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    struct DiagnosticAnalyzer;

    #[async_trait]
    impl AiAnalyzer for DiagnosticAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(Some(make_diagnostic()))
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

    struct CountingNotifier {
        notify_count: AtomicUsize,
        diagnostic_count: AtomicUsize,
    }

    impl CountingNotifier {
        fn new() -> Self {
            Self {
                notify_count: AtomicUsize::new(0),
                diagnostic_count: AtomicUsize::new(0),
            }
        }
    }

    impl Notifier for CountingNotifier {
        fn notify(&self, _alert: &Alert) -> Result<(), NotificationError> {
            self.notify_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
        ) -> Result<(), NotificationError> {
            self.diagnostic_count.fetch_add(1, Ordering::Relaxed);
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

    fn make_alert() -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity: Severity::High,
            rule: "test_rule".to_string(),
            title: "Test Alert".to_string(),
            details: "Some details".to_string(),
            suggested_actions: vec![SuggestedAction {
                description: "Fix it".to_string(),
                command: "echo fix".to_string(),
                risk: ActionRisk::Safe,
            }],
        }
    }

    fn make_diagnostic() -> AiDiagnostic {
        AiDiagnostic {
            timestamp: Utc::now(),
            summary: "High memory pressure".to_string(),
            details: "Process X consumes 95% RAM".to_string(),
            severity: Severity::High,
            confidence: 0.87,
        }
    }

    /// Rule that always fires one alert, for testing alert-producing scenarios.
    struct AlwaysAlertRule;

    impl crate::domain::rules::Rule for AlwaysAlertRule {
        fn name(&self) -> &'static str {
            "always_alert"
        }

        fn evaluate(&self, _snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
            vec![make_alert()]
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
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            false,
            true,
        )
        .await;
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
            false,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn scan_without_ai_skips_analyzer() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = DiagnosticAnalyzer;
        let notifier = CountingNotifier::new();
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            false,
            false,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(notifier.notify_count.load(Ordering::Relaxed), 1);
        assert_eq!(notifier.diagnostic_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn scan_with_ai_calls_analyzer() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = DiagnosticAnalyzer;
        let notifier = CountingNotifier::new();
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            true,
            false,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(notifier.notify_count.load(Ordering::Relaxed), 1);
        assert_eq!(notifier.diagnostic_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn scan_ai_no_alerts_skips_analyzer() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = DiagnosticAnalyzer;
        let notifier = CountingNotifier::new();
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            true,
            false,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(notifier.notify_count.load(Ordering::Relaxed), 0);
        assert_eq!(notifier.diagnostic_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn scan_json_includes_snapshot_and_alerts() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
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
            true,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn scan_ai_json_includes_diagnostic() {
        disable_colors();
        let collector = MockCollector {
            snapshot: healthy_snapshot(),
        };
        let engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = DiagnosticAnalyzer;
        let notifier = MockNotifier;
        let result = run_scan(
            &collector,
            &engine,
            &thresholds,
            &analyzer,
            &notifier,
            true,
            true,
        )
        .await;
        assert!(result.is_ok());
    }
}
