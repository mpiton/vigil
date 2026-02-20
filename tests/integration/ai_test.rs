#![allow(clippy::expect_used)]

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Mutex;

use vigil::application::services::monitor::MonitorService;
use vigil::domain::entities::alert::{Alert, SuggestedAction};
use vigil::domain::entities::diagnostic::AiDiagnostic;
use vigil::domain::entities::snapshot::SystemSnapshot;
use vigil::domain::ports::analyzer::{AiAnalyzer, AnalysisError};
use vigil::domain::ports::collector::{CollectionError, SystemCollector};
use vigil::domain::ports::notifier::{NotificationError, Notifier};
use vigil::domain::rules::{default_rules, RuleEngine};
use vigil::domain::value_objects::operation_mode::OperationMode;
use vigil::domain::value_objects::severity::Severity;
use vigil::domain::value_objects::thresholds::ThresholdSet;
use vigil::infrastructure::ai::noop::NoopAnalyzer;
use vigil::infrastructure::persistence::in_memory_store::InMemoryStore;

// ---------------------------------------------------------------------------
// Fixture loader
// ---------------------------------------------------------------------------

fn load_fixture(name: &str) -> SystemSnapshot {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let json = std::fs::read_to_string(&path).expect("Failed to read fixture");
    serde_json::from_str(&json).expect("Failed to parse fixture")
}

// ---------------------------------------------------------------------------
// MockCollector
// ---------------------------------------------------------------------------

struct MockCollector {
    snapshot: SystemSnapshot,
}

impl SystemCollector for MockCollector {
    fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
        Ok(self.snapshot.clone())
    }
}

// ---------------------------------------------------------------------------
// DiagnosticTrackingNotifier
// ---------------------------------------------------------------------------

struct DiagnosticTrackingNotifier {
    diagnostic_received: Mutex<bool>,
    alerts: Mutex<Vec<Alert>>,
}

impl DiagnosticTrackingNotifier {
    const fn new() -> Self {
        Self {
            diagnostic_received: Mutex::new(false),
            alerts: Mutex::new(vec![]),
        }
    }

    fn was_diagnostic_received(&self) -> bool {
        *self.diagnostic_received.lock().expect("lock")
    }

    fn collected_alerts(&self) -> Vec<Alert> {
        self.alerts.lock().expect("lock").clone()
    }
}

impl Notifier for DiagnosticTrackingNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        self.alerts.lock().expect("lock").push(alert.clone());
        Ok(())
    }

    fn notify_ai_diagnostic(&self, _d: &AiDiagnostic) -> Result<(), NotificationError> {
        *self.diagnostic_received.lock().expect("lock") = true;
        Ok(())
    }

    fn notify_action_executed(
        &self,
        _a: &SuggestedAction,
        _s: bool,
        _o: &str,
    ) -> Result<(), NotificationError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockAiAnalyzer
// ---------------------------------------------------------------------------

struct MockAiAnalyzer {
    called: Mutex<bool>,
}

impl MockAiAnalyzer {
    const fn new() -> Self {
        Self {
            called: Mutex::new(false),
        }
    }

    fn was_called(&self) -> bool {
        *self.called.lock().expect("lock")
    }
}

#[async_trait]
impl AiAnalyzer for MockAiAnalyzer {
    async fn analyze(
        &self,
        _s: &SystemSnapshot,
        _a: &[Alert],
    ) -> Result<Option<AiDiagnostic>, AnalysisError> {
        *self.called.lock().expect("lock") = true;
        Ok(Some(AiDiagnostic {
            timestamp: Utc::now(),
            summary: "Test diagnostic".into(),
            details: "Detailed analysis".into(),
            severity: Severity::High,
            confidence: 0.85,
            suggested_actions: vec![],
        }))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn noop_analyzer_returns_no_diagnostic() {
    let snapshot = load_fixture("snapshot_ram_critical.json");
    let collector = MockCollector { snapshot };
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = NoopAnalyzer::new();
    let notifier = DiagnosticTrackingNotifier::new();
    let store = InMemoryStore::new();

    let monitor = MonitorService::new(
        &collector,
        &rule_engine,
        &thresholds,
        &analyzer,
        &notifier,
        &store,
        &store,
        &store,
        &store,
        &[],
        true,
        OperationMode::Observe,
    );

    let result = monitor.run_once().await;
    assert!(result.is_ok());
    assert!(!notifier.was_diagnostic_received());
}

#[tokio::test]
async fn ai_disabled_skips_analysis() {
    let snapshot = load_fixture("snapshot_ram_critical.json");
    let collector = MockCollector { snapshot };
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = MockAiAnalyzer::new();
    let notifier = DiagnosticTrackingNotifier::new();
    let store = InMemoryStore::new();

    let monitor = MonitorService::new(
        &collector,
        &rule_engine,
        &thresholds,
        &analyzer,
        &notifier,
        &store,
        &store,
        &store,
        &store,
        &[],
        false,
        OperationMode::Observe,
    );

    let result = monitor.run_once().await;
    assert!(result.is_ok());
    assert!(!analyzer.was_called());
}

#[tokio::test]
async fn ai_enabled_with_critical_alerts_calls_analyzer() {
    let snapshot = load_fixture("snapshot_ram_critical.json");
    let collector = MockCollector { snapshot };
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = MockAiAnalyzer::new();
    let notifier = DiagnosticTrackingNotifier::new();
    let store = InMemoryStore::new();

    let monitor = MonitorService::new(
        &collector,
        &rule_engine,
        &thresholds,
        &analyzer,
        &notifier,
        &store,
        &store,
        &store,
        &store,
        &[],
        true,
        OperationMode::Observe,
    );

    let result = monitor.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");
    assert!(cycle.alerts_count > 0);
    assert!(analyzer.was_called());
}

#[tokio::test]
async fn noop_analyzer_with_normal_snapshot() {
    let snapshot = load_fixture("snapshot_normal.json");
    let collector = MockCollector { snapshot };
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = NoopAnalyzer::new();
    let notifier = DiagnosticTrackingNotifier::new();
    let store = InMemoryStore::new();

    let monitor = MonitorService::new(
        &collector,
        &rule_engine,
        &thresholds,
        &analyzer,
        &notifier,
        &store,
        &store,
        &store,
        &store,
        &[],
        true,
        OperationMode::Observe,
    );

    let result = monitor.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");
    assert_eq!(cycle.alerts_count, 0);
    assert!(notifier.collected_alerts().is_empty());
    assert!(!notifier.was_diagnostic_received());
}

#[tokio::test]
async fn ai_diagnostic_delivered_to_notifier() {
    let snapshot = load_fixture("snapshot_ram_critical.json");
    let collector = MockCollector { snapshot };
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = MockAiAnalyzer::new();
    let notifier = DiagnosticTrackingNotifier::new();
    let store = InMemoryStore::new();

    let monitor = MonitorService::new(
        &collector,
        &rule_engine,
        &thresholds,
        &analyzer,
        &notifier,
        &store,
        &store,
        &store,
        &store,
        &[],
        true,
        OperationMode::Observe,
    );

    let result = monitor.run_once().await;
    assert!(result.is_ok());
    assert!(notifier.was_diagnostic_received());
}

#[tokio::test]
async fn full_pipeline_with_noop_and_oom() {
    let snapshot = load_fixture("snapshot_oom.json");
    let collector = MockCollector { snapshot };
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = NoopAnalyzer::new();
    let notifier = DiagnosticTrackingNotifier::new();
    let store = InMemoryStore::new();

    let monitor = MonitorService::new(
        &collector,
        &rule_engine,
        &thresholds,
        &analyzer,
        &notifier,
        &store,
        &store,
        &store,
        &store,
        &[],
        true,
        OperationMode::Observe,
    );

    let result = monitor.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");
    assert!(cycle.alerts_count > 0);
    assert!(!notifier.was_diagnostic_received());
}
