#![allow(clippy::expect_used)]

use std::sync::Mutex;

use vigil::application::services::monitor::MonitorService;
use vigil::domain::entities::alert::{Alert, SuggestedAction};
use vigil::domain::entities::diagnostic::AiDiagnostic;
use vigil::domain::entities::snapshot::SystemSnapshot;
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
// TrackingNotifier
// ---------------------------------------------------------------------------

struct TrackingNotifier {
    alerts: Mutex<Vec<Alert>>,
}

impl TrackingNotifier {
    const fn new() -> Self {
        Self {
            alerts: Mutex::new(vec![]),
        }
    }

    fn collected_alerts(&self) -> Vec<Alert> {
        self.alerts.lock().expect("lock").clone()
    }
}

impl Notifier for TrackingNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        self.alerts.lock().expect("lock").push(alert.clone());
        Ok(())
    }

    fn notify_ai_diagnostic(&self, _d: &AiDiagnostic) -> Result<(), NotificationError> {
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
// Helper: build a MonitorService with default rules
// ---------------------------------------------------------------------------

fn make_service_parts() -> (RuleEngine, ThresholdSet, NoopAnalyzer, InMemoryStore) {
    let rule_engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let analyzer = NoopAnalyzer::new();
    let store = InMemoryStore::new();
    (rule_engine, thresholds, analyzer, store)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_normal_no_alerts() {
    let snapshot = load_fixture("snapshot_normal.json");
    let collector = MockCollector { snapshot };
    let (rule_engine, thresholds, analyzer, store) = make_service_parts();
    let notifier = TrackingNotifier::new();

    let service = MonitorService::new(
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

    let result = service.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");

    assert_eq!(cycle.alerts_count, 0);
    assert!(cycle.snapshot_saved);
    assert!(notifier.collected_alerts().is_empty());
}

#[tokio::test]
async fn scan_ram_critical_generates_alerts() {
    let snapshot = load_fixture("snapshot_ram_critical.json");
    let collector = MockCollector { snapshot };
    let (rule_engine, thresholds, analyzer, store) = make_service_parts();
    let notifier = TrackingNotifier::new();

    let service = MonitorService::new(
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

    let result = service.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");

    assert!(cycle.alerts_count > 0);

    let alerts = notifier.collected_alerts();
    assert!(!alerts.is_empty());

    let has_critical = alerts.iter().any(|a| a.severity == Severity::Critical);
    assert!(has_critical, "expected at least one Critical alert");
}

#[tokio::test]
async fn scan_oom_generates_critical_alert() {
    let snapshot = load_fixture("snapshot_oom.json");
    let collector = MockCollector { snapshot };
    let (rule_engine, thresholds, analyzer, store) = make_service_parts();
    let notifier = TrackingNotifier::new();

    let service = MonitorService::new(
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

    let result = service.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");

    assert!(cycle.alerts_count > 0);

    let alerts = notifier.collected_alerts();
    let oom_critical = alerts
        .iter()
        .any(|a| a.severity == Severity::Critical && a.rule == "oom_killer");
    assert!(oom_critical, "expected a Critical OOM-related alert");
}

#[tokio::test]
async fn scan_mcp_zombies_detects_duplicates() {
    let snapshot = load_fixture("snapshot_mcp_zombies.json");
    let collector = MockCollector { snapshot };
    let (rule_engine, thresholds, analyzer, store) = make_service_parts();
    let notifier = TrackingNotifier::new();

    let service = MonitorService::new(
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

    let result = service.run_once().await;
    assert!(result.is_ok());
    let cycle = result.expect("run_once failed");

    assert!(cycle.alerts_count > 0);

    let alerts = notifier.collected_alerts();
    let has_duplicate_alert = alerts.iter().any(|a| a.rule == "duplicate_processes");
    assert!(
        has_duplicate_alert,
        "expected a duplicate process detection alert"
    );
}
