use super::baseline::update_baselines;
use crate::domain::ports::analyzer::AiAnalyzer;
use crate::domain::ports::collector::SystemCollector;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::store::{
    ActionLogStore, ActionRecord, AlertStore, BaselineStore, SnapshotStore,
};
use crate::domain::rules::RuleEngine;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::operation_mode::OperationMode;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

/// Result of a single monitoring cycle.
pub struct MonitorCycleResult {
    pub alerts_count: usize,
    pub snapshot_saved: bool,
    pub auto_actions_run: usize,
}

/// Orchestrates a monitoring cycle: collect → persist → analyze → notify.
pub struct MonitorService<'a> {
    collector: &'a dyn SystemCollector,
    rule_engine: &'a RuleEngine,
    thresholds: &'a ThresholdSet,
    analyzer: &'a dyn AiAnalyzer,
    notifier: &'a dyn Notifier,
    alert_store: &'a dyn AlertStore,
    snapshot_store: &'a dyn SnapshotStore,
    baseline_store: &'a dyn BaselineStore,
    ai_enabled: bool,
    operation_mode: OperationMode,
    action_log: Option<&'a dyn ActionLogStore>,
    protected_commands: &'a [String],
}

impl<'a> MonitorService<'a> {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        collector: &'a dyn SystemCollector,
        rule_engine: &'a RuleEngine,
        thresholds: &'a ThresholdSet,
        analyzer: &'a dyn AiAnalyzer,
        notifier: &'a dyn Notifier,
        alert_store: &'a dyn AlertStore,
        snapshot_store: &'a dyn SnapshotStore,
        baseline_store: &'a dyn BaselineStore,
        ai_enabled: bool,
        operation_mode: OperationMode,
        action_log: Option<&'a dyn ActionLogStore>,
        protected_commands: &'a [String],
    ) -> Self {
        Self {
            collector,
            rule_engine,
            thresholds,
            analyzer,
            notifier,
            alert_store,
            snapshot_store,
            baseline_store,
            ai_enabled,
            operation_mode,
            action_log,
            protected_commands,
        }
    }

    /// Run a single monitoring cycle: collect → persist → analyze → notify.
    ///
    /// # Errors
    ///
    /// Returns an error if the system metrics collection fails.
    pub async fn run_once(&self) -> anyhow::Result<MonitorCycleResult> {
        let snapshot = self.collector.collect()?;

        let snapshot_saved = match self.snapshot_store.save_snapshot(&snapshot) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("Échec sauvegarde snapshot : {e}");
                false
            }
        };

        if snapshot_saved {
            if let Err(e) = update_baselines(self.baseline_store, &snapshot) {
                tracing::warn!("Échec mise à jour baselines : {e}");
            }
        }

        let alerts = self.rule_engine.analyze(&snapshot, self.thresholds);

        if alerts.is_empty() {
            tracing::debug!("Système OK — aucune alerte");
        }

        if !alerts.is_empty() {
            tracing::warn!("{} alerte(s) détectée(s)", alerts.len());
        }

        for alert in &alerts {
            if let Err(e) = self.alert_store.save_alert(alert) {
                tracing::warn!("Échec sauvegarde alerte : {e}");
            }
        }

        for alert in &alerts {
            if let Err(e) = self.notifier.notify(alert) {
                tracing::warn!("Échec notification alerte : {e}");
            }
        }

        // --- AI Analysis (moved before auto-execution) ---
        let ai_diagnostic =
            if self.ai_enabled && alerts.iter().any(|a| a.severity >= Severity::High) {
                match self.analyzer.analyze(&snapshot, &alerts).await {
                    Ok(Some(diag)) => {
                        if let Err(e) = self.notifier.notify_ai_diagnostic(&diag) {
                            tracing::warn!("Échec notification diagnostic IA : {e}");
                        }
                        Some(diag)
                    }
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!("Analyse IA échouée : {e}");
                        None
                    }
                }
            } else {
                None
            };

        // --- Auto-remediation ---
        let auto_actions_run = if self.operation_mode == OperationMode::Auto {
            self.execute_safe_actions(&alerts, ai_diagnostic.as_ref())
                .await
        } else {
            0
        };

        Ok(MonitorCycleResult {
            alerts_count: alerts.len(),
            snapshot_saved,
            auto_actions_run,
        })
    }

    /// Maximum output bytes captured from a remediation command.
    const MAX_OUTPUT_BYTES: usize = 4096;

    /// Timeout for a single remediation command.
    const ACTION_TIMEOUT_SECS: u64 = 30;

    /// Execute all safe actions from alerts and AI diagnostic.
    /// Returns the number of successfully executed actions.
    async fn execute_safe_actions(
        &self,
        alerts: &[crate::domain::entities::alert::Alert],
        ai_diagnostic: Option<&crate::domain::entities::diagnostic::AiDiagnostic>,
    ) -> usize {
        use std::collections::HashSet;

        let ai_actions: &[crate::domain::entities::alert::SuggestedAction] =
            ai_diagnostic.map_or(&[], |d| &d.suggested_actions);

        let all_actions = alerts
            .iter()
            .flat_map(|a| &a.suggested_actions)
            .chain(ai_actions.iter())
            .filter(|a| a.risk == ActionRisk::Safe);

        // Deduplicate by command string to avoid executing the same command twice.
        let mut seen = HashSet::new();
        let mut count = 0usize;

        for action in all_actions {
            if !seen.insert(&action.command) {
                tracing::debug!("Action dupliquée ignorée : {}", action.command);
                continue;
            }

            if is_command_protected(&action.command, self.protected_commands) {
                tracing::warn!("Action ignorée (commande protégée) : {}", action.command);
                continue;
            }

            tracing::info!("Auto-exécution : {}", action.description);

            let (success, output_str) = self.run_shell_command(&action.command).await;

            if success {
                count += 1;
            }

            if let Some(store) = self.action_log {
                let record = ActionRecord {
                    timestamp: chrono::Utc::now(),
                    alert_id: None,
                    command: action.command.clone(),
                    result: Some(output_str.clone()),
                    risk: action.risk,
                };
                if let Err(e) = store.log_action(&record) {
                    tracing::warn!("Échec journalisation action : {e}");
                }
            }

            if let Err(e) = self
                .notifier
                .notify_action_executed(action, success, &output_str)
            {
                tracing::warn!("Échec notification action : {e}");
            }
        }

        count
    }

    /// Execute a shell command with timeout and output capture.
    async fn run_shell_command(&self, command: &str) -> (bool, String) {
        let timeout = std::time::Duration::from_secs(Self::ACTION_TIMEOUT_SECS);

        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .kill_on_drop(true)
            .output();

        match tokio::time::timeout(timeout, child).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(
                    &output.stdout[..output.stdout.len().min(Self::MAX_OUTPUT_BYTES)],
                );
                let stderr = String::from_utf8_lossy(
                    &output.stderr[..output.stderr.len().min(Self::MAX_OUTPUT_BYTES)],
                );
                let combined = if stderr.is_empty() {
                    stdout.into_owned()
                } else {
                    format!("{stdout}\n{stderr}")
                };
                let success = output.status.success();
                if success {
                    tracing::info!("Commande réussie : {command}");
                } else {
                    tracing::warn!("Commande échouée : {command}");
                }
                (success, combined)
            }
            Ok(Err(e)) => {
                tracing::warn!("Échec lancement '{command}' : {e}");
                (false, format!("Erreur : {e}"))
            }
            Err(_) => {
                tracing::warn!(
                    "Commande '{command}' interrompue (timeout {timeout}s)",
                    timeout = Self::ACTION_TIMEOUT_SECS
                );
                (
                    false,
                    format!("Timeout après {}s", Self::ACTION_TIMEOUT_SECS),
                )
            }
        }
    }
}

/// Check if a shell command targets a protected process.
/// Matches if any protected command name appears as a word in the command string.
fn is_command_protected(command: &str, protected: &[String]) -> bool {
    protected
        .iter()
        .any(|p| command.split_whitespace().any(|word| word == p))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::{Alert, SuggestedAction};
    use crate::domain::entities::diagnostic::AiDiagnostic;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::analyzer::AnalysisError;
    use crate::domain::ports::collector::CollectionError;
    use crate::domain::ports::notifier::NotificationError;
    use crate::domain::ports::store::{ActionLogStore, ActionRecord, StoreError};
    use crate::domain::rules::Rule;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use crate::domain::value_objects::severity::Severity;
    use crate::infrastructure::persistence::in_memory_store::InMemoryStore;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;

    struct MockCollector;

    impl SystemCollector for MockCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Ok(healthy_snapshot())
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

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            Ok(())
        }
    }

    struct MockAlertStore {
        alerts: Mutex<Vec<Alert>>,
    }

    impl MockAlertStore {
        fn new() -> Self {
            Self {
                alerts: Mutex::new(vec![]),
            }
        }
    }

    impl AlertStore for MockAlertStore {
        fn save_alert(&self, alert: &Alert) -> Result<(), StoreError> {
            self.alerts
                .lock()
                .expect("mutex poisoned")
                .push(alert.clone());
            Ok(())
        }

        fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.lock().expect("mutex poisoned").clone())
        }

        fn get_recent_alerts(&self, count: usize) -> Result<Vec<Alert>, StoreError> {
            let alerts = self.alerts.lock().expect("mutex poisoned");
            Ok(alerts.iter().rev().take(count).cloned().collect())
        }

        fn get_alerts_since(&self, _since: DateTime<Utc>) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.lock().expect("mutex poisoned").clone())
        }
    }

    struct MockSnapshotStore {
        snapshots: Mutex<Vec<SystemSnapshot>>,
    }

    impl MockSnapshotStore {
        fn new() -> Self {
            Self {
                snapshots: Mutex::new(vec![]),
            }
        }
    }

    impl SnapshotStore for MockSnapshotStore {
        fn save_snapshot(&self, snapshot: &SystemSnapshot) -> Result<(), StoreError> {
            self.snapshots
                .lock()
                .expect("mutex poisoned")
                .push(snapshot.clone());
            Ok(())
        }

        fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
            Ok(self
                .snapshots
                .lock()
                .expect("mutex poisoned")
                .last()
                .cloned())
        }

        fn get_snapshots_since(
            &self,
            _since: DateTime<Utc>,
        ) -> Result<Vec<SystemSnapshot>, StoreError> {
            Ok(self.snapshots.lock().expect("mutex poisoned").clone())
        }
    }

    struct AlwaysAlertRule;

    impl Rule for AlwaysAlertRule {
        fn name(&self) -> &'static str {
            "always_alert"
        }

        fn evaluate(&self, _snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
            vec![Alert {
                timestamp: Utc::now(),
                severity: Severity::High,
                rule: "always_alert".to_string(),
                title: "Test Alert".to_string(),
                details: "Test details".to_string(),
                suggested_actions: vec![SuggestedAction {
                    description: "Fix it".to_string(),
                    command: "echo fix".to_string(),
                    risk: ActionRisk::Safe,
                }],
            }]
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
    async fn run_once_saves_snapshot() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert!(cycle.snapshot_saved);
        assert_eq!(
            snapshot_store
                .snapshots
                .lock()
                .expect("mutex poisoned")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn run_once_saves_alerts() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert_eq!(alert_store.alerts.lock().expect("mutex poisoned").len(), 1);
    }

    #[tokio::test]
    async fn run_once_no_alerts_skips_ai() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 0);
    }

    struct FailingCollector;

    impl SystemCollector for FailingCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Err(CollectionError::MetricsUnavailable("test failure".into()))
        }
    }

    struct FailingSnapshotStore;

    impl SnapshotStore for FailingSnapshotStore {
        fn save_snapshot(&self, _snapshot: &SystemSnapshot) -> Result<(), StoreError> {
            Err(StoreError::WriteFailed("disk full".into()))
        }

        fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
            Ok(None)
        }

        fn get_snapshots_since(
            &self,
            _since: DateTime<Utc>,
        ) -> Result<Vec<SystemSnapshot>, StoreError> {
            Err(StoreError::WriteFailed("disk full".into()))
        }
    }

    struct FailingAlertStore;

    impl AlertStore for FailingAlertStore {
        fn save_alert(&self, _alert: &Alert) -> Result<(), StoreError> {
            Err(StoreError::WriteFailed("disk full".into()))
        }

        fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
            Ok(vec![])
        }

        fn get_recent_alerts(&self, _count: usize) -> Result<Vec<Alert>, StoreError> {
            Ok(vec![])
        }

        fn get_alerts_since(&self, _since: DateTime<Utc>) -> Result<Vec<Alert>, StoreError> {
            Err(StoreError::WriteFailed("disk full".into()))
        }
    }

    struct FailingNotifier;

    impl Notifier for FailingNotifier {
        fn notify(&self, _alert: &Alert) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("dbus down".into()))
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
        ) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("dbus down".into()))
        }

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("dbus down".into()))
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
            Ok(Some(AiDiagnostic {
                timestamp: Utc::now(),
                summary: "Test diagnostic".to_string(),
                details: "Test details".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                suggested_actions: vec![],
            }))
        }
    }

    struct FailingAnalyzer;

    #[async_trait]
    impl AiAnalyzer for FailingAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Err(AnalysisError::ServiceUnavailable("API down".into()))
        }
    }

    #[tokio::test]
    async fn run_once_collection_failure_propagates() {
        let collector = FailingCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_once_snapshot_save_failure_continues() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = FailingSnapshotStore;

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert!(!cycle.snapshot_saved);
    }

    #[tokio::test]
    async fn run_once_alert_save_failure_continues() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = FailingAlertStore;
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
    }

    #[tokio::test]
    async fn run_once_notification_failure_continues() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = FailingNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
    }

    #[tokio::test]
    async fn run_once_ai_returns_diagnostic() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = DiagnosticAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert!(cycle.snapshot_saved);
    }

    #[tokio::test]
    async fn run_once_ai_failure_continues() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = FailingAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert!(cycle.snapshot_saved);
    }

    #[tokio::test]
    async fn run_once_ai_returns_none_with_alerts() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer; // returns Ok(None)
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true, // AI enabled
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
    }

    #[tokio::test]
    async fn run_once_ai_diagnostic_notification_failure_continues() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = DiagnosticAnalyzer;
        let notifier = FailingNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_once_auto_mode_executes_safe_actions() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Auto,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert_eq!(cycle.auto_actions_run, 1);
    }

    struct MediumAlertRule;

    impl Rule for MediumAlertRule {
        fn name(&self) -> &'static str {
            "medium_alert"
        }

        fn evaluate(&self, _snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
            vec![Alert {
                timestamp: Utc::now(),
                severity: Severity::Medium,
                rule: "medium_alert".to_string(),
                title: "Medium Alert".to_string(),
                details: "Test details".to_string(),
                suggested_actions: vec![SuggestedAction {
                    description: "Fix it".to_string(),
                    command: "echo fix".to_string(),
                    risk: ActionRisk::Safe,
                }],
            }]
        }
    }

    /// Track if AI analyze was called.
    struct TrackingAnalyzer {
        called: Mutex<bool>,
    }

    impl TrackingAnalyzer {
        fn new() -> Self {
            Self {
                called: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl AiAnalyzer for TrackingAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            *self.called.lock().expect("mutex poisoned") = true;
            Ok(None)
        }
    }

    #[tokio::test]
    async fn run_once_ai_skipped_for_medium_severity() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(MediumAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = TrackingAnalyzer::new();
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert!(!*analyzer.called.lock().expect("mutex poisoned"));
    }

    #[tokio::test]
    async fn run_once_observe_mode_skips_auto_execute() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Observe,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert_eq!(cycle.auto_actions_run, 0);
    }

    struct DangerousActionRule;

    impl Rule for DangerousActionRule {
        fn name(&self) -> &'static str {
            "dangerous_action"
        }

        fn evaluate(&self, _snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
            vec![Alert {
                timestamp: Utc::now(),
                severity: Severity::High,
                rule: "dangerous_action".to_string(),
                title: "Dangerous Alert".to_string(),
                details: "Test details".to_string(),
                suggested_actions: vec![SuggestedAction {
                    description: "Kill process".to_string(),
                    command: "kill -9 1234".to_string(),
                    risk: ActionRisk::Dangerous,
                }],
            }]
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_skips_dangerous_actions() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(DangerousActionRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Auto,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert_eq!(cycle.auto_actions_run, 0);
    }

    struct CountingActionLog {
        count: Mutex<usize>,
    }

    impl CountingActionLog {
        fn new() -> Self {
            Self {
                count: Mutex::new(0),
            }
        }
    }

    impl ActionLogStore for CountingActionLog {
        fn log_action(
            &self,
            _record: &ActionRecord,
        ) -> Result<(), crate::domain::ports::store::StoreError> {
            *self.count.lock().expect("mutex") += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_logs_actions() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let action_log = CountingActionLog::new();

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Auto,
            Some(&action_log as &dyn ActionLogStore),
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.auto_actions_run, 1);
        assert_eq!(*action_log.count.lock().expect("mutex"), 1);
    }

    #[tokio::test]
    async fn run_once_auto_mode_skips_protected_commands() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let protected = vec!["echo".to_string()];

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Auto,
            None,
            &protected,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.auto_actions_run, 0);
    }

    struct ModerateActionRule;

    impl Rule for ModerateActionRule {
        fn name(&self) -> &'static str {
            "moderate_action"
        }

        fn evaluate(&self, _snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
            vec![Alert {
                timestamp: Utc::now(),
                severity: Severity::High,
                rule: "moderate_action".to_string(),
                title: "Moderate Alert".to_string(),
                details: "Test details".to_string(),
                suggested_actions: vec![SuggestedAction {
                    description: "Restart service".to_string(),
                    command: "systemctl restart foo".to_string(),
                    risk: ActionRisk::Moderate,
                }],
            }]
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_skips_moderate_actions() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(ModerateActionRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Auto,
            None,
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert_eq!(cycle.auto_actions_run, 0);
    }

    struct AnalyzerWithActions;

    #[async_trait]
    impl AiAnalyzer for AnalyzerWithActions {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(Some(AiDiagnostic {
                timestamp: Utc::now(),
                summary: "Test diagnostic".to_string(),
                details: "Details".to_string(),
                confidence: 0.9,
                severity: Severity::High,
                suggested_actions: vec![SuggestedAction {
                    description: "AI fix".to_string(),
                    command: "echo ai_fix".to_string(),
                    risk: ActionRisk::Safe,
                }],
            }))
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_includes_ai_actions() {
        let collector = MockCollector;
        // No rule actions — only AI actions
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = AnalyzerWithActions;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let action_log = CountingActionLog::new();

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Auto,
            Some(&action_log as &dyn ActionLogStore),
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        // 1 from rule (echo fix) + 1 from AI (echo ai_fix)
        assert_eq!(cycle.auto_actions_run, 2);
        assert_eq!(*action_log.count.lock().expect("mutex"), 2);
    }

    struct DuplicateAnalyzer;

    #[async_trait]
    impl AiAnalyzer for DuplicateAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(Some(AiDiagnostic {
                timestamp: Utc::now(),
                summary: "Dup diagnostic".to_string(),
                details: "Details".to_string(),
                confidence: 0.9,
                severity: Severity::High,
                suggested_actions: vec![SuggestedAction {
                    description: "Same fix".to_string(),
                    // Same command as AlwaysAlertRule
                    command: "echo fix".to_string(),
                    risk: ActionRisk::Safe,
                }],
            }))
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_deduplicates_actions() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = DuplicateAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let action_log = CountingActionLog::new();

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            true,
            OperationMode::Auto,
            Some(&action_log as &dyn ActionLogStore),
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        // Same command "echo fix" appears in both rule and AI — executed only once
        assert_eq!(cycle.auto_actions_run, 1);
        assert_eq!(*action_log.count.lock().expect("mutex"), 1);
    }

    struct FailingActionLog;

    impl ActionLogStore for FailingActionLog {
        fn log_action(&self, _record: &ActionRecord) -> Result<(), StoreError> {
            Err(StoreError::WriteFailed("disk full".to_string()))
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_continues_on_log_failure() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let action_log = FailingActionLog;

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            false,
            OperationMode::Auto,
            Some(&action_log as &dyn ActionLogStore),
            &[],
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        // Action still executed despite log failure
        assert_eq!(cycle.auto_actions_run, 1);
    }

    #[test]
    fn is_command_protected_matches_word() {
        let protected = vec!["systemd".to_string(), "sshd".to_string()];
        assert!(is_command_protected("kill systemd", &protected));
        assert!(is_command_protected("systemctl restart sshd", &protected));
        assert!(!is_command_protected("echo hello", &protected));
    }

    #[test]
    fn is_command_protected_empty_list() {
        assert!(!is_command_protected("kill 1234", &[]));
    }
}
