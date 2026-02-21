use chrono::Utc;

use super::baseline::update_baselines;
use crate::domain::entities::alert::SuggestedAction;
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

/// Orchestrates a monitoring cycle: collect → persist → analyze → notify → remediate.
pub struct MonitorService<'a> {
    collector: &'a dyn SystemCollector,
    rule_engine: &'a RuleEngine,
    thresholds: &'a ThresholdSet,
    analyzer: &'a dyn AiAnalyzer,
    notifier: &'a dyn Notifier,
    alert_store: &'a dyn AlertStore,
    snapshot_store: &'a dyn SnapshotStore,
    baseline_store: &'a dyn BaselineStore,
    action_log_store: &'a dyn ActionLogStore,
    protected_commands: &'a [String],
    ai_enabled: bool,
    operation_mode: OperationMode,
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
        action_log_store: &'a dyn ActionLogStore,
        protected_commands: &'a [String],
        ai_enabled: bool,
        operation_mode: OperationMode,
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
            action_log_store,
            protected_commands,
            ai_enabled,
            operation_mode,
        }
    }

    /// Run a single monitoring cycle: collect → persist → analyze → notify.
    ///
    /// # Errors
    ///
    /// Returns an error if the system metrics collection fails.
    pub async fn run_once(&self) -> anyhow::Result<MonitorCycleResult> {
        let mut snapshot = self.collector.collect()?;

        // Exclude own process to prevent self-detection and kill loops
        let own_pid = std::process::id();
        snapshot.processes.retain(|p| p.pid != own_pid);

        let snapshot_saved = match self.snapshot_store.save_snapshot(&snapshot) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("Failed to save snapshot: {e}");
                false
            }
        };

        if snapshot_saved {
            if let Err(e) = update_baselines(self.baseline_store, &snapshot) {
                tracing::warn!("Failed to update baselines: {e}");
            }
        }

        let alerts = self.rule_engine.analyze(&snapshot, self.thresholds);

        if alerts.is_empty() {
            tracing::debug!("System OK — no alerts");
        }

        if !alerts.is_empty() {
            tracing::warn!("{} alert(s) detected", alerts.len());
        }

        for alert in &alerts {
            if let Err(e) = self.alert_store.save_alert(alert) {
                tracing::warn!("Failed to save alert: {e}");
            }
        }

        for alert in &alerts {
            if let Err(e) = self.notifier.notify(alert) {
                tracing::warn!("Alert notification failed: {e}");
            }
        }

        let mut auto_actions_run = 0usize;

        if self.operation_mode == OperationMode::Auto {
            for alert in &alerts {
                for action in &alert.suggested_actions {
                    if action.risk == ActionRisk::Safe {
                        if self.execute_action(action).await {
                            auto_actions_run += 1;
                        }
                    } else {
                        tracing::debug!(
                            "Action skipped (risk {:?}): {}",
                            action.risk,
                            action.description
                        );
                    }
                }
            }
        }

        let has_serious = alerts.iter().any(|a| a.severity >= Severity::High);
        if self.ai_enabled && has_serious {
            match self.analyzer.analyze(&snapshot, &alerts).await {
                Ok(Some(diag)) => {
                    if let Err(e) = self.notifier.notify_ai_diagnostic(&diag) {
                        tracing::warn!("AI diagnostic notification failed: {e}");
                    }
                    // Auto-execute safe actions suggested by AI
                    if self.operation_mode == OperationMode::Auto {
                        for action in &diag.suggested_actions {
                            if action.risk == ActionRisk::Safe {
                                if self.execute_action(action).await {
                                    auto_actions_run += 1;
                                }
                            } else {
                                tracing::debug!(
                                    "AI action skipped (risk {:?}): {}",
                                    action.risk,
                                    action.description
                                );
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("AI analysis failed: {e}");
                }
            }
        }

        Ok(MonitorCycleResult {
            alerts_count: alerts.len(),
            snapshot_saved,
            auto_actions_run,
        })
    }

    /// Execute a single safe action with allowlist check, logging, and notification.
    /// Returns `true` if the command executed successfully.
    async fn execute_action(&self, action: &SuggestedAction) -> bool {
        if contains_shell_metacharacters(&action.command) {
            tracing::warn!("Action blocked (shell metacharacters): {}", action.command);
            return false;
        }

        if is_command_protected(&action.command, self.protected_commands) {
            tracing::warn!("Action blocked (protected process): {}", action.command);
            return false;
        }

        tracing::info!("Auto-executing: {}", action.description);

        let timeout = std::time::Duration::from_secs(30);
        let (success, output_str) = match tokio::time::timeout(
            timeout,
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&action.command)
                .kill_on_drop(true)
                .output(),
        )
        .await
        {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let combined = format!("{stdout}{stderr}");
                let combined = truncate_output(combined.trim());
                (output.status.success(), combined)
            }
            Ok(Err(e)) => (false, format!("Launch error: {e}")),
            Err(_) => (false, "Timeout (30s)".to_string()),
        };

        // Log action to persistent store
        let record = ActionRecord {
            timestamp: Utc::now(),
            alert_id: None,
            command: action.command.clone(),
            result: Some(output_str.clone()),
            risk: action.risk,
        };
        if let Err(e) = self.action_log_store.log_action(&record) {
            tracing::warn!("Failed to log action: {e}");
        }

        // Notify user of action execution
        if let Err(e) = self
            .notifier
            .notify_action_executed(action, success, &output_str)
        {
            tracing::warn!("Action notification failed: {e}");
        }

        if success {
            tracing::info!("Command succeeded: {}", action.command);
        } else {
            tracing::warn!("Command failed: {}", action.command);
        }

        success
    }
}

/// Reject commands that contain shell metacharacters to prevent injection.
///
/// Only simple commands (single executable + arguments) are allowed.
/// Any chaining (`&&`, `||`, `;`), piping (`|`), subshells (`$(`, `` ` ``),
/// redirections (`>`, `<`), or glob/variable expansion (`$`, `*`, `?`) are blocked.
fn contains_shell_metacharacters(command: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        ";", "&&", "||", "|", "`", "$(", "${", ">", "<", "\n", "\r", "*", "?", "&",
    ];
    // Also block bare `$` followed by a letter (variable expansion)
    if command.bytes().enumerate().any(|(i, b)| {
        b == b'$'
            && command
                .as_bytes()
                .get(i + 1)
                .is_some_and(|&next| next.is_ascii_alphabetic() || next == b'_')
    }) {
        return true;
    }
    FORBIDDEN.iter().any(|meta| command.contains(meta))
}

/// Check if a command targets a protected process from the allowlist.
fn is_command_protected(command: &str, protected: &[String]) -> bool {
    let lower = command.to_lowercase();
    protected.iter().any(|p| lower.contains(&p.to_lowercase()))
}

/// Truncate command output for logging (max 2000 chars).
fn truncate_output(s: &str) -> String {
    const MAX_OUTPUT_CHARS: usize = 2000;
    if s.len() <= MAX_OUTPUT_CHARS {
        s.to_owned()
    } else {
        let mut result: String = s.chars().take(MAX_OUTPUT_CHARS).collect();
        result.push_str("... [truncated]");
        result
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::{Alert, SuggestedAction};
    use crate::domain::entities::diagnostic::AiDiagnostic;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
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

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            Ok(())
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
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

    struct MockActionLogStore {
        logs: Mutex<Vec<ActionRecord>>,
    }

    impl MockActionLogStore {
        fn new() -> Self {
            Self {
                logs: Mutex::new(vec![]),
            }
        }
    }

    impl ActionLogStore for MockActionLogStore {
        fn log_action(&self, record: &ActionRecord) -> Result<(), StoreError> {
            self.logs
                .lock()
                .expect("mutex poisoned")
                .push(record.clone());
            Ok(())
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            true,
            OperationMode::Observe,
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

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("dbus down".into()))
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            true,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            true,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            true, // AI enabled
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            true,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            true,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
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
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.alerts_count, 1);
        assert_eq!(cycle.auto_actions_run, 0);
    }

    #[tokio::test]
    async fn run_once_auto_mode_logs_executed_actions() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let action_log_store = MockActionLogStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.auto_actions_run, 1);

        // Verify action was logged to store
        let logs: Vec<ActionRecord> = action_log_store
            .logs
            .lock()
            .expect("mutex poisoned")
            .clone();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].command, "echo fix");
        assert!(logs[0].result.is_some());
        assert_eq!(logs[0].risk, ActionRisk::Safe);
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
        let action_log_store = MockActionLogStore::new();
        // "fix" appears in the command "echo fix", so it should be protected
        let protected: Vec<String> = vec!["fix".to_string()];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        // Action was blocked by allowlist
        assert_eq!(cycle.auto_actions_run, 0);

        // Verify nothing was logged
        let logs: Vec<ActionRecord> = action_log_store
            .logs
            .lock()
            .expect("mutex poisoned")
            .clone();
        assert!(logs.is_empty());
    }

    #[test]
    fn is_command_protected_matches_case_insensitive() {
        let protected = vec!["sshd".to_string(), "systemd".to_string()];
        assert!(is_command_protected("kill $(pidof sshd)", &protected));
        assert!(is_command_protected("systemctl stop SSHD", &protected));
        assert!(is_command_protected("kill systemd-logind", &protected));
        assert!(!is_command_protected("echo hello", &protected));
        assert!(!is_command_protected("ps aux | head -10", &protected));
    }

    #[test]
    fn is_command_protected_empty_list_allows_all() {
        let protected: Vec<String> = vec![];
        assert!(!is_command_protected("kill -9 1234", &protected));
        assert!(!is_command_protected("systemctl restart sshd", &protected));
    }

    struct TrackingNotifier {
        action_count: Mutex<usize>,
    }

    impl TrackingNotifier {
        fn new() -> Self {
            Self {
                action_count: Mutex::new(0),
            }
        }
    }

    impl Notifier for TrackingNotifier {
        fn notify(&self, _alert: &Alert) -> Result<(), NotificationError> {
            Ok(())
        }

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            *self.action_count.lock().expect("mutex poisoned") += 1;
            Ok(())
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
        ) -> Result<(), NotificationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_notifies_action_executed() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = TrackingNotifier::new();
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        assert_eq!(cycle.auto_actions_run, 1);

        // Verify notifier was called for the action
        let count = *notifier.action_count.lock().expect("mutex poisoned");
        assert_eq!(count, 1);
    }

    struct FailingActionLogStore;
    impl ActionLogStore for FailingActionLogStore {
        fn log_action(&self, _record: &ActionRecord) -> Result<(), StoreError> {
            Err(StoreError::WriteFailed("disk full".into()))
        }
    }

    #[tokio::test]
    async fn run_once_auto_mode_action_log_failure_continues() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(AlwaysAlertRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();

        let baseline_store = InMemoryStore::new();
        let action_log_store = FailingActionLogStore;
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        // Action still executes even if logging fails
        assert_eq!(cycle.auto_actions_run, 1);
    }

    #[test]
    fn metacharacters_blocks_chained_commands() {
        assert!(contains_shell_metacharacters("echo ok; rm -rf /"));
        assert!(contains_shell_metacharacters("cmd1 && cmd2"));
        assert!(contains_shell_metacharacters("cmd1 || cmd2"));
        assert!(contains_shell_metacharacters("ls | grep foo"));
    }

    #[test]
    fn metacharacters_blocks_subshells_and_redirections() {
        assert!(contains_shell_metacharacters("echo $(whoami)"));
        assert!(contains_shell_metacharacters("echo `id`"));
        assert!(contains_shell_metacharacters("cat > /etc/passwd"));
        assert!(contains_shell_metacharacters("cat < /etc/shadow"));
    }

    #[test]
    fn metacharacters_blocks_background_operator() {
        assert!(contains_shell_metacharacters("cmd1 & cmd2"));
        assert!(contains_shell_metacharacters("sleep 999 &"));
    }

    #[test]
    fn metacharacters_blocks_variable_expansion() {
        assert!(contains_shell_metacharacters("echo $HOME"));
        assert!(contains_shell_metacharacters("echo ${PATH}"));
        assert!(contains_shell_metacharacters("kill $pid"));
    }

    #[test]
    fn metacharacters_blocks_globs_and_newlines() {
        assert!(contains_shell_metacharacters("rm /tmp/*"));
        assert!(contains_shell_metacharacters("ls /tmp/?"));
        assert!(contains_shell_metacharacters("echo a\necho b"));
    }

    #[test]
    fn metacharacters_allows_safe_commands() {
        assert!(!contains_shell_metacharacters("echo fix"));
        assert!(!contains_shell_metacharacters("sync"));
        assert!(!contains_shell_metacharacters("systemctl restart nginx"));
        assert!(!contains_shell_metacharacters("kill -15 1234"));
        assert!(!contains_shell_metacharacters("free -h"));
    }

    #[test]
    fn truncate_output_short_string_unchanged() {
        let result = truncate_output("hello world");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn truncate_output_long_string_truncated() {
        let long = "x".repeat(3000);
        let result = truncate_output(&long);
        assert!(result.len() < 3000);
        assert!(result.ends_with("... [truncated]"));
    }

    #[test]
    fn truncate_output_exact_limit_unchanged() {
        let exact = "y".repeat(2000);
        let result = truncate_output(&exact);
        assert_eq!(result, exact);
    }

    #[tokio::test]
    async fn run_once_auto_mode_blocks_metacharacter_commands() {
        struct MetacharRule;
        impl Rule for MetacharRule {
            fn name(&self) -> &'static str {
                "metachar"
            }
            fn evaluate(
                &self,
                _snapshot: &SystemSnapshot,
                _thresholds: &ThresholdSet,
            ) -> Vec<Alert> {
                vec![Alert {
                    timestamp: Utc::now(),
                    severity: Severity::High,
                    rule: "metachar".to_string(),
                    title: "Injection attempt".to_string(),
                    details: "Details".to_string(),
                    suggested_actions: vec![SuggestedAction {
                        description: "Bad command".to_string(),
                        command: "echo ok; rm -rf /".to_string(),
                        risk: ActionRisk::Safe,
                    }],
                }]
            }
        }

        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![Box::new(MetacharRule)]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let action_log_store = MockActionLogStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Auto,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());
        let cycle = result.expect("run_once failed");
        // Command was blocked by metacharacter check
        assert_eq!(cycle.auto_actions_run, 0);
        let logs: Vec<ActionRecord> = action_log_store
            .logs
            .lock()
            .expect("mutex poisoned")
            .clone();
        assert!(logs.is_empty());
    }

    #[tokio::test]
    async fn run_once_excludes_own_pid_from_snapshot() {
        struct SelfProcessCollector;

        impl SystemCollector for SelfProcessCollector {
            fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
                Ok(SystemSnapshot {
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
                    processes: vec![
                        ProcessInfo {
                            pid: std::process::id(),
                            ppid: 1,
                            name: "vigil".to_string(),
                            cmdline: "vigil daemon".to_string(),
                            state: ProcessState::Running,
                            cpu_percent: 5.0,
                            rss_mb: 100,
                            vms_mb: 200,
                            user: "root".to_string(),
                            start_time: 0,
                            open_fds: 10,
                        },
                        ProcessInfo {
                            pid: 9999,
                            ppid: 1,
                            name: "nginx".to_string(),
                            cmdline: "/usr/sbin/nginx".to_string(),
                            state: ProcessState::Running,
                            cpu_percent: 2.0,
                            rss_mb: 50,
                            vms_mb: 100,
                            user: "www-data".to_string(),
                            start_time: 0,
                            open_fds: 20,
                        },
                    ],
                    disks: vec![],
                    journal_entries: vec![],
                })
            }
        }

        let collector = SelfProcessCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;
        let alert_store = MockAlertStore::new();
        let snapshot_store = MockSnapshotStore::new();
        let baseline_store = InMemoryStore::new();
        let action_log_store = InMemoryStore::new();
        let protected: Vec<String> = vec![];
        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &alert_store,
            &snapshot_store,
            &baseline_store,
            &action_log_store,
            &protected,
            false,
            OperationMode::Observe,
        );

        let result = service.run_once().await;
        assert!(result.is_ok());

        let saved = snapshot_store
            .snapshots
            .lock()
            .expect("mutex poisoned")
            .last()
            .cloned()
            .expect("no snapshot saved");
        assert_eq!(saved.processes.len(), 1);
        assert_eq!(saved.processes[0].pid, 9999);
        assert!(!saved.processes.iter().any(|p| p.pid == std::process::id()));
    }
}
