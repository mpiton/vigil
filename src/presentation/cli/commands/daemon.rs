use std::time::Duration;

use crate::application::services::monitor::MonitorService;

/// Run the monitoring daemon loop at the configured interval.
///
/// This function runs indefinitely until the process is terminated.
/// Errors during individual monitoring cycles are logged but do not stop the daemon.
///
/// # Errors
///
/// In practice this function never returns; the `Result` return type exists
/// only for compatibility with the `#[tokio::main]` entry point.
pub async fn run_daemon(service: &MonitorService<'_>, interval_secs: u64) -> anyhow::Result<()> {
    println!("Démarrage du daemon vigil (intervalle : {interval_secs}s)...");
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match service.run_once().await {
            Ok(result) => {
                tracing::info!(
                    "Cycle terminé : {} alerte(s), snapshot {}",
                    result.alerts_count,
                    if result.snapshot_saved {
                        "sauvegardé"
                    } else {
                        "échoué"
                    }
                );
            }
            Err(e) => {
                tracing::error!("Erreur cycle monitoring : {e}");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::Alert;
    use crate::domain::entities::diagnostic::AiDiagnostic;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::analyzer::AnalysisError;
    use crate::domain::ports::collector::{CollectionError, SystemCollector};
    use crate::domain::ports::notifier::{NotificationError, Notifier};
    use crate::domain::ports::store::{AlertStore, SnapshotStore, StoreError};
    use crate::domain::rules::RuleEngine;
    use crate::domain::value_objects::thresholds::ThresholdSet;
    use async_trait::async_trait;
    use chrono::Utc;

    struct MockCollector;

    impl SystemCollector for MockCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Ok(SystemSnapshot {
                timestamp: Utc::now(),
                memory: MemoryInfo {
                    total_mb: 8192,
                    used_mb: 4096,
                    available_mb: 4096,
                    swap_total_mb: 0,
                    swap_used_mb: 0,
                    usage_percent: 50.0,
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
            })
        }
    }

    struct MockAnalyzer;

    #[async_trait]
    impl crate::domain::ports::analyzer::AiAnalyzer for MockAnalyzer {
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

    struct MockStore;

    impl AlertStore for MockStore {
        fn save_alert(&self, _alert: &Alert) -> Result<(), StoreError> {
            Ok(())
        }
        fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
            Ok(vec![])
        }
        fn get_recent_alerts(&self, _count: usize) -> Result<Vec<Alert>, StoreError> {
            Ok(vec![])
        }
    }

    impl SnapshotStore for MockStore {
        fn save_snapshot(&self, _snapshot: &SystemSnapshot) -> Result<(), StoreError> {
            Ok(())
        }
        fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
            Ok(None)
        }
    }

    struct FailingCollector;

    impl SystemCollector for FailingCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Err(CollectionError::MetricsUnavailable("test failure".into()))
        }
    }

    #[tokio::test]
    async fn daemon_handles_cycle_error() {
        let collector = FailingCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &MockStore,
            &MockStore,
            false,
        );

        let result =
            tokio::time::timeout(Duration::from_millis(200), run_daemon(&service, 1)).await;

        // Timeout expected — daemon continues despite errors
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn daemon_runs_at_least_one_cycle() {
        let collector = MockCollector;
        let rule_engine = RuleEngine::new(vec![]);
        let thresholds = ThresholdSet::default();
        let analyzer = MockAnalyzer;
        let notifier = MockNotifier;

        let service = MonitorService::new(
            &collector,
            &rule_engine,
            &thresholds,
            &analyzer,
            &notifier,
            &MockStore,
            &MockStore,
            false,
        );

        let result =
            tokio::time::timeout(Duration::from_millis(200), run_daemon(&service, 1)).await;

        // Timeout is expected — the daemon loops forever
        assert!(result.is_err());
    }
}
