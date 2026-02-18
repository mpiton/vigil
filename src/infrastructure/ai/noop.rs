use async_trait::async_trait;

use crate::domain::entities::{AiDiagnostic, Alert, SystemSnapshot};
use crate::domain::ports::{AiAnalyzer, AnalysisError};

/// No-op AI analyzer that always returns `None`.
///
/// Used when AI analysis is disabled or as a fallback when the configured
/// provider is unavailable.
pub struct NoopAnalyzer;

impl NoopAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for NoopAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AiAnalyzer for NoopAnalyzer {
    async fn analyze(
        &self,
        _snapshot: &SystemSnapshot,
        _alerts: &[Alert],
    ) -> Result<Option<AiDiagnostic>, AnalysisError> {
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::{CpuInfo, MemoryInfo, SystemSnapshot};
    use chrono::Utc;

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 8192,
                used_mb: 4096,
                available_mb: 4096,
                swap_total_mb: 2048,
                swap_used_mb: 0,
                usage_percent: 50.0,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 25.0,
                per_core_usage: vec![25.0],
                core_count: 4,
                load_avg_1m: 1.0,
                load_avg_5m: 0.8,
                load_avg_15m: 0.5,
            },
            processes: vec![],
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[tokio::test]
    async fn analyze_returns_none() {
        let analyzer = NoopAnalyzer::new();
        let snapshot = make_snapshot();
        let alerts: Vec<Alert> = vec![];

        let result = analyzer.analyze(&snapshot, &alerts).await;
        assert!(result.is_ok());
        assert!(result.expect("should be ok").is_none());
    }

    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    #[test]
    fn new_and_default_produce_analyzer() {
        let a = NoopAnalyzer::new();
        let b = <NoopAnalyzer as Default>::default();
        assert_send_sync(&a);
        assert_send_sync(&b);
    }
}
