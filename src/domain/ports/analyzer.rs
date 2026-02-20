use async_trait::async_trait;
use thiserror::Error;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::entities::process::ProcessInfo;
use crate::domain::entities::snapshot::SystemSnapshot;

#[derive(Error, Debug)]
pub enum AnalysisError {
    #[error("AI service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("invalid response from AI: {0}")]
    InvalidResponse(String),
    #[error("rate limited")]
    RateLimited,
    #[error("analysis timed out")]
    Timeout,
}

#[async_trait]
pub trait AiAnalyzer: Send + Sync {
    /// Analyze a system snapshot and recent alerts using AI.
    ///
    /// # Errors
    ///
    /// Returns `AnalysisError` if the AI service is unavailable,
    /// the response is invalid, the request is rate-limited, or
    /// the analysis times out.
    async fn analyze(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &[Alert],
    ) -> Result<Option<AiDiagnostic>, AnalysisError>;

    /// Explain a specific process behavior using AI.
    ///
    /// # Errors
    ///
    /// Returns `AnalysisError` if the AI service is unavailable,
    /// the response is invalid, the request is rate-limited, or
    /// the analysis times out.
    async fn explain_process(
        &self,
        _process: &ProcessInfo,
    ) -> Result<Option<String>, AnalysisError> {
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn analysis_error_display() {
        let err = AnalysisError::ServiceUnavailable("connection refused".to_string());
        assert_eq!(
            err.to_string(),
            "AI service unavailable: connection refused"
        );

        let err = AnalysisError::RateLimited;
        assert_eq!(err.to_string(), "rate limited");
    }

    use crate::domain::entities::process::{ProcessInfo, ProcessState};

    struct StubAnalyzer;

    #[async_trait]
    impl AiAnalyzer for StubAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn default_explain_process_returns_none() {
        let analyzer = StubAnalyzer;
        let process = ProcessInfo {
            pid: 1,
            ppid: 0,
            name: "init".to_string(),
            cmdline: "/sbin/init".to_string(),
            state: ProcessState::Running,
            cpu_percent: 0.0,
            rss_mb: 10,
            vms_mb: 50,
            user: "root".to_string(),
            start_time: 0,
            open_fds: 5,
        };
        let result = analyzer.explain_process(&process).await;
        assert!(result.is_ok());
        assert!(result.expect("should be ok").is_none());
    }
}
