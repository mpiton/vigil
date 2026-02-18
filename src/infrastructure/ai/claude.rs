use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::domain::entities::{AiDiagnostic, Alert, SystemSnapshot};
use crate::domain::ports::{AiAnalyzer, AnalysisError};
use crate::domain::value_objects::Severity;

use super::prompt_builder::PromptBuilder;

/// Maximum response size from the claude CLI (4 MB).
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum stderr bytes included in error messages.
const MAX_STDERR_BYTES: usize = 512;

pub struct ClaudeCliAnalyzer {
    cooldown_secs: u64,
    last_call: Mutex<Option<Instant>>,
    model: String,
    timeout_secs: u64,
}

impl ClaudeCliAnalyzer {
    #[must_use]
    pub const fn new(model: String, cooldown_secs: u64, timeout_secs: u64) -> Self {
        Self {
            cooldown_secs,
            last_call: Mutex::new(None),
            model,
            timeout_secs,
        }
    }

    /// Atomically check cooldown and claim the call slot.
    ///
    /// Returns `true` if the call is permitted (and records the timestamp),
    /// `false` if still within the cooldown window.
    fn try_claim(&self) -> Result<bool, AnalysisError> {
        let mut guard = self
            .last_call
            .lock()
            .map_err(|e| AnalysisError::ServiceUnavailable(format!("lock poisoned: {e}")))?;
        let allowed =
            guard.is_none_or(|last| last.elapsed() >= Duration::from_secs(self.cooldown_secs));
        if allowed {
            *guard = Some(Instant::now());
        }
        drop(guard);
        Ok(allowed)
    }
}

#[async_trait]
impl AiAnalyzer for ClaudeCliAnalyzer {
    async fn analyze(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &[Alert],
    ) -> Result<Option<AiDiagnostic>, AnalysisError> {
        if !self.try_claim()? {
            return Ok(None);
        }

        let prompt = PromptBuilder::build(snapshot, alerts);

        let output = tokio::time::timeout(
            Duration::from_secs(self.timeout_secs),
            tokio::process::Command::new("claude")
                .args([
                    "--print",
                    "--output-format",
                    "json",
                    "--model",
                    &self.model,
                    "--",
                    &prompt,
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| AnalysisError::Timeout)?
        .map_err(|e| AnalysisError::ServiceUnavailable(format!("failed to run claude: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(
                &output.stderr[..output.stderr.len().min(MAX_STDERR_BYTES)],
            );
            return Err(AnalysisError::ServiceUnavailable(format!(
                "claude exited with {}: {stderr}",
                output.status
            )));
        }

        if output.stdout.len() > MAX_RESPONSE_BYTES {
            return Err(AnalysisError::InvalidResponse(format!(
                "response too large: {} bytes",
                output.stdout.len()
            )));
        }

        parse_response(&output.stdout).map(Some)
    }
}

#[derive(Deserialize)]
struct ClaudeCliResponse {
    result: String,
}

#[derive(Deserialize)]
struct RawDiagnostic {
    summary: String,
    details: String,
    severity: Severity,
    confidence: f64,
}

fn parse_response(stdout: &[u8]) -> Result<AiDiagnostic, AnalysisError> {
    if stdout.is_empty() {
        return Err(AnalysisError::InvalidResponse(
            "empty response from claude".into(),
        ));
    }

    let text = std::str::from_utf8(stdout)
        .map_err(|e| AnalysisError::InvalidResponse(format!("invalid UTF-8: {e}")))?;

    let inner = match serde_json::from_str::<ClaudeCliResponse>(text) {
        Ok(envelope) => envelope.result,
        Err(_) => text.to_owned(),
    };

    let raw: RawDiagnostic = serde_json::from_str(&inner)
        .map_err(|e| AnalysisError::InvalidResponse(format!("failed to parse diagnostic: {e}")))?;

    Ok(AiDiagnostic {
        timestamp: Utc::now(),
        summary: raw.summary,
        details: raw.details,
        severity: raw.severity,
        confidence: raw.confidence.clamp(0.0, 1.0),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_constructs_correctly() {
        let analyzer = ClaudeCliAnalyzer::new("test-model".into(), 60, 30);
        assert_eq!(analyzer.model, "test-model");
        assert_eq!(analyzer.cooldown_secs, 60);
        assert_eq!(analyzer.timeout_secs, 30);
    }

    #[test]
    fn try_claim_returns_true_initially() {
        let analyzer = ClaudeCliAnalyzer::new("m".into(), 60, 30);
        assert!(analyzer.try_claim().expect("should not error"));
    }

    #[test]
    fn try_claim_returns_false_within_cooldown() {
        let analyzer = ClaudeCliAnalyzer::new("m".into(), 3600, 30);
        // First claim succeeds and sets the timestamp
        assert!(analyzer.try_claim().expect("first claim"));
        // Second claim within cooldown fails
        assert!(!analyzer.try_claim().expect("second claim"));
    }

    #[test]
    fn try_claim_returns_true_after_cooldown() {
        let analyzer = ClaudeCliAnalyzer::new("m".into(), 0, 30);
        // First claim succeeds
        assert!(analyzer.try_claim().expect("first claim"));
        // With 0 cooldown, immediate second claim succeeds
        assert!(analyzer.try_claim().expect("second claim"));
    }

    #[test]
    fn try_claim_is_atomic() {
        let analyzer = ClaudeCliAnalyzer::new("m".into(), 3600, 30);
        // After claiming, the timestamp is immediately set
        assert!(analyzer.try_claim().expect("claim"));
        assert!(analyzer.last_call.lock().expect("lock").is_some());
    }

    #[test]
    fn parse_valid_direct_json() {
        let json = br#"{"summary":"High memory","details":"RAM at 95%","severity":"High","confidence":0.9}"#;
        let diag = parse_response(json).expect("should parse");
        assert_eq!(diag.summary, "High memory");
        assert_eq!(diag.details, "RAM at 95%");
        assert_eq!(diag.severity, Severity::High);
        assert!((diag.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_claude_cli_envelope() {
        let inner = r#"{"summary":"OK","details":"All good","severity":"Low","confidence":0.5}"#;
        let envelope = format!(
            r#"{{"type":"result","subtype":"success","result":"{escaped}","session_id":"abc"}}"#,
            escaped = inner.replace('"', r#"\""#)
        );
        let diag = parse_response(envelope.as_bytes()).expect("should parse envelope");
        assert_eq!(diag.summary, "OK");
        assert_eq!(diag.severity, Severity::Low);
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let bad = b"this is not json";
        let result = parse_response(bad);
        assert!(result.is_err());
        let err = result.expect_err("should be error");
        assert!(err.to_string().contains("failed to parse diagnostic"));
    }

    #[test]
    fn parse_empty_response_returns_error() {
        let result = parse_response(b"");
        assert!(result.is_err());
        let err = result.expect_err("should be error");
        assert!(err.to_string().contains("empty response"));
    }

    #[test]
    fn confidence_is_clamped() {
        let json = br#"{"summary":"s","details":"d","severity":"Low","confidence":1.5}"#;
        let diag = parse_response(json).expect("should parse");
        assert!((diag.confidence - 1.0).abs() < f64::EPSILON);
    }
}
