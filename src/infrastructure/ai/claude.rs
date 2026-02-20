use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::domain::entities::alert::SuggestedAction;
use crate::domain::entities::process::ProcessInfo;
use crate::domain::entities::{AiDiagnostic, Alert, SystemSnapshot};
use crate::domain::ports::{AiAnalyzer, AnalysisError};
use crate::domain::value_objects::action_risk::ActionRisk;
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

    /// Run the claude CLI with the given prompt and return raw stdout bytes.
    async fn run_claude_cli(&self, prompt: &str) -> Result<Vec<u8>, AnalysisError> {
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
                    prompt,
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

        if output.stdout.is_empty() {
            return Err(AnalysisError::InvalidResponse(
                "empty response from claude".into(),
            ));
        }

        Ok(output.stdout)
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
        let stdout = self.run_claude_cli(&prompt).await?;

        parse_response(&stdout).map(Some)
    }

    async fn explain_process(
        &self,
        process: &ProcessInfo,
    ) -> Result<Option<String>, AnalysisError> {
        if !self.try_claim()? {
            return Ok(None);
        }

        let prompt = format!(
            "Explique le comportement de ce processus Linux :\n\
            - Nom : {name}\n\
            - Ligne de commande : {cmdline}\n\
            - État : {state}\n\
            - Mémoire RSS : {rss_mb} MB\n\
            - Mémoire virtuelle : {vms_mb} MB\n\
            - CPU : {cpu_percent}%\n\
            - PID parent : {ppid}\n\
            - Descripteurs de fichiers ouverts : {open_fds}\n\
            - Utilisateur : {user}\n\
            \n\
            Explique en français :\n\
            1. À quoi sert ce processus\n\
            2. Si son comportement est normal\n\
            3. Si sa consommation de ressources est attendue",
            name = process.name,
            cmdline = process.cmdline,
            state = process.state,
            rss_mb = process.rss_mb,
            vms_mb = process.vms_mb,
            cpu_percent = process.cpu_percent,
            ppid = process.ppid,
            open_fds = process.open_fds,
            user = process.user,
        );

        let stdout = self.run_claude_cli(&prompt).await?;

        let text = std::str::from_utf8(&stdout)
            .map_err(|e| AnalysisError::InvalidResponse(format!("invalid UTF-8: {e}")))?;

        let result_text = extract_result(text)?;

        Ok(Some(result_text))
    }
}

#[derive(Deserialize)]
struct ClaudeCliEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    result: serde_json::Value,
}

#[derive(Deserialize)]
struct RawDiagnostic {
    summary: String,
    details: String,
    severity: Severity,
    confidence: f64,
    #[serde(default)]
    suggested_actions: Vec<RawSuggestedAction>,
}

#[derive(Deserialize)]
struct RawSuggestedAction {
    description: String,
    command: String,
    #[serde(default = "default_risk")]
    risk: String,
}

fn default_risk() -> String {
    "Dangerous".to_string()
}

/// Truncate a string to at most `max_bytes` without splitting a UTF-8 codepoint.
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn parse_response(stdout: &[u8]) -> Result<AiDiagnostic, AnalysisError> {
    if stdout.is_empty() {
        return Err(AnalysisError::InvalidResponse(
            "empty response from claude".into(),
        ));
    }

    let text = std::str::from_utf8(stdout)
        .map_err(|e| AnalysisError::InvalidResponse(format!("invalid UTF-8: {e}")))?;

    tracing::debug!(response_len = text.len(), "raw claude CLI response");

    // The Claude CLI --output-format json returns a JSON array of events:
    // [{"type":"system",...}, ..., {"type":"result","result":"..."}]
    // We need to find the "result" event and extract the diagnostic.
    let result_text = extract_result(text)?;

    tracing::debug!(
        result_preview = truncate_str(&result_text, 500),
        "extracted result text"
    );

    let raw: RawDiagnostic = serde_json::from_str(&result_text).map_err(|e| {
        AnalysisError::InvalidResponse(format!(
            "failed to parse diagnostic: {e} — raw: {}",
            truncate_str(&result_text, 200)
        ))
    })?;

    Ok(to_diagnostic(raw))
}

/// Extract the `result` field from the Claude CLI JSON output.
/// Handles both array format `[..., {"type":"result","result":"..."}]`
/// and single-object format `{"type":"result","result":"..."}`.
fn extract_result(text: &str) -> Result<String, AnalysisError> {
    // Try as array of events first (standard --output-format json)
    if let Ok(events) = serde_json::from_str::<Vec<ClaudeCliEvent>>(text) {
        if let Some(result_event) = events.iter().rfind(|e| e.event_type == "result") {
            return value_to_string(&result_event.result);
        }
        return Err(AnalysisError::InvalidResponse(
            "no result event in claude response".into(),
        ));
    }

    // Try as single object with result field
    if let Ok(event) = serde_json::from_str::<ClaudeCliEvent>(text) {
        if event.event_type == "result" {
            return value_to_string(&event.result);
        }
    }

    // Fallback: treat as raw diagnostic JSON
    Ok(text.to_owned())
}

/// Convert a `serde_json::Value` to a string suitable for diagnostic parsing.
/// If the value is a string, return it (it may contain embedded JSON).
/// If the value is an object, serialize it back to a JSON string.
fn value_to_string(value: &serde_json::Value) -> Result<String, AnalysisError> {
    match value {
        serde_json::Value::String(s) => Ok(strip_markdown_fences(s)),
        serde_json::Value::Object(_) => serde_json::to_string(value)
            .map_err(|e| AnalysisError::InvalidResponse(format!("failed to serialize: {e}"))),
        _ => Err(AnalysisError::InvalidResponse(format!(
            "unexpected result type: {value}"
        ))),
    }
}

/// Strip markdown code fences (```json ... ```) from a string.
/// Claude often wraps JSON responses in code blocks.
fn strip_markdown_fences(s: &str) -> String {
    let trimmed = s.trim();
    trimmed.strip_prefix("```").map_or_else(
        || s.to_owned(),
        |rest| {
            let after_tag = rest.find('\n').map_or(rest, |pos| &rest[pos + 1..]);
            let content = after_tag
                .rfind("```")
                .map_or(after_tag, |pos| &after_tag[..pos]);
            content.trim().to_owned()
        },
    )
}

fn to_diagnostic(raw: RawDiagnostic) -> AiDiagnostic {
    let suggested_actions = raw
        .suggested_actions
        .into_iter()
        .map(|a| {
            let risk = match a.risk.to_lowercase().as_str() {
                "safe" => ActionRisk::Safe,
                "moderate" => ActionRisk::Moderate,
                "dangerous" => ActionRisk::Dangerous,
                other => {
                    tracing::warn!("Risque IA inconnu '{other}', défaut à Dangerous");
                    ActionRisk::Dangerous
                }
            };
            SuggestedAction {
                description: a.description,
                command: a.command,
                risk,
            }
        })
        .collect();

    AiDiagnostic {
        timestamp: Utc::now(),
        summary: raw.summary,
        details: raw.details,
        severity: raw.severity,
        confidence: raw.confidence.clamp(0.0, 1.0),
        suggested_actions,
    }
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
    fn strip_markdown_fences_extracts_json() {
        let input = "```json\n{\"key\":\"value\"}\n```";
        assert_eq!(strip_markdown_fences(input), r#"{"key":"value"}"#);
    }

    #[test]
    fn strip_markdown_fences_no_fences_passthrough() {
        let input = r#"{"key":"value"}"#;
        assert_eq!(strip_markdown_fences(input), input);
    }

    #[test]
    fn strip_markdown_fences_no_language_tag() {
        let input = "```\n{\"key\":\"value\"}\n```";
        assert_eq!(strip_markdown_fences(input), r#"{"key":"value"}"#);
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
    fn parse_claude_cli_single_event_string_result() {
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
    fn parse_claude_cli_single_event_object_result() {
        let envelope = r#"{"type":"result","subtype":"success","result":{"summary":"OK","details":"All good","severity":"Low","confidence":0.5},"session_id":"abc"}"#;
        let diag = parse_response(envelope.as_bytes()).expect("should parse object result");
        assert_eq!(diag.summary, "OK");
        assert_eq!(diag.details, "All good");
        assert_eq!(diag.severity, Severity::Low);
    }

    #[test]
    fn parse_claude_cli_event_array() {
        let array = r#"[{"type":"system","subtype":"init","cwd":"/tmp","session_id":"abc","tools":[]},{"type":"result","subtype":"success","result":"{\"summary\":\"Disk full\",\"details\":\"AppImage mount full\",\"severity\":\"Critical\",\"confidence\":0.95}","session_id":"abc"}]"#;
        let diag = parse_response(array.as_bytes()).expect("should parse event array");
        assert_eq!(diag.summary, "Disk full");
        assert_eq!(diag.severity, Severity::Critical);
    }

    #[test]
    fn parse_claude_cli_event_array_object_result() {
        let array = r#"[{"type":"system","subtype":"init","cwd":"/tmp","session_id":"abc","tools":[]},{"type":"result","subtype":"success","result":{"summary":"Disk full","details":"AppImage mount full","severity":"Critical","confidence":0.95},"session_id":"abc"}]"#;
        let diag = parse_response(array.as_bytes()).expect("should parse array with object result");
        assert_eq!(diag.summary, "Disk full");
        assert_eq!(diag.severity, Severity::Critical);
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

    #[test]
    fn parse_response_with_suggested_actions() {
        let json = br#"{"summary":"High memory","details":"RAM at 95%","severity":"High","confidence":0.9,"suggested_actions":[{"description":"Free cache","command":"sync && echo 3 > /proc/sys/vm/drop_caches","risk":"Safe"}]}"#;
        let diag = parse_response(json).expect("should parse");
        assert_eq!(diag.suggested_actions.len(), 1);
        assert_eq!(diag.suggested_actions[0].risk, ActionRisk::Safe);
        assert_eq!(
            diag.suggested_actions[0].command,
            "sync && echo 3 > /proc/sys/vm/drop_caches"
        );
    }

    #[test]
    fn parse_response_without_suggested_actions_defaults_empty() {
        let json = br#"{"summary":"OK","details":"All good","severity":"Low","confidence":0.5}"#;
        let diag = parse_response(json).expect("should parse");
        assert!(diag.suggested_actions.is_empty());
    }

    #[test]
    fn parse_response_with_unknown_risk_defaults_dangerous() {
        let json = br#"{"summary":"s","details":"d","severity":"Low","confidence":0.5,"suggested_actions":[{"description":"test","command":"echo test","risk":"unknown"}]}"#;
        let diag = parse_response(json).expect("should parse");
        assert_eq!(diag.suggested_actions[0].risk, ActionRisk::Dangerous);
    }

    #[test]
    fn parse_response_omitted_risk_defaults_dangerous() {
        let json = br#"{"summary":"s","details":"d","severity":"Low","confidence":0.5,"suggested_actions":[{"description":"test","command":"echo test"}]}"#;
        let diag = parse_response(json).expect("should parse");
        assert_eq!(diag.suggested_actions.len(), 1);
        assert_eq!(diag.suggested_actions[0].risk, ActionRisk::Dangerous);
    }

    #[test]
    fn truncate_str_short_string_unchanged() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact_boundary() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_cuts_at_limit() {
        assert_eq!(truncate_str("hello world", 5), "hello");
    }

    #[test]
    fn truncate_str_respects_utf8_boundary() {
        // 'é' is 2 bytes in UTF-8: if we cut at byte 1, we must back up to 0
        let s = "é";
        assert_eq!(s.len(), 2);
        assert_eq!(truncate_str(s, 1), "");
    }

    #[test]
    fn truncate_str_multibyte_preserves_complete_chars() {
        // "café" = 'c'(1) + 'a'(1) + 'f'(1) + 'é'(2) = 5 bytes
        let s = "café";
        assert_eq!(s.len(), 5);
        // Cutting at 4 bytes would split 'é', so back up to 3
        assert_eq!(truncate_str(s, 4), "caf");
        // Cutting at 5 keeps everything
        assert_eq!(truncate_str(s, 5), "café");
    }

    #[test]
    fn truncate_str_empty_string() {
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn truncate_str_zero_limit() {
        assert_eq!(truncate_str("hello", 0), "");
    }
}
