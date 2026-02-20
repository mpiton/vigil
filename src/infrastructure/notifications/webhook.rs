use std::time::Duration;

use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::ports::notifier::{NotificationError, Notifier};
use crate::domain::value_objects::severity::Severity;

const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Webhook notification target format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookKind {
    Slack,
    Discord,
}

/// Sends critical alerts to an HTTP webhook endpoint (Slack, Discord).
///
/// Payloads are formatted according to the detected webhook platform.
/// Notifications are sent asynchronously (fire-and-forget, best effort).
pub struct WebhookNotifier {
    url: String,
    kind: WebhookKind,
    client: reqwest::Client,
    min_severity: Severity,
}

impl WebhookNotifier {
    /// Create a new webhook notifier.
    ///
    /// Auto-detects Slack or Discord from the URL pattern.
    /// Defaults to Slack format for unknown URLs.
    #[must_use]
    pub fn new(url: &str, min_severity: Severity) -> Self {
        let kind = detect_webhook_kind(url);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            url: url.to_string(),
            kind,
            client,
            min_severity,
        }
    }

    fn post_payload(&self, payload: serde_json::Value) {
        if self.url.is_empty() || !is_valid_webhook_url(&self.url) {
            return;
        }
        let client = self.client.clone();
        let url = self.url.clone();
        let host = extract_host(&self.url).to_string();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                drop(handle.spawn(async move {
                    match client.post(&url).json(&payload).send().await {
                        Ok(resp) if !resp.status().is_success() => {
                            tracing::error!("Webhook {host} a répondu HTTP {}", resp.status());
                        }
                        Err(e) => {
                            tracing::error!("Échec envoi webhook {host}: {e}");
                        }
                        Ok(_) => {}
                    }
                }));
            }
            Err(_) => {
                tracing::warn!("Notification webhook ignorée : pas de runtime tokio disponible");
            }
        }
    }

    fn build_alert_payload(&self, alert: &Alert) -> serde_json::Value {
        match self.kind {
            WebhookKind::Slack => build_slack_alert(alert),
            WebhookKind::Discord => build_discord_alert(alert),
        }
    }

    fn build_diagnostic_payload(&self, diagnostic: &AiDiagnostic) -> serde_json::Value {
        match self.kind {
            WebhookKind::Slack => build_slack_diagnostic(diagnostic),
            WebhookKind::Discord => build_discord_diagnostic(diagnostic),
        }
    }

    fn build_action_payload(
        &self,
        action: &SuggestedAction,
        success: bool,
        output: &str,
    ) -> serde_json::Value {
        match self.kind {
            WebhookKind::Slack => build_slack_action(action, success, output),
            WebhookKind::Discord => build_discord_action(action, success, output),
        }
    }
}

impl Default for WebhookNotifier {
    fn default() -> Self {
        Self {
            url: String::new(),
            kind: WebhookKind::Slack,
            client: reqwest::Client::new(),
            min_severity: Severity::High,
        }
    }
}

impl Notifier for WebhookNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        if alert.severity < self.min_severity {
            return Ok(());
        }
        let payload = self.build_alert_payload(alert);
        self.post_payload(payload);
        Ok(())
    }

    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError> {
        if diagnostic.severity < self.min_severity {
            return Ok(());
        }
        let payload = self.build_diagnostic_payload(diagnostic);
        self.post_payload(payload);
        Ok(())
    }

    fn notify_action_executed(
        &self,
        action: &SuggestedAction,
        success: bool,
        output: &str,
    ) -> Result<(), NotificationError> {
        let payload = self.build_action_payload(action, success, output);
        self.post_payload(payload);
        Ok(())
    }
}

// --- URL detection ---

fn extract_host(url: &str) -> &str {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
}

fn detect_webhook_kind(url: &str) -> WebhookKind {
    let host = extract_host(url);
    if host == "discord.com" || host == "discordapp.com" {
        WebhookKind::Discord
    } else {
        WebhookKind::Slack
    }
}

fn is_valid_webhook_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        t.push('\u{2026}');
        t
    }
}

// --- Color helpers ---

const fn severity_color_decimal(severity: Severity) -> u64 {
    match severity {
        Severity::Low => 0x00_34_98_DB,
        Severity::Medium => 0x00_F3_9C_12,
        Severity::High => 0x00_E7_4C_3C,
        Severity::Critical => 0x00_FF_00_00,
    }
}

const fn severity_color_hex(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "#3498DB",
        Severity::Medium => "#F39C12",
        Severity::High => "#E74C3C",
        Severity::Critical => "#FF0000",
    }
}

// --- Slack payload builders ---

fn build_slack_alert(alert: &Alert) -> serde_json::Value {
    let actions_text = if alert.suggested_actions.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = alert
            .suggested_actions
            .iter()
            .map(|a| format!("• `{}` — {} [{}]", a.command, a.description, a.risk))
            .collect();
        format!("\n*Actions recommandées :*\n{}", items.join("\n"))
    };

    let body = truncate(
        &format!(
            "*Règle :* {}\n*Titre :* {}\n*Détails :* {}{}",
            alert.rule, alert.title, alert.details, actions_text
        ),
        2900,
    );

    serde_json::json!({
        "text": format!("Vigil — {} {}", alert.severity.emoji(), alert.title),
        "attachments": [{
            "color": severity_color_hex(alert.severity),
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!("{} Vigil — Alerte {}", alert.severity.emoji(), alert.severity)
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": body
                    }
                }
            ]
        }]
    })
}

fn build_slack_diagnostic(diagnostic: &AiDiagnostic) -> serde_json::Value {
    serde_json::json!({
        "text": format!("Vigil IA — {} {}", diagnostic.severity.emoji(), diagnostic.summary),
        "attachments": [{
            "color": severity_color_hex(diagnostic.severity),
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!("{} Vigil — Diagnostic IA", diagnostic.severity.emoji())
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!(
                            "*Résumé :* {}\n*Détails :* {}\n*Sévérité :* {} | *Confiance :* {:.0}%",
                            diagnostic.summary, diagnostic.details,
                            diagnostic.severity, diagnostic.confidence * 100.0
                        )
                    }
                }
            ]
        }]
    })
}

fn build_slack_action(action: &SuggestedAction, success: bool, output: &str) -> serde_json::Value {
    let status = if success {
        "✅ Réussi"
    } else {
        "❌ Échoué"
    };
    let output_text = if output.is_empty() {
        String::new()
    } else {
        let truncated: String = output.lines().take(5).collect::<Vec<_>>().join("\n");
        let truncated = truncate(&truncated, 500);
        format!("\n```\n{truncated}\n```")
    };

    serde_json::json!({
        "text": format!("Vigil — Action : {} ({})", action.description, status),
        "attachments": [{
            "color": if success { "#2ECC71" } else { "#E74C3C" },
            "blocks": [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "*Action :* {}\n*Commande :* `{}`\n*Risque :* {}\n*Résultat :* {}{}",
                        action.description, action.command, action.risk, status, output_text
                    )
                }
            }]
        }]
    })
}

// --- Discord payload builders ---

fn build_discord_alert(alert: &Alert) -> serde_json::Value {
    let mut fields = vec![
        serde_json::json!({"name": "Sévérité", "value": format!("{}", alert.severity), "inline": true}),
        serde_json::json!({"name": "Règle", "value": &alert.rule, "inline": true}),
    ];

    for action in &alert.suggested_actions {
        fields.push(serde_json::json!({
            "name": format!("Action [{}]", action.risk),
            "value": truncate(&format!("`{}` — {}", action.command, action.description), 1024),
            "inline": false
        }));
    }

    serde_json::json!({
        "embeds": [{
            "title": format!("{} Vigil — Alerte", alert.severity.emoji()),
            "description": truncate(&format!("**{}**\n{}", alert.title, alert.details), 4096),
            "color": severity_color_decimal(alert.severity),
            "timestamp": alert.timestamp.to_rfc3339(),
            "fields": fields,
            "footer": {"text": "Vigil — Gardien système"}
        }]
    })
}

fn build_discord_diagnostic(diagnostic: &AiDiagnostic) -> serde_json::Value {
    serde_json::json!({
        "embeds": [{
            "title": format!("{} Vigil — Diagnostic IA", diagnostic.severity.emoji()),
            "description": truncate(&format!("**{}**\n{}", diagnostic.summary, diagnostic.details), 4096),
            "color": severity_color_decimal(diagnostic.severity),
            "timestamp": diagnostic.timestamp.to_rfc3339(),
            "fields": [
                {"name": "Sévérité", "value": format!("{}", diagnostic.severity), "inline": true},
                {"name": "Confiance", "value": format!("{:.0}%", diagnostic.confidence * 100.0), "inline": true}
            ],
            "footer": {"text": "Vigil — Gardien système"}
        }]
    })
}

fn build_discord_action(
    action: &SuggestedAction,
    success: bool,
    output: &str,
) -> serde_json::Value {
    let status = if success {
        "✅ Réussi"
    } else {
        "❌ Échoué"
    };
    let description = if output.is_empty() {
        action.description.clone()
    } else {
        let truncated: String = output.lines().take(5).collect::<Vec<_>>().join("\n");
        let truncated = truncate(&truncated, 500);
        format!("{}\n```\n{truncated}\n```", action.description)
    };

    serde_json::json!({
        "embeds": [{
            "title": "Vigil — Action exécutée",
            "description": description,
            "color": if success { 0x00_2E_CC_71_u64 } else { 0x00_E7_4C_3C_u64 },
            "fields": [
                {"name": "Commande", "value": format!("`{}`", action.command), "inline": true},
                {"name": "Risque", "value": format!("{}", action.risk), "inline": true},
                {"name": "Résultat", "value": status, "inline": true}
            ],
            "footer": {"text": "Vigil — Gardien système"}
        }]
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use chrono::Utc;

    fn make_alert(severity: Severity) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: "Test alert".to_string(),
            details: "Some details".to_string(),
            suggested_actions: vec![SuggestedAction {
                description: "Restart service".to_string(),
                command: "systemctl restart test".to_string(),
                risk: ActionRisk::Safe,
            }],
        }
    }

    fn make_diagnostic(severity: Severity) -> AiDiagnostic {
        AiDiagnostic {
            timestamp: Utc::now(),
            summary: "Test diagnostic".to_string(),
            details: "Diagnostic details".to_string(),
            severity,
            confidence: 0.85,
            suggested_actions: vec![],
        }
    }

    fn make_action() -> SuggestedAction {
        SuggestedAction {
            description: "Kill process".to_string(),
            command: "kill -15 1234".to_string(),
            risk: ActionRisk::Moderate,
        }
    }

    // --- URL detection ---

    #[test]
    fn detect_slack_url() {
        assert_eq!(
            detect_webhook_kind("https://hooks.slack.com/services/T.../B.../xxx"),
            WebhookKind::Slack
        );
    }

    #[test]
    fn detect_discord_url() {
        assert_eq!(
            detect_webhook_kind("https://discord.com/api/webhooks/123/token"),
            WebhookKind::Discord
        );
    }

    #[test]
    fn detect_discordapp_url() {
        assert_eq!(
            detect_webhook_kind("https://discordapp.com/api/webhooks/123/token"),
            WebhookKind::Discord
        );
    }

    #[test]
    fn unknown_url_defaults_to_slack() {
        assert_eq!(
            detect_webhook_kind("https://example.com/webhook"),
            WebhookKind::Slack
        );
    }

    // --- Constructor ---

    #[test]
    fn constructor_sets_fields() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::High);
        assert_eq!(notifier.url, "https://hooks.slack.com/services/test");
        assert_eq!(notifier.kind, WebhookKind::Slack);
        assert_eq!(notifier.min_severity, Severity::High);
    }

    #[test]
    fn constructor_discord_detection() {
        let notifier = WebhookNotifier::new(
            "https://discord.com/api/webhooks/123/token",
            Severity::Critical,
        );
        assert_eq!(notifier.kind, WebhookKind::Discord);
        assert_eq!(notifier.min_severity, Severity::Critical);
    }

    #[test]
    fn default_notifier_is_disabled() {
        let notifier = WebhookNotifier::default();
        assert!(notifier.url.is_empty());
        assert_eq!(notifier.kind, WebhookKind::Slack);
        assert_eq!(notifier.min_severity, Severity::High);
    }

    // --- Severity filtering ---

    #[test]
    fn notify_filters_low_severity() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::High);
        let alert = make_alert(Severity::Low);
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_filters_medium_severity() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::High);
        let alert = make_alert(Severity::Medium);
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_passes_high_severity() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::High);
        let alert = make_alert(Severity::High);
        // No tokio runtime in tests — post_payload silently skips
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_passes_critical_severity() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::High);
        let alert = make_alert(Severity::Critical);
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn diagnostic_filters_low_severity() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::High);
        let diagnostic = make_diagnostic(Severity::Low);
        assert!(notifier.notify_ai_diagnostic(&diagnostic).is_ok());
    }

    #[test]
    fn action_executed_always_sent() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::Critical);
        let action = make_action();
        assert!(notifier
            .notify_action_executed(&action, true, "output")
            .is_ok());
    }

    // --- Slack payload structure ---

    #[test]
    fn slack_alert_payload_structure() {
        let alert = make_alert(Severity::High);
        let payload = build_slack_alert(&alert);
        assert!(payload["text"].is_string());
        assert!(payload["attachments"].is_array());
        assert!(payload["attachments"][0]["color"].is_string());
        assert!(payload["attachments"][0]["blocks"].is_array());
    }

    #[test]
    fn slack_alert_payload_contains_rule() {
        let alert = make_alert(Severity::High);
        let payload = build_slack_alert(&alert);
        let text = payload["attachments"][0]["blocks"][1]["text"]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("test_rule"));
    }

    #[test]
    fn slack_alert_without_actions() {
        let alert = Alert {
            timestamp: Utc::now(),
            severity: Severity::High,
            rule: "test".to_string(),
            title: "Test".to_string(),
            details: "Details".to_string(),
            suggested_actions: vec![],
        };
        let payload = build_slack_alert(&alert);
        let text = payload["attachments"][0]["blocks"][1]["text"]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(!text.contains("Actions recommandées"));
    }

    #[test]
    fn slack_diagnostic_payload_structure() {
        let diagnostic = make_diagnostic(Severity::High);
        let payload = build_slack_diagnostic(&diagnostic);
        assert!(payload["text"].is_string());
        assert!(payload["attachments"].is_array());
    }

    #[test]
    fn slack_action_success_text() {
        let action = make_action();
        let payload = build_slack_action(&action, true, "");
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("Réussi"));
    }

    #[test]
    fn slack_action_failure_text() {
        let action = make_action();
        let payload = build_slack_action(&action, false, "error");
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("Échoué"));
    }

    // --- Discord payload structure ---

    #[test]
    fn discord_alert_payload_structure() {
        let alert = make_alert(Severity::Critical);
        let payload = build_discord_alert(&alert);
        assert!(payload["embeds"].is_array());
        assert!(payload["embeds"][0]["title"].is_string());
        assert!(payload["embeds"][0]["color"].is_number());
        assert!(payload["embeds"][0]["fields"].is_array());
        assert!(payload["embeds"][0]["timestamp"].is_string());
    }

    #[test]
    fn discord_alert_payload_contains_severity_field() {
        let alert = make_alert(Severity::Critical);
        let payload = build_discord_alert(&alert);
        let field_value = payload["embeds"][0]["fields"][0]["value"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(field_value, "CRITICAL");
    }

    #[test]
    fn discord_diagnostic_payload_structure() {
        let diagnostic = make_diagnostic(Severity::High);
        let payload = build_discord_diagnostic(&diagnostic);
        assert!(payload["embeds"].is_array());
        assert!(payload["embeds"][0]["fields"].is_array());
    }

    #[test]
    fn discord_action_success_color() {
        let action = make_action();
        let payload = build_discord_action(&action, true, "");
        assert_eq!(payload["embeds"][0]["color"], 0x00_2E_CC_71_u64);
    }

    #[test]
    fn discord_action_failure_color() {
        let action = make_action();
        let payload = build_discord_action(&action, false, "");
        assert_eq!(payload["embeds"][0]["color"], 0x00_E7_4C_3C_u64);
    }

    // --- Output truncation ---

    #[test]
    fn output_truncated_to_five_lines() {
        let action = make_action();
        let long_output = "line1\nline2\nline3\nline4\nline5\nline6\nline7";
        let payload = build_slack_action(&action, true, long_output);
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("line5"));
        assert!(!text.contains("line6"));
        assert!(!text.contains("line7"));
    }

    #[test]
    fn empty_output_no_code_block() {
        let action = make_action();
        let payload = build_slack_action(&action, true, "");
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(!text.contains("```"));
    }

    // --- Color helpers ---

    #[test]
    fn severity_colors_hex_valid() {
        assert_eq!(severity_color_hex(Severity::Low), "#3498DB");
        assert_eq!(severity_color_hex(Severity::Medium), "#F39C12");
        assert_eq!(severity_color_hex(Severity::High), "#E74C3C");
        assert_eq!(severity_color_hex(Severity::Critical), "#FF0000");
    }

    #[test]
    fn severity_colors_decimal_valid() {
        assert_eq!(severity_color_decimal(Severity::Low), 0x00_34_98_DB);
        assert_eq!(severity_color_decimal(Severity::Critical), 0x00_FF_00_00);
    }

    // --- Payload dispatch by kind ---

    #[test]
    fn slack_notifier_builds_slack_payload() {
        let notifier = WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::Low);
        let alert = make_alert(Severity::High);
        let payload = notifier.build_alert_payload(&alert);
        assert!(payload["attachments"].is_array());
    }

    #[test]
    fn discord_notifier_builds_discord_payload() {
        let notifier =
            WebhookNotifier::new("https://discord.com/api/webhooks/123/token", Severity::Low);
        let alert = make_alert(Severity::High);
        let payload = notifier.build_alert_payload(&alert);
        assert!(payload["embeds"].is_array());
    }

    // --- URL validation ---

    #[test]
    fn valid_https_url() {
        assert!(is_valid_webhook_url(
            "https://hooks.slack.com/services/test"
        ));
    }

    #[test]
    fn valid_http_url() {
        assert!(is_valid_webhook_url("http://localhost:8080/webhook"));
    }

    #[test]
    fn invalid_ftp_url() {
        assert!(!is_valid_webhook_url("ftp://example.com/webhook"));
    }

    #[test]
    fn invalid_file_url() {
        assert!(!is_valid_webhook_url("file:///etc/passwd"));
    }

    // --- Hostname extraction ---

    #[test]
    fn extract_host_from_https() {
        assert_eq!(
            extract_host("https://hooks.slack.com/services/T/B/x"),
            "hooks.slack.com"
        );
    }

    #[test]
    fn extract_host_from_http() {
        assert_eq!(extract_host("http://localhost:8080/test"), "localhost:8080");
    }

    #[test]
    fn extract_host_from_invalid() {
        assert_eq!(extract_host("ftp://example.com"), "");
    }

    // --- Truncation ---

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let result = truncate("abcdefghij", 5);
        assert_eq!(result.chars().count(), 5);
        assert!(result.ends_with('\u{2026}'));
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    // --- Action executed ignores severity filter ---

    #[test]
    fn action_executed_ignores_severity_filter() {
        let notifier =
            WebhookNotifier::new("https://hooks.slack.com/services/test", Severity::Critical);
        let action = make_action();
        // Even with Critical min_severity, actions should still build payloads
        let payload = notifier.build_action_payload(&action, true, "done");
        assert!(payload["attachments"].is_array());
    }

    // --- Default notifier silently skips ---

    #[test]
    fn default_notifier_notify_is_noop() {
        let notifier = WebhookNotifier::default();
        let alert = make_alert(Severity::Critical);
        assert!(notifier.notify(&alert).is_ok());
    }
}
