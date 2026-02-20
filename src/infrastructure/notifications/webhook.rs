use std::fmt::Write;
use std::time::Duration;

use serde_json::{json, Value};
use tracing::warn;

use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::ports::notifier::{NotificationError, Notifier};
use crate::domain::value_objects::severity::Severity;

/// Webhook notification format, auto-detected from the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookFormat {
    Slack,
    Discord,
    Generic,
}

/// Sends alert notifications to an HTTP webhook endpoint.
///
/// Supports Slack (Block Kit with colored attachments), Discord (embeds),
/// and generic JSON payloads. The format is auto-detected from the webhook URL.
///
/// Only alerts with severity >= `High` are dispatched (configurable via constructor).
/// All HTTP errors are logged but never propagated (best-effort delivery).
pub struct WebhookNotifier {
    url: String,
    client: reqwest::Client,
    min_severity: Severity,
}

impl WebhookNotifier {
    /// Creates a new webhook notifier targeting the given URL.
    ///
    /// The HTTP client is configured with a 5-second timeout covering
    /// DNS resolution, connection, and response.
    ///
    /// # Errors
    ///
    /// Returns `NotificationError::ChannelUnavailable` if the HTTP client
    /// cannot be initialized (e.g. TLS backend failure).
    pub fn new(url: String) -> Result<Self, NotificationError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                NotificationError::ChannelUnavailable(format!(
                    "impossible de créer le client HTTP: {e}"
                ))
            })?;

        Ok(Self {
            url,
            client,
            min_severity: Severity::High,
        })
    }

    fn detect_format(&self) -> WebhookFormat {
        if self.url.contains("hooks.slack.com") {
            WebhookFormat::Slack
        } else if self.url.contains("discord.com/api/webhooks")
            || self.url.contains("discordapp.com/api/webhooks")
        {
            WebhookFormat::Discord
        } else {
            WebhookFormat::Generic
        }
    }

    /// Sends a JSON payload to the webhook URL. Best-effort: errors are logged
    /// and swallowed so that a failing webhook never blocks the monitoring cycle.
    fn send_payload(&self, payload: &Value) {
        let client = self.client.clone();
        let url = self.url.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            match client.post(&url).json(&payload).send().await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => warn!("Webhook HTTP {}", resp.status()),
                Err(e) => warn!("Webhook error: {e}"),
            }
        });
    }

    // --- Color helpers ---

    const fn severity_color_hex(severity: Severity) -> &'static str {
        match severity {
            Severity::Low => "#3498DB",
            Severity::Medium => "#E67E22",
            Severity::High => "#E74C3C",
            Severity::Critical => "#FF0000",
        }
    }

    const fn severity_color_decimal(severity: Severity) -> u32 {
        match severity {
            Severity::Low => 0x00_34_98_DB,
            Severity::Medium => 0x00_E6_7E_22,
            Severity::High => 0x00_E7_4C_3C,
            Severity::Critical => 0x00_FF_00_00,
        }
    }

    // --- Alert formatting ---

    fn format_alert(&self, alert: &Alert) -> Value {
        match self.detect_format() {
            WebhookFormat::Slack => Self::format_alert_slack(alert),
            WebhookFormat::Discord => Self::format_alert_discord(alert),
            WebhookFormat::Generic => Self::format_alert_generic(alert),
        }
    }

    fn format_alert_slack(alert: &Alert) -> Value {
        let mut text = alert.details.clone();
        if !alert.suggested_actions.is_empty() {
            text.push_str("\n*Actions suggérées :*");
            for action in &alert.suggested_actions {
                let _ = write!(
                    text,
                    "\n\u{2022} [{}] `{}` \u{2014} {}",
                    action.risk, action.command, action.description
                );
            }
        }

        json!({
            "attachments": [{
                "color": Self::severity_color_hex(alert.severity),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": format!("{} Vigil \u{2014} {}", alert.severity.emoji(), alert.title)
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            { "type": "mrkdwn", "text": format!("*Sévérité :*\n{}", alert.severity) },
                            { "type": "mrkdwn", "text": format!("*Règle :*\n{}", alert.rule) }
                        ]
                    },
                    {
                        "type": "section",
                        "text": { "type": "mrkdwn", "text": text }
                    }
                ]
            }]
        })
    }

    fn format_alert_discord(alert: &Alert) -> Value {
        let mut fields = vec![
            json!({ "name": "Sévérité", "value": format!("{}", alert.severity), "inline": true }),
            json!({ "name": "Règle", "value": &alert.rule, "inline": true }),
        ];

        for action in &alert.suggested_actions {
            fields.push(json!({
                "name": format!("Action [{}]", action.risk),
                "value": format!("`{}`\n{}", action.command, action.description),
                "inline": false
            }));
        }

        json!({
            "username": "Vigil",
            "embeds": [{
                "title": format!("{} {}", alert.severity.emoji(), alert.title),
                "description": &alert.details,
                "color": Self::severity_color_decimal(alert.severity),
                "fields": fields,
                "timestamp": alert.timestamp.to_rfc3339()
            }]
        })
    }

    fn format_alert_generic(alert: &Alert) -> Value {
        json!({
            "source": "vigil",
            "severity": format!("{}", alert.severity),
            "title": &alert.title,
            "details": &alert.details,
            "rule": &alert.rule,
            "timestamp": alert.timestamp.to_rfc3339(),
            "actions": alert.suggested_actions.iter().map(|a| json!({
                "description": &a.description,
                "command": &a.command,
                "risk": format!("{}", a.risk)
            })).collect::<Vec<_>>()
        })
    }

    // --- AI diagnostic formatting ---

    fn format_diagnostic(&self, diagnostic: &AiDiagnostic) -> Value {
        match self.detect_format() {
            WebhookFormat::Slack => Self::format_diagnostic_slack(diagnostic),
            WebhookFormat::Discord => Self::format_diagnostic_discord(diagnostic),
            WebhookFormat::Generic => Self::format_diagnostic_generic(diagnostic),
        }
    }

    fn format_diagnostic_slack(diagnostic: &AiDiagnostic) -> Value {
        json!({
            "attachments": [{
                "color": Self::severity_color_hex(diagnostic.severity),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "\u{1F916} Vigil \u{2014} Analyse IA"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            { "type": "mrkdwn", "text": format!("*Sévérité :*\n{}", diagnostic.severity) },
                            { "type": "mrkdwn", "text": format!("*Confiance :*\n{:.0}%", diagnostic.confidence * 100.0) }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!("*{}*\n{}", diagnostic.summary, diagnostic.details)
                        }
                    }
                ]
            }]
        })
    }

    fn format_diagnostic_discord(diagnostic: &AiDiagnostic) -> Value {
        json!({
            "username": "Vigil",
            "embeds": [{
                "title": "\u{1F916} Analyse IA",
                "description": &diagnostic.details,
                "color": Self::severity_color_decimal(diagnostic.severity),
                "fields": [
                    { "name": "Résumé", "value": &diagnostic.summary, "inline": false },
                    { "name": "Sévérité", "value": format!("{}", diagnostic.severity), "inline": true },
                    { "name": "Confiance", "value": format!("{:.0}%", diagnostic.confidence * 100.0), "inline": true }
                ],
                "timestamp": diagnostic.timestamp.to_rfc3339()
            }]
        })
    }

    fn format_diagnostic_generic(diagnostic: &AiDiagnostic) -> Value {
        json!({
            "source": "vigil",
            "type": "ai_diagnostic",
            "severity": format!("{}", diagnostic.severity),
            "summary": &diagnostic.summary,
            "details": &diagnostic.details,
            "confidence": diagnostic.confidence,
            "timestamp": diagnostic.timestamp.to_rfc3339()
        })
    }

    // --- Action executed formatting ---

    fn format_action(&self, action: &SuggestedAction, success: bool, output: &str) -> Value {
        match self.detect_format() {
            WebhookFormat::Slack => Self::format_action_slack(action, success, output),
            WebhookFormat::Discord => Self::format_action_discord(action, success, output),
            WebhookFormat::Generic => Self::format_action_generic(action, success, output),
        }
    }

    fn format_action_slack(action: &SuggestedAction, success: bool, output: &str) -> Value {
        let status = if success {
            "\u{2713} Réussie"
        } else {
            "\u{2717} Échouée"
        };
        let color = if success { "#2ECC71" } else { "#E74C3C" };
        let icon = if success { "\u{2713}" } else { "\u{2717}" };

        let mut body = format!("{}\n`{}`", action.description, action.command);
        if !output.is_empty() {
            let _ = write!(body, "\n```\n{output}\n```");
        }

        json!({
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": format!("{icon} Vigil \u{2014} Action exécutée")
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            { "type": "mrkdwn", "text": format!("*Statut :*\n{status}") },
                            { "type": "mrkdwn", "text": format!("*Risque :*\n{}", action.risk) }
                        ]
                    },
                    {
                        "type": "section",
                        "text": { "type": "mrkdwn", "text": body }
                    }
                ]
            }]
        })
    }

    fn format_action_discord(action: &SuggestedAction, success: bool, output: &str) -> Value {
        let icon = if success { "\u{2713}" } else { "\u{2717}" };
        let color: u32 = if success {
            0x00_2E_CC_71
        } else {
            0x00_E7_4C_3C
        };

        let mut fields = vec![
            json!({ "name": "Statut", "value": if success { "Réussie" } else { "Échouée" }, "inline": true }),
            json!({ "name": "Risque", "value": format!("{}", action.risk), "inline": true }),
            json!({ "name": "Commande", "value": format!("`{}`", action.command), "inline": false }),
        ];
        if !output.is_empty() {
            fields.push(
                json!({ "name": "Sortie", "value": format!("```\n{output}\n```"), "inline": false }),
            );
        }

        json!({
            "username": "Vigil",
            "embeds": [{
                "title": format!("{icon} Action exécutée"),
                "description": &action.description,
                "color": color,
                "fields": fields,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        })
    }

    fn format_action_generic(action: &SuggestedAction, success: bool, output: &str) -> Value {
        json!({
            "source": "vigil",
            "type": "action_executed",
            "description": &action.description,
            "command": &action.command,
            "risk": format!("{}", action.risk),
            "success": success,
            "output": output,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })
    }
}

impl Notifier for WebhookNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        if alert.severity < self.min_severity {
            return Ok(());
        }
        let payload = self.format_alert(alert);
        self.send_payload(&payload);
        Ok(())
    }

    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError> {
        if diagnostic.severity < self.min_severity {
            return Ok(());
        }
        let payload = self.format_diagnostic(diagnostic);
        self.send_payload(&payload);
        Ok(())
    }

    fn notify_action_executed(
        &self,
        action: &SuggestedAction,
        success: bool,
        output: &str,
    ) -> Result<(), NotificationError> {
        let payload = self.format_action(action, success, output);
        self.send_payload(&payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use chrono::Utc;

    fn make_notifier(url: &str) -> WebhookNotifier {
        WebhookNotifier::new(url.to_string()).expect("build HTTP client")
    }

    fn make_alert(severity: Severity, actions: Vec<SuggestedAction>) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "ram_critical".to_string(),
            title: "Utilisation mémoire élevée".to_string(),
            details: "RAM à 95%".to_string(),
            suggested_actions: actions,
        }
    }

    fn make_action() -> SuggestedAction {
        SuggestedAction {
            description: "Tuer le processus lourd".to_string(),
            command: "kill -9 1234".to_string(),
            risk: ActionRisk::Dangerous,
        }
    }

    fn make_diagnostic(severity: Severity) -> AiDiagnostic {
        AiDiagnostic {
            timestamp: Utc::now(),
            summary: "Analyse mémoire".to_string(),
            details: "Utilisation RAM critique".to_string(),
            severity,
            confidence: 0.87,
            suggested_actions: vec![],
        }
    }

    // --- Format detection ---

    #[test]
    fn detect_slack_url() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        assert_eq!(n.detect_format(), WebhookFormat::Slack);
    }

    #[test]
    fn detect_discord_url() {
        let n = make_notifier("https://discord.com/api/webhooks/123/token");
        assert_eq!(n.detect_format(), WebhookFormat::Discord);
    }

    #[test]
    fn detect_discordapp_url() {
        let n = make_notifier("https://discordapp.com/api/webhooks/123/token");
        assert_eq!(n.detect_format(), WebhookFormat::Discord);
    }

    #[test]
    fn detect_generic_url() {
        let n = make_notifier("https://example.com/webhook");
        assert_eq!(n.detect_format(), WebhookFormat::Generic);
    }

    // --- Severity filtering (no HTTP call, no runtime needed) ---

    #[test]
    fn notify_skips_low_severity() {
        let n = make_notifier("https://example.com/webhook");
        let alert = make_alert(Severity::Low, vec![]);
        assert!(n.notify(&alert).is_ok());
    }

    #[test]
    fn notify_skips_medium_severity() {
        let n = make_notifier("https://example.com/webhook");
        let alert = make_alert(Severity::Medium, vec![]);
        assert!(n.notify(&alert).is_ok());
    }

    #[test]
    fn diagnostic_skips_low_severity() {
        let n = make_notifier("https://example.com/webhook");
        let diag = make_diagnostic(Severity::Low);
        assert!(n.notify_ai_diagnostic(&diag).is_ok());
    }

    #[test]
    fn diagnostic_skips_medium_severity() {
        let n = make_notifier("https://example.com/webhook");
        let diag = make_diagnostic(Severity::Medium);
        assert!(n.notify_ai_diagnostic(&diag).is_ok());
    }

    // --- Slack alert payload ---

    #[test]
    fn slack_alert_has_attachment_with_color() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let alert = make_alert(Severity::High, vec![]);
        let payload = n.format_alert(&alert);

        let att = &payload["attachments"][0];
        assert_eq!(att["color"], "#E74C3C");
        assert!(att["blocks"].is_array());
    }

    #[test]
    fn slack_alert_header_contains_title() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let alert = make_alert(Severity::Critical, vec![]);
        let payload = n.format_alert(&alert);

        let header = &payload["attachments"][0]["blocks"][0]["text"]["text"];
        let text = header.as_str().expect("header text");
        assert!(text.contains("Vigil"));
        assert!(text.contains("Utilisation mémoire élevée"));
    }

    #[test]
    fn slack_alert_includes_actions() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let alert = make_alert(Severity::High, vec![make_action()]);
        let payload = n.format_alert(&alert);

        let body = &payload["attachments"][0]["blocks"][2]["text"]["text"];
        let text = body.as_str().expect("body text");
        assert!(text.contains("kill -9 1234"));
        assert!(text.contains("dangerous"));
    }

    #[test]
    fn slack_critical_color_is_red() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let alert = make_alert(Severity::Critical, vec![]);
        let payload = n.format_alert(&alert);
        assert_eq!(payload["attachments"][0]["color"], "#FF0000");
    }

    // --- Discord alert payload ---

    #[test]
    fn discord_alert_has_embed_with_color() {
        let n = make_notifier("https://discord.com/api/webhooks/123/token");
        let alert = make_alert(Severity::High, vec![]);
        let payload = n.format_alert(&alert);

        assert_eq!(payload["username"], "Vigil");
        let embed = &payload["embeds"][0];
        assert_eq!(embed["color"], 0x00_E7_4C_3C);
        assert!(embed["title"].as_str().is_some());
        assert!(embed["timestamp"].as_str().is_some());
    }

    #[test]
    fn discord_alert_includes_action_fields() {
        let n = make_notifier("https://discord.com/api/webhooks/123/token");
        let alert = make_alert(Severity::High, vec![make_action()]);
        let payload = n.format_alert(&alert);

        let fields = payload["embeds"][0]["fields"].as_array().expect("fields");
        // 2 base fields (severity, rule) + 1 action field
        assert_eq!(fields.len(), 3);
        let action_field = &fields[2];
        assert!(action_field["name"]
            .as_str()
            .expect("name")
            .contains("dangerous"));
        assert!(action_field["value"]
            .as_str()
            .expect("value")
            .contains("kill -9 1234"));
    }

    // --- Generic alert payload ---

    #[test]
    fn generic_alert_has_flat_structure() {
        let n = make_notifier("https://example.com/webhook");
        let alert = make_alert(Severity::High, vec![make_action()]);
        let payload = n.format_alert(&alert);

        assert_eq!(payload["source"], "vigil");
        assert_eq!(payload["severity"], "HIGH");
        assert_eq!(payload["title"], "Utilisation mémoire élevée");
        assert_eq!(payload["rule"], "ram_critical");
        let actions = payload["actions"].as_array().expect("actions array");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["risk"], "dangerous");
    }

    // --- Diagnostic payloads ---

    #[test]
    fn slack_diagnostic_has_confidence_field() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let diag = make_diagnostic(Severity::High);
        let payload = n.format_diagnostic(&diag);

        let fields = &payload["attachments"][0]["blocks"][1]["fields"];
        let confidence = fields[1]["text"].as_str().expect("confidence text");
        assert!(confidence.contains("87%"));
    }

    #[test]
    fn discord_diagnostic_has_summary_and_confidence() {
        let n = make_notifier("https://discord.com/api/webhooks/123/token");
        let diag = make_diagnostic(Severity::High);
        let payload = n.format_diagnostic(&diag);

        let fields = payload["embeds"][0]["fields"].as_array().expect("fields");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0]["name"], "Résumé");
        assert_eq!(fields[0]["value"], "Analyse mémoire");
        assert_eq!(fields[2]["value"], "87%");
    }

    #[test]
    fn generic_diagnostic_has_all_fields() {
        let n = make_notifier("https://example.com/webhook");
        let diag = make_diagnostic(Severity::High);
        let payload = n.format_diagnostic(&diag);

        assert_eq!(payload["source"], "vigil");
        assert_eq!(payload["type"], "ai_diagnostic");
        assert_eq!(payload["severity"], "HIGH");
        assert_eq!(payload["summary"], "Analyse mémoire");
        assert_eq!(payload["confidence"], 0.87);
    }

    // --- Action executed payloads ---

    #[test]
    fn slack_action_success_uses_green_color() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let action = make_action();
        let payload = n.format_action(&action, true, "");

        assert_eq!(payload["attachments"][0]["color"], "#2ECC71");
    }

    #[test]
    fn slack_action_failure_uses_red_color() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let action = make_action();
        let payload = n.format_action(&action, false, "error output");

        assert_eq!(payload["attachments"][0]["color"], "#E74C3C");
        let body = payload["attachments"][0]["blocks"][2]["text"]["text"]
            .as_str()
            .expect("body");
        assert!(body.contains("error output"));
    }

    #[test]
    fn discord_action_includes_output_field_when_non_empty() {
        let n = make_notifier("https://discord.com/api/webhooks/123/token");
        let action = make_action();
        let payload = n.format_action(&action, true, "done");

        let fields = payload["embeds"][0]["fields"].as_array().expect("fields");
        assert_eq!(fields.len(), 4); // status, risk, command, output
        assert_eq!(fields[3]["name"], "Sortie");
    }

    #[test]
    fn discord_action_omits_output_field_when_empty() {
        let n = make_notifier("https://discord.com/api/webhooks/123/token");
        let action = make_action();
        let payload = n.format_action(&action, true, "");

        let fields = payload["embeds"][0]["fields"].as_array().expect("fields");
        assert_eq!(fields.len(), 3); // status, risk, command (no output)
    }

    #[test]
    fn generic_action_has_all_fields() {
        let n = make_notifier("https://example.com/webhook");
        let action = make_action();
        let payload = n.format_action(&action, false, "error");

        assert_eq!(payload["source"], "vigil");
        assert_eq!(payload["type"], "action_executed");
        assert_eq!(payload["command"], "kill -9 1234");
        assert_eq!(payload["risk"], "dangerous");
        assert_eq!(payload["success"], false);
        assert_eq!(payload["output"], "error");
    }

    #[test]
    fn empty_actions_list_omitted_from_slack_body() {
        let n = make_notifier("https://hooks.slack.com/services/T00/B00/xxx");
        let alert = make_alert(Severity::High, vec![]);
        let payload = n.format_alert(&alert);

        let body = payload["attachments"][0]["blocks"][2]["text"]["text"]
            .as_str()
            .expect("body");
        assert!(!body.contains("Actions suggérées"));
    }
}
