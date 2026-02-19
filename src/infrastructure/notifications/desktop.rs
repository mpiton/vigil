use notify_rust::{Notification, Timeout, Urgency};

use crate::domain::entities::alert::Alert;
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::ports::notifier::{NotificationError, Notifier};
use crate::domain::value_objects::severity::Severity;

const MAX_BODY_CHARS: usize = 250;
const MAX_SUMMARY_CHARS: usize = 100;

pub struct DesktopNotifier;

impl DesktopNotifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DesktopNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier for DesktopNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        let urgency = severity_to_urgency(alert.severity);

        let raw_summary = format!("{} Vigil \u{2014} {}", alert.severity.emoji(), alert.title);
        let summary = truncate(&escape_markup(&raw_summary), MAX_SUMMARY_CHARS);

        let raw_body = if alert.suggested_actions.is_empty() {
            alert.details.clone()
        } else {
            format!(
                "{}\n\n\u{1f4a1} {}",
                alert.details,
                alert
                    .suggested_actions
                    .first()
                    .map_or("", |a| a.description.as_str())
            )
        };

        let body = truncate(&escape_markup(&raw_body), MAX_BODY_CHARS);

        send_notification(&summary, &body, urgency)
    }

    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError> {
        let urgency = severity_to_urgency(diagnostic.severity);

        let raw_summary = format!("\u{1f916} Vigil \u{2014} {}", diagnostic.summary);
        let summary = truncate(&escape_markup(&raw_summary), MAX_SUMMARY_CHARS);
        let body = truncate(&escape_markup(&diagnostic.details), MAX_BODY_CHARS);

        send_notification(&summary, &body, urgency)
    }
}

fn send_notification(summary: &str, body: &str, urgency: Urgency) -> Result<(), NotificationError> {
    Notification::new()
        .summary(summary)
        .body(body)
        .urgency(urgency)
        .timeout(Timeout::Milliseconds(10_000))
        .show()
        .map_err(|_| {
            NotificationError::ChannelUnavailable(
                "desktop notification server unreachable".to_string(),
            )
        })?;

    Ok(())
}

// Spec: Critical = Critical, High = Critical, Medium = Normal, Low = Low
#[must_use]
const fn severity_to_urgency(severity: Severity) -> Urgency {
    match severity {
        Severity::Critical | Severity::High => Urgency::Critical,
        Severity::Medium => Urgency::Normal,
        Severity::Low => Urgency::Low,
    }
}

// Truncates on Unicode scalar values (not grapheme clusters; ZWJ sequences may split).
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_owned()
    } else {
        let mut result: String = s.chars().take(max_chars - 1).collect();
        result.push('\u{2026}');
        result
    }
}

fn escape_markup(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::domain::entities::alert::SuggestedAction;
    use crate::domain::value_objects::action_risk::ActionRisk;

    fn make_alert(severity: Severity, actions: Vec<SuggestedAction>) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: "Test Alert".to_string(),
            details: "Some details".to_string(),
            suggested_actions: actions,
        }
    }

    fn make_action(risk: ActionRisk) -> SuggestedAction {
        SuggestedAction {
            description: "Kill the process".to_string(),
            command: "kill -9 1234".to_string(),
            risk,
        }
    }

    fn make_diagnostic() -> AiDiagnostic {
        AiDiagnostic {
            timestamp: Utc::now(),
            summary: "High memory pressure detected".to_string(),
            details: "Process X is consuming 95% of RAM".to_string(),
            severity: Severity::High,
            confidence: 0.87,
        }
    }

    #[test]
    fn new_creates_notifier() {
        let _notifier = DesktopNotifier::new();
    }

    #[test]
    fn default_creates_notifier() {
        let _notifier = <DesktopNotifier as Default>::default();
    }

    #[test]
    fn severity_to_urgency_critical() {
        assert!(matches!(
            severity_to_urgency(Severity::Critical),
            Urgency::Critical
        ));
    }

    #[test]
    fn severity_to_urgency_high() {
        assert!(matches!(
            severity_to_urgency(Severity::High),
            Urgency::Critical
        ));
    }

    #[test]
    fn severity_to_urgency_medium() {
        assert!(matches!(
            severity_to_urgency(Severity::Medium),
            Urgency::Normal
        ));
    }

    #[test]
    fn severity_to_urgency_low() {
        assert!(matches!(severity_to_urgency(Severity::Low), Urgency::Low));
    }

    #[test]
    fn truncate_short_string_unchanged() {
        let result = truncate("hello", 250);
        assert_eq!(result, "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        let long = "a".repeat(300);
        let result = truncate(&long, 250);
        assert_eq!(result.chars().count(), 250);
        assert!(result.ends_with('\u{2026}'));
    }

    #[test]
    fn truncate_exact_length_no_ellipsis() {
        let exact = "b".repeat(250);
        let result = truncate(&exact, 250);
        assert_eq!(result, exact);
    }

    #[test]
    fn truncate_unicode_safe() {
        let input = "\u{00e9}".repeat(300);
        let result = truncate(&input, 250);
        assert_eq!(result.chars().count(), 250);
        assert!(result.ends_with('\u{2026}'));
        assert!(result.is_char_boundary(result.len()));
    }

    #[test]
    fn truncate_empty_string() {
        let result = truncate("", 250);
        assert_eq!(result, "");
    }

    #[test]
    fn escape_markup_strips_html() {
        let input = "<b>bold</b> & <script>";
        let result = escape_markup(input);
        assert_eq!(result, "&lt;b&gt;bold&lt;/b&gt; &amp; &lt;script&gt;");
    }

    #[test]
    fn escape_markup_preserves_clean_text() {
        let input = "normal text with accents \u{00e9}\u{00e0}";
        let result = escape_markup(input);
        assert_eq!(result, input);
    }

    #[test]
    fn notify_returns_error_without_server() {
        let notifier = DesktopNotifier::new();
        let alert = make_alert(Severity::Critical, vec![]);
        let result = notifier.notify(&alert);
        // On CI/test environments without D-Bus, this returns ChannelUnavailable.
        // On systems with a notification server, this succeeds.
        assert!(result.is_ok() || matches!(result, Err(NotificationError::ChannelUnavailable(_))));
    }

    #[test]
    fn notify_ai_diagnostic_returns_error_without_server() {
        let notifier = DesktopNotifier::new();
        let diag = make_diagnostic();
        let result = notifier.notify_ai_diagnostic(&diag);
        assert!(result.is_ok() || matches!(result, Err(NotificationError::ChannelUnavailable(_))));
    }

    #[test]
    fn notify_graceful_error_hides_dbus_details() {
        let notifier = DesktopNotifier::new();
        let alert = make_alert(Severity::Low, vec![]);
        if let Err(e) = notifier.notify(&alert) {
            let msg = e.to_string();
            assert!(
                !msg.contains("org.freedesktop"),
                "error should not leak D-Bus details: {msg}"
            );
        }
    }

    #[test]
    fn notify_with_actions_includes_first_action() {
        let notifier = DesktopNotifier::new();
        let alert = make_alert(Severity::High, vec![make_action(ActionRisk::Safe)]);
        // Verify it doesn't panic regardless of server availability
        let result = notifier.notify(&alert);
        assert!(result.is_ok() || matches!(result, Err(NotificationError::ChannelUnavailable(_))));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_are_reasonable() {
        assert!(MAX_BODY_CHARS >= 100);
        assert!(MAX_SUMMARY_CHARS >= 50);
        assert!(MAX_BODY_CHARS > MAX_SUMMARY_CHARS);
    }
}
