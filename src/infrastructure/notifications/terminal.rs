use std::borrow::Cow;

use colored::Colorize;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::ports::notifier::{NotificationError, Notifier};
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::operation_mode::OperationMode;
use crate::domain::value_objects::severity::Severity;

const SEPARATOR_WIDTH: usize = 70;

pub struct TerminalNotifier {
    mode: OperationMode,
}

impl TerminalNotifier {
    #[must_use]
    pub const fn new(mode: OperationMode) -> Self {
        Self { mode }
    }
}

impl Default for TerminalNotifier {
    fn default() -> Self {
        Self::new(OperationMode::default())
    }
}

impl Notifier for TerminalNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        let separator = "\u{2500}".repeat(SEPARATOR_WIDTH);

        let badge = severity_badge(alert.severity);

        println!("\n{}", separator.dimmed());
        println!("{} {}", badge, sanitize(&alert.title).bold());
        println!("{}", separator.dimmed());

        if !alert.details.is_empty() {
            println!("{}", sanitize(&alert.details));
        }

        let show_actions = match self.mode {
            OperationMode::Suggest | OperationMode::Auto => true,
            OperationMode::Observe => false,
        };

        if show_actions && !alert.suggested_actions.is_empty() {
            println!("\n{}", "Actions sugg\u{00e9}r\u{00e9}es :".cyan().bold());
            for (i, action) in alert.suggested_actions.iter().enumerate() {
                let risk = risk_badge(action.risk);
                println!(
                    "  {}. {} {} {}",
                    i + 1,
                    risk,
                    sanitize(&action.description),
                    format!("\u{2192} {}", sanitize(&action.command)).dimmed()
                );
            }
        }

        println!("{}\n", separator.dimmed());
        Ok(())
    }

    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError> {
        let separator = "\u{2550}".repeat(SEPARATOR_WIDTH);

        println!("\n{}", separator.cyan());
        println!(
            "{}",
            " \u{1f916} Analyse IA (Claude) ".on_cyan().black().bold()
        );
        println!("{}", separator.cyan());

        if !diagnostic.summary.is_empty() {
            println!("\n{}", "R\u{00e9}sum\u{00e9} :".cyan().bold());
            println!("  {}", sanitize(&diagnostic.summary));
        }

        if !diagnostic.details.is_empty() {
            println!("\n{}", "D\u{00e9}tails :".cyan().bold());
            println!("  {}", sanitize(&diagnostic.details));
        }

        println!("\n{}", "S\u{00e9}v\u{00e9}rit\u{00e9} :".cyan().bold());
        println!(
            "  {} {}",
            severity_badge(diagnostic.severity),
            diagnostic.severity
        );

        let confidence = diagnostic.confidence.clamp(0.0, 1.0);
        println!("\n{}", "Confiance :".cyan().bold());
        println!("  {:.0}%", confidence * 100.0);

        println!("{}\n", separator.cyan());
        Ok(())
    }
}

/// Strip ANSI escape sequences and C0/C1 control characters from a string,
/// preserving only printable content, newlines, and tabs.
fn sanitize(s: &str) -> Cow<'_, str> {
    if s.bytes()
        .any(|b| matches!(b, 0x00..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F | 0x7F))
    {
        Cow::Owned(
            s.chars()
                .filter(|&c| !matches!(c as u32, 0x00..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F | 0x7F))
                .collect(),
        )
    } else {
        Cow::Borrowed(s)
    }
}

#[must_use]
fn severity_badge(severity: Severity) -> String {
    match severity {
        Severity::Critical => format!(" {} {} ", severity.emoji(), severity)
            .on_red()
            .white()
            .bold()
            .to_string(),
        Severity::High => format!(" {} {} ", severity.emoji(), severity)
            .on_yellow()
            .black()
            .bold()
            .to_string(),
        Severity::Medium => format!(" {} {} ", severity.emoji(), severity)
            .on_bright_yellow()
            .black()
            .to_string(),
        Severity::Low => format!(" {} {} ", severity.emoji(), severity)
            .on_blue()
            .white()
            .to_string(),
    }
}

#[must_use]
fn risk_badge(risk: ActionRisk) -> String {
    match risk {
        ActionRisk::Safe => "[safe]".green().to_string(),
        ActionRisk::Moderate => "[moderate]".yellow().to_string(),
        ActionRisk::Dangerous => "[dangerous]".red().to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::domain::entities::alert::SuggestedAction;

    fn disable_colors() {
        colored::control::set_override(false);
    }

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
    fn new_creates_notifier_with_mode() {
        let notifier = TerminalNotifier::new(OperationMode::Suggest);
        assert_eq!(notifier.mode, OperationMode::Suggest);
    }

    #[test]
    fn default_uses_observe_mode() {
        let notifier = TerminalNotifier::default();
        assert_eq!(notifier.mode, OperationMode::Observe);
    }

    #[test]
    fn notify_critical_alert_succeeds() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let alert = make_alert(Severity::Critical, vec![]);
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_all_severities_succeed() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let alert = make_alert(severity, vec![]);
            assert!(notifier.notify(&alert).is_ok());
        }
    }

    #[test]
    fn notify_observe_mode_hides_actions() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let alert = make_alert(Severity::High, vec![make_action(ActionRisk::Safe)]);
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_suggest_mode_with_all_risk_levels() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Suggest);
        let alert = make_alert(
            Severity::High,
            vec![
                make_action(ActionRisk::Safe),
                make_action(ActionRisk::Moderate),
                make_action(ActionRisk::Dangerous),
            ],
        );
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_empty_details_succeeds() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let mut alert = make_alert(Severity::Low, vec![]);
        alert.details = String::new();
        assert!(notifier.notify(&alert).is_ok());
    }

    #[test]
    fn notify_ai_diagnostic_succeeds() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let diag = make_diagnostic();
        assert!(notifier.notify_ai_diagnostic(&diag).is_ok());
    }

    #[test]
    fn notify_ai_diagnostic_empty_details() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let mut diag = make_diagnostic();
        diag.details = String::new();
        assert!(notifier.notify_ai_diagnostic(&diag).is_ok());
    }

    #[test]
    fn notify_ai_diagnostic_empty_summary() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let mut diag = make_diagnostic();
        diag.summary = String::new();
        assert!(notifier.notify_ai_diagnostic(&diag).is_ok());
    }

    #[test]
    fn notify_ai_diagnostic_clamps_confidence() {
        disable_colors();
        let notifier = TerminalNotifier::new(OperationMode::Observe);
        let mut diag = make_diagnostic();
        diag.confidence = 1.5;
        assert!(notifier.notify_ai_diagnostic(&diag).is_ok());
        diag.confidence = -0.5;
        assert!(notifier.notify_ai_diagnostic(&diag).is_ok());
    }

    #[test]
    fn severity_badge_returns_non_empty() {
        disable_colors();
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let badge = severity_badge(severity);
            assert!(
                !badge.is_empty(),
                "badge for {severity} should not be empty"
            );
        }
    }

    #[test]
    fn risk_badge_returns_non_empty() {
        disable_colors();
        for risk in [
            ActionRisk::Safe,
            ActionRisk::Moderate,
            ActionRisk::Dangerous,
        ] {
            let badge = risk_badge(risk);
            assert!(!badge.is_empty(), "badge for {risk} should not be empty");
        }
    }

    #[test]
    fn sanitize_strips_control_characters() {
        let input = "hello\x1b[2Jworld\x07done";
        let result = sanitize(input);
        assert_eq!(result, "hello[2Jworlddone");
    }

    #[test]
    fn sanitize_preserves_clean_strings() {
        let input = "clean string with\nnewlines\tand tabs";
        let result = sanitize(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, input);
    }

    #[test]
    fn sanitize_preserves_unicode() {
        let input = "alerte: m\u{00e9}moire \u{00e9}lev\u{00e9}e \u{1f916}";
        let result = sanitize(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, input);
    }
}
