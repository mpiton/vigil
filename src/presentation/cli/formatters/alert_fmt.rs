use colored::Colorize;

use crate::domain::entities::alert::Alert;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;

/// Strips ANSI/OSC escape sequences from a string to prevent terminal injection.
fn sanitize_terminal(input: &str) -> String {
    input.chars().filter(|c| *c != '\x1b').collect()
}

fn severity_badge(severity: Severity) -> String {
    let label = format!(" {severity} ");
    match severity {
        Severity::Critical => format!("{}", label.on_red().white().bold()),
        Severity::High => format!("{}", label.on_yellow().black().bold()),
        Severity::Medium => format!("{}", label.on_bright_yellow().black()),
        Severity::Low => format!("{}", label.on_blue().white()),
    }
}

fn risk_badge(risk: ActionRisk) -> String {
    let label = format!("[{risk}]");
    match risk {
        ActionRisk::Safe => format!("{}", label.green()),
        ActionRisk::Moderate => format!("{}", label.yellow()),
        ActionRisk::Dangerous => format!("{}", label.red().bold()),
    }
}

pub fn format_alerts(alerts: &[Alert]) {
    for alert in alerts {
        println!();
        println!(
            "{} {} {}",
            severity_badge(alert.severity),
            alert.severity.emoji(),
            alert.title.bold()
        );
        if !alert.details.is_empty() {
            println!("  {}", alert.details.dimmed());
        }
        for action in &alert.suggested_actions {
            let safe_cmd = sanitize_terminal(&action.command);
            println!(
                "  {} {} — {}",
                risk_badge(action.risk),
                sanitize_terminal(&action.description),
                safe_cmd.cyan()
            );
        }
    }
    println!();
}

pub fn print_no_alerts() {
    println!();
    println!(
        "{}",
        "✅ Système sain — aucune alerte détectée".green().bold()
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use colored::control;

    use crate::domain::entities::alert::SuggestedAction;

    fn disable_colors() {
        control::set_override(false);
    }

    fn make_alert(severity: Severity) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: "Test alert".to_string(),
            details: "Some details".to_string(),
            suggested_actions: vec![SuggestedAction {
                description: "Fix it".to_string(),
                command: "echo fix".to_string(),
                risk: ActionRisk::Safe,
            }],
        }
    }

    #[test]
    fn severity_badge_contains_level_name() {
        disable_colors();
        assert!(severity_badge(Severity::Critical).contains("CRITICAL"));
        assert!(severity_badge(Severity::High).contains("HIGH"));
        assert!(severity_badge(Severity::Medium).contains("MEDIUM"));
        assert!(severity_badge(Severity::Low).contains("LOW"));
    }

    #[test]
    fn risk_badge_contains_level_name() {
        disable_colors();
        assert!(risk_badge(ActionRisk::Safe).contains("safe"));
        assert!(risk_badge(ActionRisk::Moderate).contains("moderate"));
        assert!(risk_badge(ActionRisk::Dangerous).contains("dangerous"));
    }

    #[test]
    fn format_alerts_does_not_panic() {
        disable_colors();
        let alerts = vec![make_alert(Severity::Critical), make_alert(Severity::Low)];
        format_alerts(&alerts);
    }

    #[test]
    fn format_alerts_empty_does_not_panic() {
        disable_colors();
        format_alerts(&[]);
    }

    #[test]
    fn print_no_alerts_does_not_panic() {
        disable_colors();
        print_no_alerts();
    }

    #[test]
    fn sanitize_terminal_strips_escape_sequences() {
        assert_eq!(sanitize_terminal("normal text"), "normal text");
        assert_eq!(sanitize_terminal("evil\x1b[31mred"), "evil[31mred");
        assert_eq!(
            sanitize_terminal("\x1b]8;;http://evil.com\x1b\\click\x1b]8;;\x1b\\"),
            "]8;;http://evil.com\\click]8;;\\"
        );
    }

    #[test]
    fn format_alert_with_empty_details() {
        disable_colors();
        let alert = Alert {
            timestamp: Utc::now(),
            severity: Severity::Medium,
            rule: "test".to_string(),
            title: "No details".to_string(),
            details: String::new(),
            suggested_actions: vec![],
        };
        format_alerts(&[alert]);
    }
}
