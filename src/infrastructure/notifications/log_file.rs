use std::io::Write;
use std::path::PathBuf;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::ports::notifier::{NotificationError, Notifier};

const DEFAULT_LOG_PATH: &str = "~/.local/share/vigil/vigil.log";

pub struct LogFileNotifier {
    path: PathBuf,
}

impl LogFileNotifier {
    #[must_use]
    pub fn new(path: &str) -> Self {
        let expanded = shellexpand::tilde(path);
        Self {
            path: PathBuf::from(expanded.as_ref()),
        }
    }

    fn append_json_line(&self, value: &serde_json::Value) -> Result<(), NotificationError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NotificationError::SendFailed(format!(
                    "impossible de creer le repertoire parent: {e}"
                ))
            })?;
        }

        let json = serde_json::to_string(value).map_err(|e| {
            NotificationError::SendFailed(format!("erreur de serialisation JSON: {e}"))
        })?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                NotificationError::SendFailed(format!("impossible d'ouvrir le fichier de log: {e}"))
            })?;

        writeln!(file, "{json}").map_err(|e| {
            NotificationError::SendFailed(format!(
                "impossible d'ecrire dans le fichier de log: {e}"
            ))
        })
    }
}

impl Default for LogFileNotifier {
    fn default() -> Self {
        Self::new(DEFAULT_LOG_PATH)
    }
}

impl Notifier for LogFileNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        let entry = serde_json::json!({
            "timestamp": alert.timestamp.to_rfc3339(),
            "severity": format!("{:?}", alert.severity),
            "rule": alert.rule,
            "title": alert.title,
            "details": alert.details,
            "actions": alert.suggested_actions.iter().map(|a| {
                serde_json::json!({
                    "description": a.description,
                    "command": a.command,
                    "risk": format!("{}", a.risk),
                })
            }).collect::<Vec<_>>(),
        });

        self.append_json_line(&entry)
    }

    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError> {
        let entry = serde_json::json!({
            "timestamp": diagnostic.timestamp.to_rfc3339(),
            "severity": format!("{:?}", diagnostic.severity),
            "summary": diagnostic.summary,
            "details": diagnostic.details,
            "confidence": diagnostic.confidence,
        });

        self.append_json_line(&entry)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::domain::entities::alert::SuggestedAction;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use crate::domain::value_objects::severity::Severity;
    use chrono::Utc;

    fn make_alert(severity: Severity, actions: Vec<SuggestedAction>) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: "Titre test".to_string(),
            details: "Details du test".to_string(),
            suggested_actions: actions,
        }
    }

    fn make_action(risk: ActionRisk) -> SuggestedAction {
        SuggestedAction {
            description: "Action de test".to_string(),
            command: "echo test".to_string(),
            risk,
        }
    }

    fn make_diagnostic() -> AiDiagnostic {
        AiDiagnostic {
            timestamp: Utc::now(),
            summary: "Diagnostic AI".to_string(),
            details: "Details du diagnostic".to_string(),
            severity: Severity::Medium,
            confidence: 0.85,
        }
    }

    #[test]
    fn new_expands_tilde() {
        let notifier = LogFileNotifier::new("~/test/vigil.log");
        let path_str = notifier.path.to_string_lossy();
        assert!(!path_str.starts_with('~'), "tilde should be expanded");
        assert!(path_str.ends_with("test/vigil.log"));
    }

    #[test]
    fn default_uses_standard_path() {
        let notifier = LogFileNotifier::default();
        let path_str = notifier.path.to_string_lossy();
        assert!(path_str.ends_with(".local/share/vigil/vigil.log"));
    }

    #[test]
    fn notify_writes_json_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let alert = make_alert(Severity::High, vec![make_action(ActionRisk::Safe)]);
        let result = notifier.notify(&alert);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).expect("parse JSON");

        assert_eq!(parsed["severity"], "High");
        assert_eq!(parsed["rule"], "test_rule");
        assert_eq!(parsed["title"], "Titre test");
        assert_eq!(parsed["details"], "Details du test");
        assert_eq!(parsed["actions"][0]["description"], "Action de test");
        assert_eq!(parsed["actions"][0]["command"], "echo test");
        assert_eq!(parsed["actions"][0]["risk"], "safe");
    }

    #[test]
    fn notify_ai_diagnostic_writes_json_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let diagnostic = make_diagnostic();
        let result = notifier.notify_ai_diagnostic(&diagnostic);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).expect("parse JSON");

        assert_eq!(parsed["severity"], "Medium");
        assert_eq!(parsed["summary"], "Diagnostic AI");
        assert_eq!(parsed["details"], "Details du diagnostic");
        assert_eq!(parsed["confidence"], 0.85);
    }

    #[test]
    fn notify_appends_multiple_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let alert1 = make_alert(Severity::Low, vec![]);
        let alert2 = make_alert(Severity::Critical, vec![]);

        assert!(notifier.notify(&alert1).is_ok());
        assert!(notifier.notify(&alert2).is_ok());

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("parse first");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("parse second");

        assert_eq!(first["severity"], "Low");
        assert_eq!(second["severity"], "Critical");
    }

    #[test]
    fn notify_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("deep").join("nested").join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let alert = make_alert(Severity::Medium, vec![]);
        let result = notifier.notify(&alert);
        assert!(result.is_ok());
        assert!(log_path.exists());
    }

    #[test]
    fn notify_includes_timestamp_field() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let alert = make_alert(Severity::Low, vec![]);
        assert!(notifier.notify(&alert).is_ok());

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).expect("parse JSON");

        assert!(parsed["timestamp"].is_string());
        let ts = parsed["timestamp"].as_str().expect("timestamp str");
        assert!(
            chrono::DateTime::parse_from_rfc3339(ts).is_ok(),
            "timestamp should be valid RFC 3339"
        );
    }

    #[test]
    fn notify_with_multiple_actions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let alert = make_alert(
            Severity::High,
            vec![
                make_action(ActionRisk::Safe),
                make_action(ActionRisk::Moderate),
                make_action(ActionRisk::Dangerous),
            ],
        );
        assert!(notifier.notify(&alert).is_ok());

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).expect("parse JSON");

        let actions = parsed["actions"].as_array().expect("actions array");
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0]["risk"], "safe");
        assert_eq!(actions[1]["risk"], "moderate");
        assert_eq!(actions[2]["risk"], "dangerous");
    }

    #[test]
    fn notify_with_empty_actions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("vigil.log");
        let notifier = LogFileNotifier {
            path: log_path.clone(),
        };

        let alert = make_alert(Severity::Low, vec![]);
        assert!(notifier.notify(&alert).is_ok());

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).expect("parse JSON");

        let actions = parsed["actions"].as_array().expect("actions array");
        assert!(actions.is_empty());
    }

    #[test]
    fn notify_returns_error_on_invalid_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "file").expect("create blocker");
        let log_path = blocker.join("subdir").join("vigil.log");
        let notifier = LogFileNotifier { path: log_path };

        let alert = make_alert(Severity::Low, vec![]);
        let result = notifier.notify(&alert);
        assert!(result.is_err());

        let err = result.expect_err("should be error");
        assert!(
            matches!(err, NotificationError::SendFailed(_)),
            "expected SendFailed, got {err:?}"
        );
    }
}
