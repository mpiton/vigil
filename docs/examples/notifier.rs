use anyhow::Result;
use colored::Colorize;

use crate::config::{NotificationConfig, OperationMode};
use crate::types::*;

pub struct Notifier {
    config: NotificationConfig,
    mode: OperationMode,
}

impl Notifier {
    pub fn new(config: NotificationConfig, mode: OperationMode) -> Self {
        Self { config, mode }
    }

    /// Send alert through all configured channels
    pub fn notify(&self, alert: &Alert) -> Result<()> {
        if self.config.terminal {
            self.notify_terminal(alert);
        }

        if self.config.desktop {
            if let Err(e) = self.notify_desktop(alert) {
                tracing::warn!("Desktop notification failed: {}", e);
            }
        }

        if let Some(ref log_file) = self.config.log_file {
            if let Err(e) = self.notify_log(alert, log_file) {
                tracing::warn!("Log notification failed: {}", e);
            }
        }

        Ok(())
    }

    fn notify_terminal(&self, alert: &Alert) {
        let separator = "─".repeat(70);

        let severity_str = match alert.severity {
            Severity::Critical => format!(" {} CRITICAL ", alert.severity.emoji())
                .on_red()
                .white()
                .bold()
                .to_string(),
            Severity::High => format!(" {} HIGH ", alert.severity.emoji())
                .on_yellow()
                .black()
                .bold()
                .to_string(),
            Severity::Medium => format!(" {} MEDIUM ", alert.severity.emoji())
                .on_bright_yellow()
                .black()
                .to_string(),
            Severity::Low => format!(" {} LOW ", alert.severity.emoji())
                .on_blue()
                .white()
                .to_string(),
        };

        println!("\n{}", separator.dimmed());
        println!("{} {}", severity_str, alert.title.bold());
        println!("{}", separator.dimmed());

        if !alert.details.is_empty() {
            println!("{}", alert.details);
        }

        if !alert.suggested_actions.is_empty()
            && (self.mode == OperationMode::Suggest || self.mode == OperationMode::Auto)
        {
            println!("\n{}", "Actions suggérées :".cyan().bold());
            for (i, action) in alert.suggested_actions.iter().enumerate() {
                let risk_badge = match action.risk {
                    ActionRisk::Safe => "[safe]".green().to_string(),
                    ActionRisk::Moderate => "[moderate]".yellow().to_string(),
                    ActionRisk::Dangerous => "[dangerous]".red().to_string(),
                };

                println!(
                    "  {}. {} {} {}",
                    i + 1,
                    risk_badge,
                    action.description,
                    format!("→ {}", action.command).dimmed()
                );
            }
        }

        println!("{}\n", separator.dimmed());
    }

    fn notify_desktop(&self, alert: &Alert) -> Result<()> {
        let urgency = match alert.severity {
            Severity::Critical => notify_rust::Urgency::Critical,
            Severity::High => notify_rust::Urgency::Critical,
            Severity::Medium => notify_rust::Urgency::Normal,
            Severity::Low => notify_rust::Urgency::Low,
        };

        let body = if alert.suggested_actions.is_empty() {
            alert.details.clone()
        } else {
            format!(
                "{}\n\n💡 {}",
                alert.details,
                alert
                    .suggested_actions
                    .first()
                    .map(|a| a.description.as_str())
                    .unwrap_or("")
            )
        };

        notify_rust::Notification::new()
            .summary(&format!(
                "{} Vigil — {}",
                alert.severity.emoji(),
                alert.title
            ))
            .body(&body[..body.len().min(250)])
            .urgency(urgency)
            .timeout(notify_rust::Timeout::Milliseconds(10_000))
            .show()
            .map_err(|e| crate::error::VigilError::Notification(e.to_string()))?;

        Ok(())
    }

    fn notify_log(&self, alert: &Alert, log_file: &str) -> Result<()> {
        let expanded = shellexpand::tilde(log_file);
        let path = std::path::Path::new(expanded.as_ref());

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

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

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(())
    }

    /// Notify AI diagnostic results
    pub fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) {
        if !self.config.terminal {
            return;
        }

        let separator = "═".repeat(70);
        println!("\n{}", separator.cyan());
        println!("{}", " 🤖 Analyse IA (Claude) ".on_cyan().black().bold());
        println!("{}", separator.cyan());

        println!("\n{}", "Diagnostic :".cyan().bold());
        println!("  {}", diagnostic.diagnostic);

        if !diagnostic.actions.is_empty() {
            println!("\n{}", "Actions recommandées :".cyan().bold());
            for (i, action) in diagnostic.actions.iter().enumerate() {
                let risk_badge = match action.risk.as_str() {
                    "safe" => "[safe]".green().to_string(),
                    "moderate" => "[moderate]".yellow().to_string(),
                    "dangerous" => "[dangerous]".red().to_string(),
                    _ => format!("[{}]", action.risk),
                };

                println!(
                    "  {}. {} {} ({})",
                    i + 1,
                    risk_badge,
                    action.explanation,
                    action.action_type.dimmed()
                );
                println!("     {}", format!("→ {}", action.command).dimmed());
            }
        }

        if !diagnostic.prevention.is_empty() {
            println!("\n{}", "Prévention :".cyan().bold());
            println!("  {}", diagnostic.prevention);
        }

        println!("{}\n", separator.cyan());
    }
}
