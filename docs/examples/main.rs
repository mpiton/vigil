mod ai_analyzer;
mod analyzer;
mod cli;
mod collectors;
mod config;
mod error;
mod notifier;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::time::Duration;

use crate::ai_analyzer::AiAnalyzer;
use crate::analyzer::RuleAnalyzer;
use crate::cli::{Cli, Commands};
use crate::collectors::SystemCollector;
use crate::config::{Config, OperationMode};
use crate::notifier::Notifier;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    // Load config
    let config = match &cli.config {
        Some(path) => Config::load_from(path)?,
        None => Config::load()?,
    };

    match cli.command {
        None | Some(Commands::Daemon { .. }) => run_daemon(config).await,
        Some(Commands::Status { json }) => run_status(json),
        Some(Commands::Scan { ai, json }) => run_scan(config, ai, json).await,
        Some(Commands::Explain { pid }) => run_explain(config, pid).await,
        Some(Commands::Kill { pid, force }) => run_kill(pid, force),
        Some(Commands::Config { edit }) => run_config(edit),
    }
}

/// Main daemon loop
async fn run_daemon(config: Config) -> Result<()> {
    print_banner();
    tracing::info!(
        "Vigil démarré en mode {:?}, intervalle: {}s",
        config.general.mode,
        config.general.interval_secs
    );

    let mut collector = SystemCollector::new();
    let mut ai = AiAnalyzer::new(config.ai.clone());
    let notifier = Notifier::new(config.notifications.clone(), config.general.mode.clone());
    let interval = Duration::from_secs(config.general.interval_secs);

    loop {
        match collector.collect() {
            Ok(snapshot) => {
                let rule_analyzer = RuleAnalyzer::new(&config);
                let alerts = rule_analyzer.analyze(&snapshot);

                if alerts.is_empty() {
                    tracing::debug!(
                        "Système OK — RAM: {:.1}%, CPU load: {:.2}, {} processus",
                        snapshot.memory.usage_percent,
                        snapshot.cpu.load_avg_1m,
                        snapshot.processes.len()
                    );
                } else {
                    tracing::warn!("{} alerte(s) détectée(s)", alerts.len());

                    for alert in &alerts {
                        if let Err(e) = notifier.notify(alert) {
                            tracing::error!("Notification failed: {}", e);
                        }
                    }

                    // AI analysis for non-trivial alerts
                    let has_serious = alerts
                        .iter()
                        .any(|a| a.severity >= types::Severity::High);

                    if has_serious && config.ai.enabled {
                        match ai.analyze(&snapshot, &alerts).await {
                            Ok(Some(diagnostic)) => {
                                notifier.notify_ai_diagnostic(&diagnostic);

                                // Auto-execute safe actions if in auto mode
                                if config.general.mode == OperationMode::Auto {
                                    for action in &diagnostic.actions {
                                        if action.risk == "safe" {
                                            tracing::info!(
                                                "Auto-exécution: {}",
                                                action.command
                                            );
                                            execute_command(&action.command);
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                tracing::debug!("AI analysis skipped (cooldown or disabled)");
                            }
                            Err(e) => {
                                tracing::warn!("AI analysis failed: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Collection failed: {}", e);
            }
        }

        tokio::time::sleep(interval).await;
    }
}

/// One-shot status display
fn run_status(json: bool) -> Result<()> {
    let mut collector = SystemCollector::new();
    // Wait a bit for CPU stats to be meaningful
    std::thread::sleep(Duration::from_millis(500));
    let snapshot = collector.collect()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(());
    }

    let mem = &snapshot.memory;
    let cpu = &snapshot.cpu;

    println!("\n{}", " 🛡️  Vigil — System Status ".on_cyan().black().bold());
    println!();

    // Memory
    let ram_bar = progress_bar(mem.usage_percent, 30);
    let ram_color = if mem.usage_percent > 90.0 {
        "red"
    } else if mem.usage_percent > 80.0 {
        "yellow"
    } else {
        "green"
    };
    println!(
        "  {} {} {:.1}% ({}/{} MB)",
        "RAM:".bold(),
        colorize_bar(&ram_bar, ram_color),
        mem.usage_percent,
        mem.used_mb,
        mem.total_mb
    );

    if mem.swap_total_mb > 0 {
        let swap_bar = progress_bar(mem.swap_percent, 30);
        println!(
            "  {} {} {:.1}% ({}/{} MB)",
            "Swap:".bold(),
            swap_bar.dimmed(),
            mem.swap_percent,
            mem.swap_used_mb,
            mem.swap_total_mb
        );
    }

    // CPU
    println!(
        "  {} Load: {:.2} / {:.2} / {:.2}  ({} cœurs, usage: {:.1}%)",
        "CPU:".bold(),
        cpu.load_avg_1m,
        cpu.load_avg_5m,
        cpu.load_avg_15m,
        cpu.core_count,
        cpu.global_usage_percent
    );

    // Disks
    for disk in &snapshot.disks {
        let disk_bar = progress_bar(disk.usage_percent, 20);
        println!(
            "  {} {} {:.1}% ({:.1} GB libre) — {}",
            "Disk:".bold(),
            disk_bar,
            disk.usage_percent,
            disk.available_gb,
            disk.mount_point
        );
    }

    // Top 5 processes by RAM
    println!("\n  {}", "Top processus (RAM):".bold());
    let mut procs = snapshot.processes.clone();
    procs.sort_by(|a, b| b.rss_mb.cmp(&a.rss_mb));
    for p in procs.iter().take(5) {
        println!(
            "    PID {:>6}  {:>6} MB  CPU {:>5.1}%  {}",
            p.pid,
            p.rss_mb,
            p.cpu_percent,
            &p.name
        );
    }

    // Zombies
    let zombies: Vec<_> = snapshot
        .processes
        .iter()
        .filter(|p| p.state == types::ProcessState::Zombie)
        .collect();
    if !zombies.is_empty() {
        println!(
            "\n  {} {} processus zombie(s)",
            "⚠️".yellow(),
            zombies.len()
        );
    }

    println!();
    Ok(())
}

/// One-shot scan with optional AI
async fn run_scan(config: Config, use_ai: bool, json: bool) -> Result<()> {
    let mut collector = SystemCollector::new();
    std::thread::sleep(Duration::from_millis(500));
    let snapshot = collector.collect()?;
    let rule_analyzer = RuleAnalyzer::new(&config);
    let alerts = rule_analyzer.analyze(&snapshot);

    if json {
        let output = serde_json::json!({
            "snapshot": snapshot,
            "alerts": alerts,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if alerts.is_empty() {
        println!(
            "\n{} Aucune anomalie détectée. Système en bon état.\n",
            "✅".green()
        );
    } else {
        let notifier = Notifier::new(config.notifications.clone(), OperationMode::Suggest);
        for alert in &alerts {
            notifier.notify(alert)?;
        }

        if use_ai && config.ai.enabled {
            let mut ai = AiAnalyzer::new(config.ai.clone());
            match ai.analyze(&snapshot, &alerts).await {
                Ok(Some(diagnostic)) => notifier.notify_ai_diagnostic(&diagnostic),
                Ok(None) => println!("{}", "IA non disponible (cooldown ou désactivée)".dimmed()),
                Err(e) => println!("{} Erreur IA: {}", "⚠️".yellow(), e),
            }
        }
    }

    Ok(())
}

/// Explain a specific process using AI
async fn run_explain(config: Config, pid: u32) -> Result<()> {
    let mut collector = SystemCollector::new();
    std::thread::sleep(Duration::from_millis(500));
    let snapshot = collector.collect()?;

    let process = snapshot
        .processes
        .iter()
        .find(|p| p.pid == pid)
        .context(format!("Process {} not found", pid))?;

    println!(
        "\n{} Processus PID {}",
        "🔍".bold(),
        pid.to_string().bold()
    );
    println!("  Nom:     {}", process.name);
    println!("  Cmdline: {}", process.cmdline);
    println!("  État:    {}", process.state);
    println!("  RAM:     {} MB", process.rss_mb);
    println!("  CPU:     {:.1}%", process.cpu_percent);
    println!("  Parent:  PID {}", process.ppid);
    println!("  FDs:     {}", process.open_fds);

    if config.ai.enabled {
        println!("\n{}", "Analyse IA en cours...".dimmed());
        let api_key = std::env::var(&config.ai.api_key_env)
            .context("ANTHROPIC_API_KEY not set")?;

        let prompt = format!(
            "Explique ce processus Linux de manière concise :\n\
             - PID: {}\n- Nom: {}\n- Cmdline: {}\n- État: {}\n- RAM: {} MB\n- CPU: {:.1}%\n- Parent PID: {}\n- FDs ouverts: {}\n\n\
             Est-ce un processus légitime ? Peut-il être tué sans risque ?",
            process.pid,
            process.name,
            process.cmdline,
            process.state,
            process.rss_mb,
            process.cpu_percent,
            process.ppid,
            process.open_fds
        );

        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "model": config.ai.model,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
            "system": "Tu es un expert Linux. Explique brièvement ce processus. Réponds en français."
        });

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            let json: serde_json::Value = resp.json().await?;
            if let Some(text) = json["content"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|b| b["text"].as_str())
            {
                println!("\n{}", " 🤖 Explication IA ".on_cyan().black().bold());
                println!("{}\n", text);
            }
        }
    }

    Ok(())
}

/// Kill a process with confirmation
fn run_kill(pid: u32, force: bool) -> Result<()> {
    let signal = if force {
        nix::sys::signal::Signal::SIGKILL
    } else {
        nix::sys::signal::Signal::SIGTERM
    };

    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };

    // Show process info before killing
    let mut collector = SystemCollector::new();
    if let Ok(snapshot) = collector.collect() {
        if let Some(proc) = snapshot.processes.iter().find(|p| p.pid == pid) {
            println!(
                "\n{} Processus à tuer:",
                "⚠️".yellow()
            );
            println!("  PID:     {}", proc.pid);
            println!("  Nom:     {}", proc.name);
            println!("  Cmdline: {}", proc.cmdline);
            println!("  RAM:     {} MB", proc.rss_mb);
        }
    }

    println!(
        "\nEnvoi de {} au PID {}...",
        signal_name.bold(),
        pid.to_string().bold()
    );

    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), signal) {
        Ok(()) => {
            println!("{} Signal envoyé avec succès.", "✅".green());
            Ok(())
        }
        Err(e) => {
            println!("{} Échec: {}", "❌".red(), e);
            anyhow::bail!("Failed to kill process {}: {}", pid, e);
        }
    }
}

/// Show/edit config
fn run_config(edit: bool) -> Result<()> {
    let config = Config::load()?;

    if edit {
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".into());
        let config_dir = dirs::config_dir().context("No config dir")?;
        let config_path = config_dir.join("vigil").join("config.toml");
        std::process::Command::new(editor)
            .arg(&config_path)
            .status()?;
    } else {
        println!(
            "{}",
            toml::to_string_pretty(&config).context("Failed to serialize config")?
        );
    }

    Ok(())
}

// --- Helpers ---

fn print_banner() {
    println!(
        r#"
{}
  ╦  ╦╦╔═╗╦╦
  ╚╗╔╝║║ ╦║║
   ╚╝ ╩╚═╝╩╩═╝
  AI-Powered Linux System Guardian
{}"#,
        "━".repeat(40).cyan(),
        "━".repeat(40).cyan()
    );
}

fn progress_bar(percent: f64, width: usize) -> String {
    let filled = ((percent / 100.0) * width as f64) as usize;
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

fn colorize_bar(bar: &str, color: &str) -> String {
    match color {
        "red" => bar.red().to_string(),
        "yellow" => bar.yellow().to_string(),
        "green" => bar.green().to_string(),
        _ => bar.to_string(),
    }
}

fn execute_command(cmd: &str) {
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                tracing::info!("Command succeeded: {}", cmd);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("Command failed: {} — {}", cmd, stderr);
            }
        }
        Err(e) => {
            tracing::error!("Failed to execute command '{}': {}", cmd, e);
        }
    }
}
