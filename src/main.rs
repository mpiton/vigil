use std::time::Duration;

use clap::Parser;
use colored::Colorize;
use tracing_subscriber::EnvFilter;

use vigil::application::config::AppConfig;
use vigil::application::services::monitor::MonitorService;
use vigil::domain::rules::{default_rules, RuleEngine};
use vigil::domain::value_objects::operation_mode::OperationMode;
use vigil::domain::value_objects::thresholds::ThresholdSet;
use vigil::infrastructure::ai::create_ai_analyzer;
use vigil::infrastructure::collectors::sysinfo_collector::SysinfoCollector;
use vigil::infrastructure::notifications::terminal::TerminalNotifier;
use vigil::infrastructure::persistence::sqlite_store::SqliteStore;
use vigil::presentation::cli::app::{Cli, Commands};
use vigil::presentation::cli::commands::daemon::run_daemon;
use vigil::presentation::cli::commands::explain::run_explain;
use vigil::presentation::cli::commands::report::run_report;
use vigil::presentation::cli::commands::scan::run_scan;
use vigil::presentation::cli::commands::status::run_status;

fn print_banner() {
    println!("{}", "━".repeat(40).cyan());
    println!("{}", "  VIGIL — Linux System Monitor".bold().cyan());
    println!("{}", "━".repeat(40).cyan());
}

fn setup_tracing(verbose: bool) {
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    setup_tracing(cli.verbose);

    // Load configuration
    let config = if let Some(ref path) = cli.config {
        AppConfig::load_from(path)?
    } else {
        AppConfig::load()?
    };

    // Manual DI — main.rs is the only place that knows concrete types
    let collector = SysinfoCollector::new();

    // Resolve effective mode: CLI --mode override takes precedence for daemon
    let effective_mode = if let Some(Commands::Daemon {
        mode: Some(ref m), ..
    }) = cli.command
    {
        match m.to_lowercase().as_str() {
            "observe" => OperationMode::Observe,
            "suggest" => OperationMode::Suggest,
            "auto" => OperationMode::Auto,
            other => {
                anyhow::bail!("Mode inconnu : '{other}'. Modes valides : observe, suggest, auto");
            }
        }
    } else {
        config.general.mode
    };
    let notifier = TerminalNotifier::new(effective_mode);
    let rules = default_rules();
    let rule_engine = RuleEngine::new(rules);
    let thresholds = ThresholdSet::from(&config.thresholds);

    // AI analyzer — select implementation based on config
    let analyzer = create_ai_analyzer(&config.ai);

    match cli.command {
        Some(Commands::Status { json }) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            run_status(&collector, json)?;
        }
        Some(Commands::Scan { ai, json }) => {
            let store = SqliteStore::new(&config.database.path)?;
            if let Err(e) = store.cleanup_old(config.database.retention_hours) {
                tracing::warn!("Échec nettoyage anciennes données : {e}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            run_scan(
                &collector,
                &rule_engine,
                &thresholds,
                &*analyzer,
                &notifier,
                &store,
                &store,
                &store,
                ai,
                json,
            )
            .await?;
        }
        Some(Commands::Daemon { .. }) | None => {
            let store = SqliteStore::new(&config.database.path)?;
            if let Err(e) = store.cleanup_old(config.database.retention_hours) {
                tracing::warn!("Échec nettoyage anciennes données : {e}");
            }
            print_banner();
            tracing::info!("Mode : {effective_mode}");
            let service = MonitorService::new(
                &collector,
                &rule_engine,
                &thresholds,
                &*analyzer,
                &notifier,
                &store,
                &store,
                &store,
                config.ai.enabled,
                effective_mode,
            );
            run_daemon(&service, config.general.interval_secs).await?;
        }
        Some(Commands::Report { hours, json }) => {
            let store = SqliteStore::new(&config.database.path)?;
            if let Err(e) = store.cleanup_old(config.database.retention_hours) {
                tracing::warn!("Échec nettoyage anciennes données : {e}");
            }
            run_report(&store, &store, hours, json)?;
        }
        Some(Commands::Explain { pid }) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            run_explain(&collector, &*analyzer, config.ai.enabled, pid).await?;
        }
        Some(Commands::Kill { .. }) => {
            eprintln!("Commande kill pas encore implémentée");
        }
        Some(Commands::Config { .. }) => {
            eprintln!("Commande config pas encore implémentée");
        }
    }

    Ok(())
}
