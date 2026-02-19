use std::time::Duration;

use clap::{CommandFactory, Parser};
use colored::Colorize;
use tracing_subscriber::EnvFilter;

use vigil::application::config::AppConfig;
use vigil::domain::rules::{default_rules, RuleEngine};
use vigil::domain::value_objects::thresholds::ThresholdSet;
use vigil::infrastructure::ai::create_ai_analyzer;
use vigil::infrastructure::collectors::sysinfo_collector::SysinfoCollector;
use vigil::infrastructure::notifications::terminal::TerminalNotifier;
use vigil::presentation::cli::app::{Cli, Commands};
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
    let notifier = TerminalNotifier::new(config.general.mode);
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
        Some(Commands::Scan { json, .. }) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            run_scan(
                &collector,
                &rule_engine,
                &thresholds,
                &*analyzer,
                &notifier,
                json,
            )
            .await?;
        }
        Some(Commands::Daemon { .. }) => {
            print_banner();
            eprintln!("Commande daemon pas encore implémentée");
        }
        Some(Commands::Explain { .. }) => {
            eprintln!("Commande explain pas encore implémentée");
        }
        Some(Commands::Kill { .. }) => {
            eprintln!("Commande kill pas encore implémentée");
        }
        Some(Commands::Config { .. }) => {
            eprintln!("Commande config pas encore implémentée");
        }
        None => {
            print_banner();
            Cli::command().print_help()?;
        }
    }

    Ok(())
}
