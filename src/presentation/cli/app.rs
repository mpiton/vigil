use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// vigil — AI-powered system guardian
///
/// Monitors system resources, detects anomalies, and provides
/// intelligent remediation suggestions.
#[derive(Parser, Debug)]
#[command(name = "vigil")]
#[command(version, about, long_about)]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to custom config file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

/// Available commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the monitoring daemon
    #[command(alias = "d")]
    Daemon {
        /// Operation mode override (observe, suggest, auto)
        #[arg(short, long)]
        mode: Option<String>,
    },

    /// Show current system status
    #[command(alias = "s")]
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run a one-shot system scan
    #[command(alias = "sc")]
    Scan {
        /// Include AI analysis
        #[arg(long)]
        ai: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Générer un rapport des dernières heures
    #[command(alias = "r")]
    Report {
        /// Fenêtre temporelle en heures (défaut : 24)
        #[arg(long, default_value = "24")]
        hours: u64,

        /// Sortie au format JSON
        #[arg(long)]
        json: bool,
    },

    /// Explain a process behavior
    #[command(alias = "e")]
    Explain {
        /// Process ID to analyze
        pid: u32,
    },

    /// Kill a problematic process
    #[command(alias = "k")]
    Kill {
        /// Process ID to kill
        pid: u32,

        /// Force kill (SIGKILL instead of SIGTERM)
        #[arg(short, long)]
        force: bool,
    },

    /// Lancer le tableau de bord interactif
    #[command(alias = "w")]
    Watch {
        /// Intervalle de rafraîchissement en secondes (défaut : config)
        #[arg(short, long)]
        interval: Option<u64>,
    },

    /// Manage configuration
    #[command(alias = "c")]
    Config {
        /// Open config in editor
        #[arg(short, long)]
        edit: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_command() {
        let cli = Cli::try_parse_from(["vigil", "status"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Status { json: false })
        ));
    }

    #[test]
    fn parse_status_with_json() {
        let cli =
            Cli::try_parse_from(["vigil", "status", "--json"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cli.command, Some(Commands::Status { json: true })));
    }

    #[test]
    fn parse_status_alias() {
        let cli = Cli::try_parse_from(["vigil", "s"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cli.command, Some(Commands::Status { .. })));
    }

    #[test]
    fn parse_global_verbose() {
        let cli =
            Cli::try_parse_from(["vigil", "--verbose", "status"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(cli.verbose);
    }

    #[test]
    fn parse_global_config() {
        let cli = Cli::try_parse_from(["vigil", "--config", "/tmp/test.toml", "status"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cli.config, Some(std::path::PathBuf::from("/tmp/test.toml")));
    }

    #[test]
    fn no_command_returns_none() {
        let cli = Cli::try_parse_from(["vigil"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_kill_with_force() {
        let cli = Cli::try_parse_from(["vigil", "kill", "1234", "--force"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Kill {
                pid: 1234,
                force: true
            })
        ));
    }

    #[test]
    fn parse_explain_pid() {
        let cli = Cli::try_parse_from(["vigil", "explain", "42"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cli.command, Some(Commands::Explain { pid: 42 })));
    }

    #[test]
    fn parse_scan_command() {
        let cli = Cli::try_parse_from(["vigil", "scan"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                ai: false,
                json: false
            })
        ));
    }

    #[test]
    fn parse_scan_with_ai() {
        let cli = Cli::try_parse_from(["vigil", "scan", "--ai"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                ai: true,
                json: false
            })
        ));
    }

    #[test]
    fn parse_scan_with_json() {
        let cli =
            Cli::try_parse_from(["vigil", "scan", "--json"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                ai: false,
                json: true
            })
        ));
    }

    #[test]
    fn parse_scan_with_ai_and_json() {
        let cli = Cli::try_parse_from(["vigil", "scan", "--ai", "--json"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                ai: true,
                json: true
            })
        ));
    }

    #[test]
    fn parse_scan_alias() {
        let cli = Cli::try_parse_from(["vigil", "sc"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cli.command, Some(Commands::Scan { .. })));
    }

    #[test]
    fn parse_report_command() {
        let cli = Cli::try_parse_from(["vigil", "report"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Report {
                hours: 24,
                json: false
            })
        ));
    }

    #[test]
    fn parse_report_with_hours() {
        let cli = Cli::try_parse_from(["vigil", "report", "--hours", "48"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Report {
                hours: 48,
                json: false
            })
        ));
    }

    #[test]
    fn parse_report_with_json() {
        let cli =
            Cli::try_parse_from(["vigil", "report", "--json"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Report {
                hours: 24,
                json: true
            })
        ));
    }

    #[test]
    fn parse_report_alias() {
        let cli = Cli::try_parse_from(["vigil", "r"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cli.command, Some(Commands::Report { .. })));
    }

    #[test]
    fn parse_watch_command() {
        let cli = Cli::try_parse_from(["vigil", "watch"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Watch { interval: None })
        ));
    }

    #[test]
    fn parse_watch_with_interval() {
        let cli = Cli::try_parse_from(["vigil", "watch", "--interval", "5"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Some(Commands::Watch { interval: Some(5) })
        ));
    }

    #[test]
    fn parse_watch_alias() {
        let cli = Cli::try_parse_from(["vigil", "w"]).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cli.command, Some(Commands::Watch { .. })));
    }
}
