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
}
