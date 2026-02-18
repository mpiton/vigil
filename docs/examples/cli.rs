use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "vigil",
    version,
    about = "🛡️ Vigil — AI-powered Linux system guardian",
    long_about = "Vigil monitors your system processes, RAM, CPU, GPU, disks, and logs.\n\
                  It detects anomalies and proposes corrections using AI analysis\n\
                  to prevent your PC from slowing down or crashing."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to config file (default: ~/.config/vigil/config.toml)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true, default_value_t = false)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the monitoring daemon (default behavior)
    Daemon {
        /// Operation mode override
        #[arg(short, long)]
        mode: Option<String>,
    },

    /// Show current system status snapshot
    Status {
        /// Output as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// One-shot analysis — collect, analyze, report, exit
    Scan {
        /// Include AI analysis
        #[arg(long, default_value_t = false)]
        ai: bool,

        /// Output as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Explain what a process is doing (uses AI)
    Explain {
        /// Process ID to analyze
        pid: u32,
    },

    /// Kill a process with confirmation and logging
    Kill {
        /// Process ID to kill
        pid: u32,

        /// Force kill (SIGKILL instead of SIGTERM)
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },

    /// Show or edit configuration
    Config {
        /// Open config in editor
        #[arg(long, default_value_t = false)]
        edit: bool,
    },
}
