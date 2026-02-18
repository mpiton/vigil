use clap::{CommandFactory, Parser};
use vigil::presentation::cli::app::{Cli, Commands};
use vigil::presentation::cli::commands::status::run_status;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status { json }) => run_status(json)?,
        Some(Commands::Daemon { .. }) => {
            eprintln!("Commande daemon pas encore implémentée");
        }
        Some(Commands::Scan { .. }) => {
            eprintln!("Commande scan pas encore implémentée");
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
            Cli::command().print_help()?;
        }
    }

    Ok(())
}
