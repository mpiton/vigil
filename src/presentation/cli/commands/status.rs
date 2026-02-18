use std::time::Duration;

use anyhow::Context;
use colored::Colorize;

use crate::domain::entities::process::ProcessState;
use crate::domain::ports::collector::SystemCollector;
use crate::infrastructure::collectors::sysinfo_collector::SysinfoCollector;

use crate::presentation::cli::formatters::status_fmt::{
    colorize_percent, print_section_header, progress_bar,
};
use crate::presentation::cli::formatters::table_fmt::format_process_table;

/// # Errors
///
/// Returns an error if system metrics collection or JSON serialization fails.
pub fn run_status(json: bool) -> anyhow::Result<()> {
    let collector = SysinfoCollector::new();
    std::thread::sleep(Duration::from_millis(500));
    let snapshot = collector
        .collect()
        .context("Échec de la collecte des métriques système")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(());
    }

    println!("{}", "vigil — System Status".bold().cyan());
    println!("{}", "━".repeat(50));

    // RAM
    let mem = &snapshot.memory;
    print_section_header("\n💾 Mémoire RAM");
    println!(
        "  {} {}",
        progress_bar(mem.usage_percent, 30),
        colorize_percent(mem.usage_percent)
    );
    println!(
        "  Utilisé: {} Mo / {} Mo (Disponible: {} Mo)",
        mem.used_mb, mem.total_mb, mem.available_mb
    );

    // Swap
    if mem.swap_total_mb > 0 {
        print_section_header("\n🔄 Swap");
        println!(
            "  {} {}",
            progress_bar(mem.swap_percent, 30),
            colorize_percent(mem.swap_percent)
        );
        println!(
            "  Utilisé: {} Mo / {} Mo",
            mem.swap_used_mb, mem.swap_total_mb
        );
    }

    // CPU
    let cpu = &snapshot.cpu;
    print_section_header("\n🖥️  CPU");
    println!(
        "  Load average: {:.2} / {:.2} / {:.2}",
        cpu.load_avg_1m, cpu.load_avg_5m, cpu.load_avg_15m
    );
    println!(
        "  Usage global: {} ({} cœurs)",
        colorize_percent(f64::from(cpu.global_usage_percent)),
        cpu.core_count
    );

    // Disques
    if !snapshot.disks.is_empty() {
        print_section_header("\n💿 Disques");
        for disk in &snapshot.disks {
            println!(
                "  {} {} {} ({:.1} Go libre)",
                disk.mount_point,
                progress_bar(disk.usage_percent, 20),
                colorize_percent(disk.usage_percent),
                disk.available_gb
            );
        }
    }

    // Top 5 processus
    print_section_header("\n📊 Top 5 processus (RAM)");
    println!("{}", format_process_table(&snapshot.processes, 5));

    // Zombies
    let zombies: Vec<_> = snapshot
        .processes
        .iter()
        .filter(|p| matches!(p.state, ProcessState::Zombie))
        .collect();
    if !zombies.is_empty() {
        println!(
            "\n{}",
            format!("🧟 {} processus zombie(s) détecté(s)", zombies.len())
                .red()
                .bold()
        );
    }

    Ok(())
}
