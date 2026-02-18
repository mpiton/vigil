use anyhow::Context;
use colored::Colorize;

use crate::domain::entities::process::ProcessState;
use crate::domain::ports::collector::SystemCollector;

use crate::presentation::cli::formatters::status_fmt::{
    colorize_percent, print_section_header, progress_bar,
};
use crate::presentation::cli::formatters::table_fmt::format_process_table;

/// # Errors
///
/// Returns an error if system metrics collection or JSON serialization fails.
pub fn run_status(collector: &dyn SystemCollector, json: bool) -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::disk::DiskInfo;
    use crate::domain::entities::process::ProcessInfo;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::collector::CollectionError;
    use chrono::Utc;
    use colored::control;

    struct MockCollector {
        snapshot: SystemSnapshot,
    }

    impl SystemCollector for MockCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Ok(self.snapshot.clone())
        }
    }

    struct FailingCollector;

    impl SystemCollector for FailingCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Err(CollectionError::MetricsUnavailable(
                "mock failure".to_string(),
            ))
        }
    }

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8192,
                available_mb: 8192,
                swap_total_mb: 2048,
                swap_used_mb: 512,
                usage_percent: 50.0,
                swap_percent: 25.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 25.0,
                per_core_usage: vec![20.0, 30.0],
                core_count: 2,
                load_avg_1m: 1.5,
                load_avg_5m: 1.2,
                load_avg_15m: 0.8,
            },
            processes: vec![ProcessInfo {
                pid: 100,
                ppid: 1,
                name: "test_proc".to_string(),
                cmdline: "test_proc --flag".to_string(),
                state: ProcessState::Running,
                cpu_percent: 5.0,
                rss_mb: 256,
                vms_mb: 512,
                user: "user".to_string(),
                start_time: 0,
                open_fds: 10,
            }],
            disks: vec![DiskInfo {
                mount_point: "/".to_string(),
                total_gb: 500.0,
                available_gb: 250.0,
                usage_percent: 50.0,
                filesystem: "ext4".to_string(),
            }],
            journal_entries: vec![],
        }
    }

    #[test]
    fn run_status_json_outputs_valid_json() {
        control::set_override(false);
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let result = run_status(&collector, true);
        assert!(result.is_ok());
    }

    #[test]
    fn run_status_human_output_succeeds() {
        control::set_override(false);
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let result = run_status(&collector, false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_status_without_swap() {
        control::set_override(false);
        let mut snapshot = make_snapshot();
        snapshot.memory.swap_total_mb = 0;
        snapshot.memory.swap_used_mb = 0;
        snapshot.memory.swap_percent = 0.0;
        let collector = MockCollector { snapshot };
        let result = run_status(&collector, false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_status_without_disks() {
        control::set_override(false);
        let mut snapshot = make_snapshot();
        snapshot.disks.clear();
        let collector = MockCollector { snapshot };
        let result = run_status(&collector, false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_status_with_zombies() {
        control::set_override(false);
        let mut snapshot = make_snapshot();
        snapshot.processes.push(ProcessInfo {
            pid: 999,
            ppid: 1,
            name: "zombie_proc".to_string(),
            cmdline: String::new(),
            state: ProcessState::Zombie,
            cpu_percent: 0.0,
            rss_mb: 0,
            vms_mb: 0,
            user: "root".to_string(),
            start_time: 0,
            open_fds: 0,
        });
        let collector = MockCollector { snapshot };
        let result = run_status(&collector, false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_status_collection_error() {
        let collector = FailingCollector;
        let result = run_status(&collector, false);
        assert!(result.is_err());
    }
}
