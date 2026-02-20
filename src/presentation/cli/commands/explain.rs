use anyhow::Context as _;
use colored::Colorize;

use crate::domain::entities::process::ProcessInfo;
use crate::domain::ports::analyzer::AiAnalyzer;
use crate::domain::ports::collector::SystemCollector;
use crate::presentation::cli::formatters::status_fmt::print_section_header;

/// Explains a specific process in detail, optionally using AI analysis.
///
/// # Errors
///
/// Returns an error if metrics collection fails or if the process with the given PID is not found.
pub async fn run_explain(
    collector: &dyn SystemCollector,
    analyzer: &dyn AiAnalyzer,
    ai_enabled: bool,
    pid: u32,
) -> anyhow::Result<()> {
    let snapshot = collector
        .collect()
        .context("Échec de la collecte système")?;

    let process = snapshot
        .processes
        .iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| anyhow::anyhow!("Processus avec PID {pid} non trouvé"))?;

    print_process_info(process);

    if ai_enabled {
        match analyzer.explain_process(process).await {
            Ok(Some(text)) => {
                print_section_header("Explication IA");
                println!("{text}");
            }
            Ok(None) => {
                println!(
                    "{}",
                    "Analyse IA non disponible (en attente de cooldown)".yellow()
                );
            }
            Err(e) => {
                tracing::warn!("Échec de l'analyse IA : {e}");
                println!("{}", "⚠ Analyse IA échouée".yellow());
            }
        }
    }

    Ok(())
}

fn print_process_info(process: &ProcessInfo) {
    print_section_header("🔍 Informations du processus");
    println!("{}: {}", "Nom".bold(), process.name);
    println!("{}: {}", "Ligne de commande".bold(), process.cmdline);
    println!("{}: {}", "État".bold(), process.state);
    println!("{}: {} MB", "Mémoire RSS".bold(), process.rss_mb);
    println!("{}: {} MB", "Mémoire virtuelle".bold(), process.vms_mb);
    println!("{}: {:.1}%", "CPU".bold(), process.cpu_percent);
    println!("{}: {}", "PID parent".bold(), process.ppid);
    println!(
        "{}: {}",
        "Descripteurs de fichiers".bold(),
        process.open_fds
    );
    println!("{}: {}", "Utilisateur".bold(), process.user);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::Alert;
    use crate::domain::entities::diagnostic::AiDiagnostic;
    use crate::domain::entities::process::ProcessState;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::analyzer::AnalysisError;
    use crate::domain::ports::collector::CollectionError;
    use async_trait::async_trait;
    use chrono::Utc;
    use colored::control;

    fn disable_colors() {
        control::set_override(false);
    }

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
            Err(CollectionError::MetricsUnavailable("test error".into()))
        }
    }

    struct NoopAnalyzer;

    #[async_trait]
    impl AiAnalyzer for NoopAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(None)
        }
    }

    struct ExplainAnalyzer;

    #[async_trait]
    impl AiAnalyzer for ExplainAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(None)
        }

        async fn explain_process(
            &self,
            _process: &ProcessInfo,
        ) -> Result<Option<String>, AnalysisError> {
            Ok(Some("Ce processus consomme beaucoup de CPU.".to_string()))
        }
    }

    struct FailingAnalyzer;

    #[async_trait]
    impl AiAnalyzer for FailingAnalyzer {
        async fn analyze(
            &self,
            _snapshot: &SystemSnapshot,
            _alerts: &[Alert],
        ) -> Result<Option<AiDiagnostic>, AnalysisError> {
            Ok(None)
        }

        async fn explain_process(
            &self,
            _process: &ProcessInfo,
        ) -> Result<Option<String>, AnalysisError> {
            Err(AnalysisError::ServiceUnavailable("API down".into()))
        }
    }

    fn make_snapshot_with_process(pid: u32) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 4000,
                available_mb: 12384,
                swap_total_mb: 8192,
                swap_used_mb: 0,
                usage_percent: 24.4,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 10.0,
                per_core_usage: vec![10.0],
                core_count: 4,
                load_avg_1m: 0.5,
                load_avg_5m: 0.4,
                load_avg_15m: 0.3,
            },
            processes: vec![ProcessInfo {
                pid,
                ppid: 1,
                name: "test-process".to_string(),
                cmdline: "/usr/bin/test-process --flag".to_string(),
                state: ProcessState::Running,
                cpu_percent: 5.5,
                rss_mb: 128,
                vms_mb: 512,
                user: "root".to_string(),
                start_time: 1000,
                open_fds: 42,
            }],
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[tokio::test]
    async fn test_explain_process_found() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let analyzer = NoopAnalyzer;
        let result = run_explain(&collector, &analyzer, false, 1234).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_explain_process_not_found() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let analyzer = NoopAnalyzer;
        let result = run_explain(&collector, &analyzer, false, 9999).await;
        assert!(result.is_err());
        let err = result.expect_err("should be error");
        assert!(err.to_string().contains("9999"));
    }

    #[tokio::test]
    async fn test_explain_with_ai_enabled() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let analyzer = ExplainAnalyzer;
        let result = run_explain(&collector, &analyzer, true, 1234).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_explain_with_ai_disabled() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let analyzer = FailingAnalyzer;
        let result = run_explain(&collector, &analyzer, false, 1234).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_explain_collection_error() {
        disable_colors();
        let collector = FailingCollector;
        let analyzer = NoopAnalyzer;
        let result = run_explain(&collector, &analyzer, false, 1234).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_explain_ai_cooldown_returns_none() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let analyzer = NoopAnalyzer;
        let result = run_explain(&collector, &analyzer, true, 1234).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_explain_ai_error_continues() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let analyzer = FailingAnalyzer;
        let result = run_explain(&collector, &analyzer, true, 1234).await;
        assert!(result.is_ok());
    }
}
