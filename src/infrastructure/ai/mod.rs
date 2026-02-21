pub mod claude;
pub mod noop;
pub mod prompt_builder;

use crate::application::config::AiConfig;
use crate::domain::ports::AiAnalyzer;

use self::claude::ClaudeCliAnalyzer;
use self::noop::NoopAnalyzer;

/// Create the appropriate AI analyzer based on configuration.
///
/// Returns [`NoopAnalyzer`] when AI is disabled or the provider is unknown.
#[must_use]
pub fn create_ai_analyzer(config: &AiConfig) -> Box<dyn AiAnalyzer> {
    if !config.enabled {
        return Box::new(NoopAnalyzer::new());
    }
    match config.provider.trim() {
        "claude-cli" => Box::new(ClaudeCliAnalyzer::new(
            config.claude_binary.clone(),
            config.model.clone(),
            config.cooldown_secs,
            config.timeout_secs,
        )),
        "noop" => Box::new(NoopAnalyzer::new()),
        _ => {
            tracing::warn!(
                provider = %config.provider,
                "unknown AI provider, falling back to noop"
            );
            Box::new(NoopAnalyzer::new())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::{Alert, CpuInfo, MemoryInfo, SystemSnapshot};
    use chrono::Utc;

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 8192,
                used_mb: 4096,
                available_mb: 4096,
                swap_total_mb: 2048,
                swap_used_mb: 0,
                usage_percent: 50.0,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 25.0,
                per_core_usage: vec![25.0],
                core_count: 4,
                load_avg_1m: 1.0,
                load_avg_5m: 0.8,
                load_avg_15m: 0.5,
            },
            processes: vec![],
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[tokio::test]
    async fn disabled_config_returns_noop() {
        let config = AiConfig {
            enabled: false,
            ..AiConfig::default()
        };
        let analyzer = create_ai_analyzer(&config);
        let snapshot = make_snapshot();
        let alerts: Vec<Alert> = vec![];

        let result = analyzer.analyze(&snapshot, &alerts).await;
        assert!(result.is_ok());
        assert!(result.expect("should be ok").is_none());
    }

    #[test]
    fn claude_cli_provider_creates_analyzer() {
        let config = AiConfig {
            enabled: true,
            provider: "claude-cli".into(),
            ..AiConfig::default()
        };
        let _analyzer = create_ai_analyzer(&config);
    }

    #[tokio::test]
    async fn unknown_provider_falls_back_to_noop() {
        let config = AiConfig {
            enabled: true,
            provider: "unknown".into(),
            ..AiConfig::default()
        };
        let analyzer = create_ai_analyzer(&config);
        let snapshot = make_snapshot();
        let alerts: Vec<Alert> = vec![];

        let result = analyzer.analyze(&snapshot, &alerts).await;
        assert!(result.is_ok());
        assert!(result.expect("should be ok").is_none());
    }

    #[tokio::test]
    async fn noop_provider_returns_noop() {
        let config = AiConfig {
            enabled: true,
            provider: "noop".into(),
            ..AiConfig::default()
        };
        let analyzer = create_ai_analyzer(&config);
        let snapshot = make_snapshot();
        let alerts: Vec<Alert> = vec![];

        let result = analyzer.analyze(&snapshot, &alerts).await;
        assert!(result.is_ok());
        assert!(result.expect("should be ok").is_none());
    }
}
