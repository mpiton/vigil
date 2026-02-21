use super::Rule;
use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

/// Patterns identifying development tool processes
const DEV_TOOL_PATTERNS: &[&str] = &[
    "mcp",
    "claude",
    "copilot",
    "lsp-server",
    "typescript-language-server",
];

/// Detects orphaned development tool processes (parent = init/0) consuming CPU resources.
///
/// An orphan dev process is one where:
/// - ppid is 0 or 1 (adopted by init, meaning original parent died)
/// - cmdline matches a known dev tool pattern
/// - `cpu_percent` > 0.0 (actively consuming resources)
pub struct OrphanDevProcessRule;

impl Rule for OrphanDevProcessRule {
    fn name(&self) -> &'static str {
        "orphan_dev_processes"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, _thresholds: &ThresholdSet) -> Vec<Alert> {
        let orphans: Vec<_> = snapshot
            .processes
            .iter()
            .filter(|p| {
                (p.ppid == 0 || p.ppid == 1)
                    && p.cpu_percent > 0.0
                    && DEV_TOOL_PATTERNS
                        .iter()
                        .any(|pat| p.cmdline.to_lowercase().contains(pat))
            })
            .collect();

        if orphans.is_empty() {
            return vec![];
        }

        let total_ram: u64 = orphans.iter().map(|p| p.rss_mb).sum();

        let details = orphans
            .iter()
            .map(|p| {
                let cmdline_display = p
                    .cmdline
                    .char_indices()
                    .nth(100)
                    .map_or(p.cmdline.as_str(), |(i, _)| &p.cmdline[..i]);
                format!(
                    "  PID {} ({}) — {} MB, CPU {:.1}%, cmdline: {}",
                    p.pid, p.name, p.rss_mb, p.cpu_percent, cmdline_display
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let suggested_actions = orphans
            .iter()
            .map(|p| SuggestedAction {
                description: format!("Kill {} (PID {})", p.name, p.pid),
                command: format!("kill {}", p.pid),
                risk: ActionRisk::Safe,
            })
            .collect();

        vec![Alert {
            timestamp: snapshot.timestamp,
            severity: Severity::High,
            rule: "orphan_dev_processes".into(),
            title: format!(
                "{} orphan dev process(es) detected ({} MB RAM)",
                orphans.len(),
                total_ram
            ),
            details,
            suggested_actions,
        }]
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use chrono::Utc;

    fn make_process(pid: u32, ppid: u32, name: &str, cmdline: &str, cpu: f32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            state: ProcessState::Running,
            cpu_percent: cpu,
            rss_mb: 256,
            vms_mb: 512,
            user: "user".to_string(),
            start_time: 0,
            open_fds: 10,
        }
    }

    fn make_snapshot(processes: Vec<ProcessInfo>) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8000,
                available_mb: 8384,
                swap_total_mb: 8192,
                swap_used_mb: 0,
                usage_percent: 48.8,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 10.0,
                per_core_usage: vec![10.0],
                core_count: 1,
                load_avg_1m: 0.5,
                load_avg_5m: 0.4,
                load_avg_15m: 0.3,
            },
            processes,
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[test]
    fn rule_name() {
        assert_eq!(OrphanDevProcessRule.name(), "orphan_dev_processes");
    }

    #[test]
    fn no_alert_when_no_processes() {
        let snapshot = make_snapshot(vec![]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_for_non_dev_orphan() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "nginx",
            "nginx -g daemon off",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_for_dev_with_parent() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            500,
            "node",
            "node /usr/lib/mcp-server/index.js",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_for_zero_cpu_orphan_dev() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "node",
            "node /usr/lib/mcp-server/index.js",
            0.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_for_orphan_dev_ppid_one() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "node",
            "node /usr/lib/mcp-server/index.js",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].rule, "orphan_dev_processes");
        assert!(alerts[0].title.contains("1 orphan dev process"));
        assert!(alerts[0].title.contains("256 MB RAM"));
    }

    #[test]
    fn alert_for_orphan_dev_ppid_zero() {
        let snapshot = make_snapshot(vec![make_process(
            200,
            0,
            "python3",
            "python3 /home/user/.local/mcp-chroma/server.py",
            3.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].details.contains("PID 200"));
    }

    #[test]
    fn multiple_orphan_dev_processes() {
        let snapshot = make_snapshot(vec![
            make_process(100, 1, "node", "node mcp-server/index.js", 5.0),
            make_process(200, 0, "python3", "python3 mcp-chroma/server.py", 3.0),
            make_process(300, 1, "copilot", "copilot-agent --stdio", 2.0),
        ]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("3 orphan dev process"));
        assert_eq!(alerts[0].suggested_actions.len(), 3);
    }

    #[test]
    fn calculates_total_ram() {
        let mut p1 = make_process(100, 1, "node", "node mcp-server/index.js", 5.0);
        p1.rss_mb = 512;
        let mut p2 = make_process(200, 1, "python3", "python3 mcp-chroma/server.py", 3.0);
        p2.rss_mb = 1024;
        let snapshot = make_snapshot(vec![p1, p2]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts[0].title.contains("1536 MB RAM"));
    }

    #[test]
    fn suggested_actions_per_process() {
        let snapshot = make_snapshot(vec![
            make_process(100, 1, "node", "node mcp-server/index.js", 5.0),
            make_process(200, 1, "copilot", "copilot-agent --stdio", 2.0),
        ]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts[0].suggested_actions.len(), 2);
        assert!(alerts[0].suggested_actions[0].command.contains("kill 100"));
        assert!(alerts[0].suggested_actions[1].command.contains("kill 200"));
        assert_eq!(alerts[0].suggested_actions[0].risk, ActionRisk::Safe);
        assert!(alerts[0].suggested_actions[0]
            .description
            .starts_with("Kill "));
    }

    #[test]
    fn case_insensitive_pattern_matching() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "node",
            "node /usr/lib/MCP-Server/index.js",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn detects_claude_pattern() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "claude",
            "claude --model opus",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn detects_copilot_pattern() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "copilot",
            "copilot-agent --stdio",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn detects_lsp_server_pattern() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "lsp",
            "rust-analyzer lsp-server",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn detects_typescript_language_server_pattern() {
        let snapshot = make_snapshot(vec![make_process(
            100,
            1,
            "node",
            "node typescript-language-server --stdio",
            5.0,
        )]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn cmdline_truncated_in_details() {
        let long_cmdline = format!("python3 /very/long/path/to/mcp-server/{}", "a".repeat(200));
        let snapshot = make_snapshot(vec![make_process(100, 1, "python3", &long_cmdline, 5.0)]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(!alerts[0].details.contains(&"a".repeat(200)));
        // The details should contain the truncated cmdline (100 chars max)
        assert_eq!(alerts[0].details.lines().count(), 1);
    }

    #[test]
    fn mixed_orphan_and_non_orphan_processes() {
        let snapshot = make_snapshot(vec![
            // Orphan dev process (should trigger)
            make_process(100, 1, "node", "node mcp-server/index.js", 5.0),
            // Non-orphan dev process (ppid != 0/1)
            make_process(200, 500, "node", "node mcp-server/index.js", 5.0),
            // Orphan non-dev process
            make_process(300, 1, "nginx", "nginx -g daemon off", 5.0),
            // Orphan dev but zero CPU
            make_process(400, 1, "node", "node mcp-server/index.js", 0.0),
        ]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].suggested_actions.len(), 1);
        assert!(alerts[0].suggested_actions[0].command.contains("kill 100"));
    }

    #[test]
    fn cmdline_with_multibyte_utf8_does_not_panic() {
        // cmdline with accented chars that exceed 100 bytes — must not panic on slicing
        let cmdline = format!("python3 /home/user/mcp-sérveur/{}", "àèéùç".repeat(20));
        assert!(cmdline.len() > 100);
        let snapshot = make_snapshot(vec![make_process(100, 1, "python3", &cmdline, 5.0)]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        // Details should contain a truncated version, not the full cmdline
        assert!(alerts[0].details.contains("PID 100"));
    }

    #[test]
    fn cmdline_exactly_100_chars_not_truncated() {
        // Build a cmdline of exactly 100 ASCII characters containing "mcp"
        let padding = "x".repeat(100 - "python3 mcp-server/".len());
        let cmdline = format!("python3 mcp-server/{padding}");
        assert_eq!(cmdline.len(), 100);
        let snapshot = make_snapshot(vec![make_process(100, 1, "python3", &cmdline, 5.0)]);
        let alerts = OrphanDevProcessRule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        // Full cmdline should appear since it's exactly 100 chars (not > 100)
        assert!(alerts[0].details.contains(&cmdline));
    }
}
