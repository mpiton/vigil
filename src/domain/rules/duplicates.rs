use std::collections::HashMap;

use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::domain::value_objects::severity::Severity;
use crate::domain::value_objects::thresholds::ThresholdSet;

use super::Rule;

const IGNORED_PROCESSES: &[&str] = &["systemd", "dbus-daemon", "Xorg", "Xwayland", "vigil"];

const DEV_TOOL_KEYWORDS: &[&str] = &["python", "node", "mcp", "typescript"];

pub struct DuplicateProcessRule;

/// Normalize a process name for grouping.
/// For interpreted languages (python/node/ruby), uses "interpreter:script" as key.
/// Finds the script argument by looking for a path or known extension, skipping flags.
/// Otherwise falls back to the bare process name.
fn normalize_process_name(cmdline: &str, name: &str) -> String {
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    if parts.len() >= 2 {
        let exec = parts[0];
        if exec.contains("python") || exec.contains("node") || exec.contains("ruby") {
            if let Some(script_arg) = parts.iter().skip(1).find(|p| looks_like_script(p)) {
                let script = script_arg.rsplit('/').next().unwrap_or(script_arg);
                let interpreter = exec.rsplit('/').next().unwrap_or(exec);
                return format!("{interpreter}:{script}");
            }
        }
    }
    name.to_string()
}

fn looks_like_script(arg: &str) -> bool {
    use std::path::Path;
    let ext_matches = |ext_name: &str| {
        Path::new(arg)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case(ext_name))
    };
    arg.contains('/')
        || ext_matches("py")
        || ext_matches("js")
        || ext_matches("rb")
        || ext_matches("ts")
        || ext_matches("mjs")
        || ext_matches("cjs")
}

fn is_ignored(name: &str) -> bool {
    IGNORED_PROCESSES.contains(&name)
}

fn is_likely_dev_tool(cmdline: &str) -> bool {
    DEV_TOOL_KEYWORDS.iter().any(|kw| cmdline.contains(kw))
}

/// Escape a string for safe use inside single quotes in a shell command.
fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Build a pkill-safe pattern from the group's first cmdline.
/// For interpreter groups (key contains ':'), uses the script path.
/// Otherwise uses the process name.
fn pkill_pattern(group_key: &str, first_cmdline: &str) -> String {
    if group_key.contains(':') {
        let parts: Vec<&str> = first_cmdline.split_whitespace().collect();
        if let Some(script_arg) = parts.iter().skip(1).find(|p| looks_like_script(p)) {
            return (*script_arg).to_string();
        }
    }
    group_key.to_string()
}

impl Rule for DuplicateProcessRule {
    fn name(&self) -> &'static str {
        "duplicate_processes"
    }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        let max_dupes = thresholds.max_duplicate_processes;

        let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, proc) in snapshot.processes.iter().enumerate() {
            if is_ignored(&proc.name) {
                continue;
            }
            let key = normalize_process_name(&proc.cmdline, &proc.name);
            groups.entry(key).or_default().push(idx);
        }

        let mut alerts = Vec::new();

        for (group_key, indices) in &groups {
            if indices.len() <= max_dupes {
                continue;
            }

            let procs: Vec<_> = indices.iter().map(|&i| &snapshot.processes[i]).collect();
            let total_ram_mb: u64 = procs.iter().map(|p| p.rss_mb).sum();
            let total_cpu: f32 = procs.iter().map(|p| p.cpu_percent).sum();
            let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();

            // Check dev tool keywords against original cmdlines, not the normalized key
            let likely_dev_tool = procs.iter().any(|p| is_likely_dev_tool(&p.cmdline));

            let severity = if total_ram_mb > 1024 || likely_dev_tool {
                Severity::High
            } else {
                Severity::Medium
            };

            let context = if likely_dev_tool {
                "Likely unterminated MCP/dev processes."
            } else {
                "Unusual number of identical processes."
            };

            let pattern = pkill_pattern(group_key, &procs[0].cmdline);
            let escaped_pattern = shell_escape(&pattern);

            alerts.push(Alert {
                timestamp: snapshot.timestamp,
                severity,
                rule: "duplicate_processes".to_string(),
                title: format!(
                    "{} instances of \"{}\" ({} MB total, CPU {:.1}%)",
                    procs.len(),
                    group_key,
                    total_ram_mb,
                    total_cpu
                ),
                details: format!(
                    "{context}\nPIDs: {pids:?}\nTotal RAM: {total_ram_mb} MB | Total CPU: {total_cpu:.1}%"
                ),
                suggested_actions: vec![
                    SuggestedAction {
                        description: format!("Kill all \"{group_key}\" processes"),
                        command: format!("pkill -f '{escaped_pattern}'"),
                        risk: ActionRisk::Moderate,
                    },
                    SuggestedAction {
                        description: "Kill by PID list".to_string(),
                        command: format!(
                            "kill {}",
                            pids.iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(" ")
                        ),
                        risk: ActionRisk::Moderate,
                    },
                ],
            });
        }

        alerts
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use chrono::Utc;

    fn make_process(pid: u32, name: &str, cmdline: &str, rss_mb: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            state: ProcessState::Running,
            cpu_percent: 5.0,
            rss_mb,
            vms_mb: rss_mb * 2,
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
    fn detects_mcp_python_storm() {
        let processes: Vec<ProcessInfo> = (0..12)
            .map(|i| {
                make_process(
                    1000 + i,
                    "python3",
                    "python3 /home/user/.mcp/servers/web-search/server.py",
                    150,
                )
            })
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("12 instances"));
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].rule, "duplicate_processes");
    }

    #[test]
    fn no_alert_below_threshold() {
        let processes: Vec<ProcessInfo> = (0..3)
            .map(|i| make_process(1000 + i, "nginx", "/usr/sbin/nginx", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_at_exact_threshold() {
        let processes: Vec<ProcessInfo> = (0..5)
            .map(|i| make_process(1000 + i, "nginx", "/usr/sbin/nginx", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_at_threshold_plus_one() {
        let processes: Vec<ProcessInfo> = (0..6)
            .map(|i| make_process(1000 + i, "nginx", "/usr/sbin/nginx", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("6 instances"));
    }

    #[test]
    fn ignores_allowlisted_processes() {
        let processes: Vec<ProcessInfo> = (0..10)
            .map(|i| make_process(1000 + i, "systemd", "/usr/lib/systemd/systemd", 20))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn allowlist_uses_exact_match() {
        // "systemd-resolved" should NOT be ignored (not an exact match for "systemd")
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| {
                make_process(
                    1000 + i,
                    "systemd-resolved",
                    "/usr/lib/systemd/systemd-resolved",
                    30,
                )
            })
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn normalizes_python_scripts_into_separate_groups() {
        let mut processes = Vec::new();
        for i in 0..6 {
            processes.push(make_process(
                1000 + i,
                "python3",
                "python3 /home/user/.mcp/servers/web-search/server.py",
                100,
            ));
        }
        for i in 0..6 {
            processes.push(make_process(
                2000 + i,
                "python3",
                "python3 /home/user/.mcp/servers/memory/main.py",
                80,
            ));
        }
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn normalizes_with_flags_skipped() {
        // python3 -u server.py should still group by server.py
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| {
                make_process(
                    1000 + i,
                    "python3",
                    "python3 -u /home/user/.mcp/servers/web-search/server.py",
                    100,
                )
            })
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("8 instances"));
    }

    #[test]
    fn high_severity_for_dev_tools() {
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| make_process(1000 + i, "node", "node /home/user/project/server.js", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].details.contains("MCP/dev"));
    }

    #[test]
    fn high_severity_for_mcp_keyword_in_cmdline() {
        // "mcp" detected in cmdline even though normalized key is "python3:server.py"
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| {
                make_process(
                    1000 + i,
                    "python3",
                    "python3 /home/user/.mcp/servers/web-search/server.py",
                    50,
                )
            })
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].details.contains("MCP/dev"));
    }

    #[test]
    fn high_severity_for_high_ram() {
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| make_process(1000 + i, "myapp", "/usr/bin/myapp", 200))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        // 8 * 200 = 1600 MB > 1024 MB → High
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn medium_severity_for_normal_duplicates() {
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| make_process(1000 + i, "myapp", "/usr/bin/myapp", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts.len(), 1);
        // 8 * 50 = 400 MB < 1024, not dev tool → Medium
        assert_eq!(alerts[0].severity, Severity::Medium);
    }

    #[test]
    fn suggested_actions_include_pkill_and_kill() {
        let processes: Vec<ProcessInfo> = (0..6)
            .map(|i| make_process(1000 + i, "myapp", "/usr/bin/myapp", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert_eq!(alerts[0].suggested_actions.len(), 2);
        assert!(alerts[0].suggested_actions[0].command.contains("pkill"));
        assert!(alerts[0].suggested_actions[1].command.contains("kill"));
        assert_eq!(alerts[0].suggested_actions[0].risk, ActionRisk::Moderate);
        assert_eq!(alerts[0].suggested_actions[1].risk, ActionRisk::Moderate);
    }

    #[test]
    fn pkill_uses_script_path_for_interpreters() {
        let processes: Vec<ProcessInfo> = (0..8)
            .map(|i| {
                make_process(
                    1000 + i,
                    "python3",
                    "python3 /home/user/.mcp/servers/web-search/server.py",
                    100,
                )
            })
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        // pkill should use the full script path, not the normalized key with ':'
        let pkill_cmd = &alerts[0].suggested_actions[0].command;
        assert!(
            pkill_cmd.contains("/home/user/.mcp/servers/web-search/server.py"),
            "pkill should use script path, got: {pkill_cmd}"
        );
        assert!(!pkill_cmd.contains(':'), "pkill should not contain ':'");
    }

    #[test]
    fn shell_escape_handles_single_quotes() {
        let escaped = shell_escape("test'name");
        assert_eq!(escaped, "test'\\''name");
    }

    #[test]
    fn no_alert_on_empty_process_list() {
        let snapshot = make_snapshot(vec![]);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = DuplicateProcessRule;
        assert_eq!(rule.name(), "duplicate_processes");
    }

    #[test]
    fn normalize_uses_script_name_for_python() {
        let key = normalize_process_name(
            "python3 /home/user/.mcp/servers/web-search/server.py",
            "python3",
        );
        assert_eq!(key, "python3:server.py");
    }

    #[test]
    fn normalize_uses_script_name_for_node() {
        let key = normalize_process_name("node /opt/app/index.js", "node");
        assert_eq!(key, "node:index.js");
    }

    #[test]
    fn normalize_falls_back_to_name() {
        let key = normalize_process_name("/usr/sbin/nginx", "nginx");
        assert_eq!(key, "nginx");
    }

    #[test]
    fn normalize_skips_flags() {
        let key = normalize_process_name("python3 -u /home/user/server.py", "python3");
        assert_eq!(key, "python3:server.py");
    }

    #[test]
    fn normalize_skips_multiple_flags() {
        let key = normalize_process_name("python3 -W ignore -u /home/user/server.py", "python3");
        assert_eq!(key, "python3:server.py");
    }

    #[test]
    fn normalize_empty_cmdline_falls_back() {
        let key = normalize_process_name("", "kworker");
        assert_eq!(key, "kworker");
    }

    #[test]
    fn normalize_interpreter_with_only_flags() {
        // python3 -c (no script file) → falls back to process name
        let key = normalize_process_name("python3 -c", "python3");
        assert_eq!(key, "python3");
    }

    #[test]
    fn ignores_vigil_processes() {
        let processes: Vec<ProcessInfo> = (0..10)
            .map(|i| make_process(1000 + i, "vigil", "/usr/local/bin/vigil", 50))
            .collect();
        let snapshot = make_snapshot(processes);
        let rule = DuplicateProcessRule;
        let alerts = rule.evaluate(&snapshot, &ThresholdSet::default());
        assert!(alerts.is_empty());
    }
}
