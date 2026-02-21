use std::collections::HashMap;

use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::Serialize;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::ports::store::{AlertStore, SnapshotStore};
use crate::domain::value_objects::severity::Severity;
use crate::presentation::cli::formatters::status_fmt::{colorize_percent, print_section_header};

#[derive(Serialize)]
struct ReportOutput {
    hours: u64,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    total_alerts: usize,
    by_severity: BySeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    peak_ram_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peak_cpu_percent: Option<f64>,
    top_rules: Vec<RuleCount>,
    alerts: Vec<Alert>,
}

#[derive(Clone, Serialize)]
struct BySeverity {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Clone, Serialize)]
struct RuleCount {
    rule: String,
    count: usize,
}

/// Generates a report of alerts from the last `hours` hours.
///
/// # Errors
///
/// Returns an error if the store query fails or JSON serialization fails.
pub fn run_report(
    alert_store: &dyn AlertStore,
    snapshot_store: &dyn SnapshotStore,
    hours: u64,
    json: bool,
) -> anyhow::Result<()> {
    if hours == 0 {
        anyhow::bail!("Time window must be greater than 0");
    }
    let i_hours = i64::try_from(hours).map_err(|e| anyhow::anyhow!("invalid hours: {e}"))?;
    let delta = chrono::TimeDelta::try_hours(i_hours)
        .ok_or_else(|| anyhow::anyhow!("invalid time window"))?;
    let now = Utc::now();
    let since = now - delta;

    let alerts = alert_store
        .get_alerts_since(since)
        .map_err(|e| anyhow::anyhow!("failed to read alerts: {e}"))?;
    let snapshots = snapshot_store
        .get_snapshots_since(since)
        .map_err(|e| anyhow::anyhow!("failed to read snapshots: {e}"))?;

    let by_severity = count_by_severity(&alerts);
    let peak_ram = peak_ram_percent(&snapshots);
    let peak_cpu = peak_cpu_percent(&snapshots);
    let top_rules = top_rules(&alerts, 5);

    if json {
        print_report_json(
            hours,
            since,
            now,
            &alerts,
            &by_severity,
            peak_ram,
            peak_cpu,
            &top_rules,
        )?;
    } else {
        print_report_human(hours, &alerts, &by_severity, peak_ram, peak_cpu, &top_rules);
    }

    Ok(())
}

fn count_by_severity(alerts: &[Alert]) -> BySeverity {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for alert in alerts {
        match alert.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }
    BySeverity {
        critical,
        high,
        medium,
        low,
    }
}

fn peak_ram_percent(snapshots: &[SystemSnapshot]) -> Option<f64> {
    snapshots
        .iter()
        .map(|s| s.memory.usage_percent)
        .reduce(f64::max)
}

fn peak_cpu_percent(snapshots: &[SystemSnapshot]) -> Option<f64> {
    snapshots
        .iter()
        .map(|s| (f64::from(s.cpu.global_usage_percent) * 100.0).round() / 100.0)
        .reduce(f64::max)
}

fn top_rules(alerts: &[Alert], limit: usize) -> Vec<RuleCount> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for alert in alerts {
        *counts.entry(alert.rule.as_str()).or_insert(0) += 1;
    }
    let mut sorted: Vec<RuleCount> = counts
        .into_iter()
        .map(|(rule, count)| RuleCount {
            rule: rule.to_string(),
            count,
        })
        .collect();
    sorted.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.rule.cmp(&b.rule)));
    sorted.truncate(limit);
    sorted
}

#[allow(clippy::too_many_arguments)]
fn print_report_json(
    hours: u64,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    alerts: &[Alert],
    by_severity: &BySeverity,
    peak_ram: Option<f64>,
    peak_cpu: Option<f64>,
    top_rules: &[RuleCount],
) -> anyhow::Result<()> {
    let output = ReportOutput {
        hours,
        period_start,
        period_end,
        total_alerts: alerts.len(),
        by_severity: by_severity.clone(),
        peak_ram_percent: peak_ram,
        peak_cpu_percent: peak_cpu,
        top_rules: top_rules.to_vec(),
        alerts: alerts.to_vec(),
    };
    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

fn severity_label(severity: Severity) -> String {
    match severity {
        Severity::Critical => format!("{}", " CRITICAL ".on_red().white().bold()),
        Severity::High => format!("{}", " HIGH ".on_yellow().black().bold()),
        Severity::Medium => format!("{}", " MEDIUM ".on_bright_yellow().black()),
        Severity::Low => format!("{}", " LOW ".on_blue().white()),
    }
}

fn print_report_human(
    hours: u64,
    alerts: &[Alert],
    by_severity: &BySeverity,
    peak_ram: Option<f64>,
    peak_cpu: Option<f64>,
    top_rules: &[RuleCount],
) {
    print_section_header(&format!("\u{1f4ca} Report for the last {hours}h"));

    if alerts.is_empty() {
        println!("{}", "✅ No alerts in this period".green().bold());
        println!();
        return;
    }

    // Summary
    println!("{}", "Summary".bold().underline());
    println!("  Total: {} alert(s)", alerts.len().to_string().bold());
    if by_severity.critical > 0 {
        println!("  {} Critical: {}", "🔴".red(), by_severity.critical);
    }
    if by_severity.high > 0 {
        println!("  🟠 High: {}", by_severity.high);
    }
    if by_severity.medium > 0 {
        println!("  🟡 Medium: {}", by_severity.medium);
    }
    if by_severity.low > 0 {
        println!("  🔵 Low: {}", by_severity.low);
    }
    println!();

    // Timeline
    println!("{}", "Timeline".bold().underline());
    println!(
        "  {:<12} {:<12} {}",
        "Date".dimmed(),
        "Severity".dimmed(),
        "Title".dimmed()
    );
    println!("  {}", "─".repeat(55).dimmed());
    // Show alerts in chronological order (oldest first)
    let mut chronological = alerts.to_vec();
    chronological.sort_by_key(|a| a.timestamp);
    for alert in &chronological {
        let time = alert.timestamp.format("%d/%m %H:%M").to_string();
        println!(
            "  {:<12} {} {}",
            time,
            severity_label(alert.severity),
            alert.title
        );
    }
    println!();

    // Statistics
    println!("{}", "Statistics".bold().underline());
    if let Some(ram) = peak_ram {
        println!("  Peak RAM: {}", colorize_percent(ram));
    }
    if let Some(cpu) = peak_cpu {
        println!("  Peak CPU: {}", colorize_percent(cpu));
    }
    if !top_rules.is_empty() {
        println!();
        println!("  {}", "Most frequent rules:".dimmed());
        for rule in top_rules {
            println!("    {} × {}", rule.count.to_string().bold(), rule.rule);
        }
    }
    println!();
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::SuggestedAction;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use crate::domain::ports::store::StoreError;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use colored::control;

    fn disable_colors() {
        control::set_override(false);
    }

    struct MockStore {
        alerts: Vec<Alert>,
        snapshots: Vec<SystemSnapshot>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                alerts: vec![],
                snapshots: vec![],
            }
        }

        fn with_alerts(alerts: Vec<Alert>) -> Self {
            Self {
                alerts,
                snapshots: vec![],
            }
        }

        fn with_all(alerts: Vec<Alert>, snapshots: Vec<SystemSnapshot>) -> Self {
            Self { alerts, snapshots }
        }
    }

    impl AlertStore for MockStore {
        fn save_alert(&self, _alert: &Alert) -> Result<(), StoreError> {
            Ok(())
        }
        fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.clone())
        }
        fn get_recent_alerts(&self, _count: usize) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.clone())
        }
        fn get_alerts_since(&self, _since: DateTime<Utc>) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.clone())
        }
    }

    impl SnapshotStore for MockStore {
        fn save_snapshot(&self, _snapshot: &SystemSnapshot) -> Result<(), StoreError> {
            Ok(())
        }
        fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
            Ok(self.snapshots.first().cloned())
        }
        fn get_snapshots_since(
            &self,
            _since: DateTime<Utc>,
        ) -> Result<Vec<SystemSnapshot>, StoreError> {
            Ok(self.snapshots.clone())
        }
    }

    struct FailingStore;

    impl AlertStore for FailingStore {
        fn save_alert(&self, _alert: &Alert) -> Result<(), StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
        fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
        fn get_recent_alerts(&self, _count: usize) -> Result<Vec<Alert>, StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
        fn get_alerts_since(&self, _since: DateTime<Utc>) -> Result<Vec<Alert>, StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
    }

    impl SnapshotStore for FailingStore {
        fn save_snapshot(&self, _snapshot: &SystemSnapshot) -> Result<(), StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
        fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
        fn get_snapshots_since(
            &self,
            _since: DateTime<Utc>,
        ) -> Result<Vec<SystemSnapshot>, StoreError> {
            Err(StoreError::ReadFailed("fail".into()))
        }
    }

    fn make_alert(severity: Severity) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: "Test alert".to_string(),
            details: "Some details".to_string(),
            suggested_actions: vec![SuggestedAction {
                description: "Fix it".to_string(),
                command: "echo fix".to_string(),
                risk: ActionRisk::Safe,
            }],
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn make_snapshot(ram_percent: f64, cpu_percent: f64) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8192,
                available_mb: 8192,
                swap_total_mb: 4096,
                swap_used_mb: 0,
                usage_percent: ram_percent,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: cpu_percent as f32,
                per_core_usage: vec![cpu_percent as f32],
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

    #[test]
    fn report_empty_alerts() {
        disable_colors();
        let store = MockStore::new();
        let result = run_report(&store, &store, 24, false);
        assert!(result.is_ok());
    }

    #[test]
    fn report_empty_alerts_json() {
        disable_colors();
        let store = MockStore::new();
        let result = run_report(&store, &store, 24, true);
        assert!(result.is_ok());
    }

    #[test]
    fn report_with_alerts_human() {
        disable_colors();
        let alerts = vec![
            make_alert(Severity::Critical),
            make_alert(Severity::High),
            make_alert(Severity::Low),
        ];
        let store = MockStore::with_alerts(alerts);
        let result = run_report(&store, &store, 24, false);
        assert!(result.is_ok());
    }

    #[test]
    fn report_with_alerts_json() {
        disable_colors();
        let alerts = vec![make_alert(Severity::High), make_alert(Severity::Medium)];
        let store = MockStore::with_alerts(alerts);
        let result = run_report(&store, &store, 24, true);
        assert!(result.is_ok());
    }

    #[test]
    fn report_with_snapshots_shows_peaks() {
        disable_colors();
        let alerts = vec![make_alert(Severity::High)];
        let snapshots = vec![
            make_snapshot(45.0, 30.0),
            make_snapshot(85.0, 70.0),
            make_snapshot(60.0, 50.0),
        ];
        let store = MockStore::with_all(alerts, snapshots);
        let result = run_report(&store, &store, 24, false);
        assert!(result.is_ok());
    }

    #[test]
    fn report_failing_alert_store_returns_error() {
        disable_colors();
        let store = FailingStore;
        let result = run_report(&store, &store, 24, false);
        assert!(result.is_err());
    }

    #[test]
    fn report_zero_hours_returns_error() {
        disable_colors();
        let store = MockStore::new();
        let result = run_report(&store, &store, 0, false);
        assert!(result.is_err());
    }

    #[test]
    fn report_custom_hours() {
        disable_colors();
        let store = MockStore::new();
        let result = run_report(&store, &store, 48, false);
        assert!(result.is_ok());
    }

    #[test]
    fn count_by_severity_counts_correctly() {
        let alerts = vec![
            make_alert(Severity::Critical),
            make_alert(Severity::Critical),
            make_alert(Severity::High),
            make_alert(Severity::Low),
        ];
        let counts = count_by_severity(&alerts);
        assert_eq!(counts.critical, 2);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 1);
    }

    #[test]
    fn peak_ram_finds_maximum() {
        let snapshots = vec![
            make_snapshot(40.0, 20.0),
            make_snapshot(85.0, 50.0),
            make_snapshot(60.0, 30.0),
        ];
        let peak = peak_ram_percent(&snapshots);
        assert_eq!(peak, Some(85.0));
    }

    #[test]
    fn peak_cpu_finds_maximum() {
        let snapshots = vec![
            make_snapshot(40.0, 20.0),
            make_snapshot(50.0, 95.0),
            make_snapshot(60.0, 30.0),
        ];
        let peak = peak_cpu_percent(&snapshots);
        assert_eq!(peak, Some(95.0));
    }

    #[test]
    fn peak_ram_returns_none_on_empty() {
        let peak = peak_ram_percent(&[]);
        assert!(peak.is_none());
    }

    #[test]
    fn top_rules_sorts_by_count() {
        let alerts = vec![
            Alert {
                rule: "ram_high".into(),
                ..make_alert(Severity::High)
            },
            Alert {
                rule: "ram_high".into(),
                ..make_alert(Severity::High)
            },
            Alert {
                rule: "cpu_high".into(),
                ..make_alert(Severity::Medium)
            },
            Alert {
                rule: "ram_high".into(),
                ..make_alert(Severity::High)
            },
            Alert {
                rule: "disk_low".into(),
                ..make_alert(Severity::Low)
            },
        ];
        let top = top_rules(&alerts, 3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].rule, "ram_high");
        assert_eq!(top[0].count, 3);
        // Secondary sort by rule name (alphabetical) for equal counts
        assert_eq!(top[1].rule, "cpu_high");
        assert_eq!(top[1].count, 1);
        assert_eq!(top[2].rule, "disk_low");
        assert_eq!(top[2].count, 1);
    }

    #[test]
    fn top_rules_respects_limit() {
        let alerts = vec![
            Alert {
                rule: "a".into(),
                ..make_alert(Severity::Low)
            },
            Alert {
                rule: "b".into(),
                ..make_alert(Severity::Low)
            },
            Alert {
                rule: "c".into(),
                ..make_alert(Severity::Low)
            },
        ];
        let top = top_rules(&alerts, 2);
        assert_eq!(top.len(), 2);
    }
}
