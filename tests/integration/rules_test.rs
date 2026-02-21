#![allow(clippy::expect_used)]

use chrono::Utc;
use vigil::domain::entities::disk::DiskInfo;
use vigil::domain::entities::journal::JournalEntry;
use vigil::domain::entities::process::{ProcessInfo, ProcessState};
use vigil::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
use vigil::domain::rules::{default_rules, RuleEngine};
use vigil::domain::value_objects::severity::Severity;
use vigil::domain::value_objects::thresholds::ThresholdSet;

fn load_fixture(name: &str) -> SystemSnapshot {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let json = std::fs::read_to_string(&path).expect("Failed to read fixture");
    serde_json::from_str(&json).expect("Failed to parse fixture")
}

fn make_base_snapshot() -> SystemSnapshot {
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
            core_count: 4,
            load_avg_1m: 0.5,
            load_avg_5m: 0.4,
            load_avg_15m: 0.3,
        },
        processes: vec![],
        disks: vec![],
        journal_entries: vec![],
    }
}

#[allow(clippy::similar_names)]
fn make_process(
    pid: u32,
    ppid: u32,
    name: &str,
    cmdline: &str,
    state: ProcessState,
) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        name: name.to_string(),
        cmdline: cmdline.to_string(),
        state,
        cpu_percent: 0.5,
        rss_mb: 100,
        vms_mb: 200,
        user: "user".to_string(),
        start_time: 1_708_400_000,
        open_fds: 10,
    }
}

#[test]
fn normal_snapshot_triggers_no_alerts() {
    let snapshot = load_fixture("snapshot_normal.json");
    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);
    assert!(
        alerts.is_empty(),
        "Expected no alerts on normal snapshot, got: {alerts:?}"
    );
}

#[test]
fn ram_critical_snapshot_triggers_ram_rule() {
    let snapshot = load_fixture("snapshot_ram_critical.json");
    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    assert!(
        !alerts.is_empty(),
        "Expected at least one alert for RAM critical snapshot"
    );

    let ram_critical_alert = alerts
        .iter()
        .find(|a| a.rule.contains("ram_critical"))
        .expect("Expected a ram_critical alert");
    assert_eq!(ram_critical_alert.severity, Severity::Critical);

    let swap_warning_alert = alerts.iter().find(|a| a.rule == "swap_warning");
    assert!(
        swap_warning_alert.is_some(),
        "Expected a swap_warning alert (swap at 60%, between 50% and 80% thresholds)"
    );
}

#[test]
fn mcp_zombies_snapshot_triggers_duplicate_rule() {
    let snapshot = load_fixture("snapshot_mcp_zombies.json");
    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    assert_eq!(
        alerts.len(),
        3,
        "Expected duplicate + orphan + zombie alerts, got: {alerts:?}"
    );

    let duplicate_alert = alerts
        .iter()
        .find(|a| a.rule == "duplicate_processes")
        .expect("Expected a duplicate_processes alert for 12 identical python3:server.py");
    assert!(
        duplicate_alert.title.contains("12 instances"),
        "Expected title to mention 12 instances, got: {}",
        duplicate_alert.title
    );

    let orphan_alert = alerts
        .iter()
        .find(|a| a.rule == "orphan_dev_processes")
        .expect("Expected an orphan_dev_processes alert for mcp processes with ppid=1");
    assert_eq!(orphan_alert.severity, Severity::High);

    let zombie_alert = alerts
        .iter()
        .find(|a| a.rule == "zombie_processes")
        .expect("Expected a zombie_processes alert for 2 zombie python3 workers");
    assert_eq!(zombie_alert.severity, Severity::Medium);
}

#[test]
fn oom_snapshot_triggers_oom_rule() {
    let snapshot = load_fixture("snapshot_oom.json");
    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    let oom_alert = alerts
        .iter()
        .find(|a| a.rule == "oom_killer")
        .expect("Expected an oom_killer alert for OOM journal entries");
    assert_eq!(
        oom_alert.severity,
        Severity::Critical,
        "OOM killer alert should be Critical"
    );

    // load_avg_5m=7.2, cpu_load_factor=1.5, core_count=4 → threshold=6.0; 7.2 > 6.0
    let cpu_alert = alerts.iter().find(|a| a.rule == "cpu_overload");
    assert!(
        cpu_alert.is_some(),
        "Expected cpu_overload alert (load_avg_5m=7.2 > 4*1.5=6.0)"
    );

    // swap at 90% >= swap_critical (80%), so swap_warning (fires only when 50 <= x < 80) should NOT fire
    let swap_warning_alert = alerts.iter().find(|a| a.rule == "swap_warning");
    assert!(
        swap_warning_alert.is_none(),
        "swap_warning should NOT fire when swap is at 90% (above swap_critical threshold)"
    );

    // ram at 90%, between ram_warning (80%) and ram_critical (95%), so ram_warning fires
    let ram_warning_alert = alerts.iter().find(|a| a.rule == "ram_warning");
    assert!(
        ram_warning_alert.is_some(),
        "Expected ram_warning alert (RAM at 90%, between 80% and 95%)"
    );
}

#[test]
fn empty_snapshot_triggers_no_alerts() {
    let snapshot = make_base_snapshot();
    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);
    assert!(
        alerts.is_empty(),
        "Expected no alerts on empty/healthy snapshot, got: {alerts:?}"
    );
}

#[test]
fn disk_critical_threshold() {
    let mut snapshot = make_base_snapshot();
    snapshot.disks = vec![DiskInfo {
        mount_point: "/".to_string(),
        total_gb: 500.0,
        available_gb: 20.0,
        usage_percent: 96.0,
        filesystem: "ext4".to_string(),
    }];

    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    let disk_alert = alerts
        .iter()
        .find(|a| a.rule == "disk_space_low")
        .expect("Expected a disk_space_low alert for disk at 96% usage");
    assert_eq!(
        disk_alert.severity,
        Severity::Critical,
        "Disk at 96% should trigger Critical alert (threshold is 95%)"
    );
}

#[test]
fn zombie_processes_detected() {
    let mut snapshot = make_base_snapshot();
    snapshot.processes = vec![
        make_process(100, 50, "defunct_a", "defunct_a", ProcessState::Zombie),
        make_process(200, 75, "defunct_b", "defunct_b", ProcessState::Zombie),
        make_process(300, 90, "defunct_c", "defunct_c", ProcessState::Zombie),
    ];

    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    let zombie_alert = alerts
        .iter()
        .find(|a| a.rule == "zombie_processes")
        .expect("Expected a zombie_processes alert for 3 zombie processes");
    assert_eq!(
        zombie_alert.severity,
        Severity::Medium,
        "Zombie processes alert should be Medium severity"
    );

    assert!(
        zombie_alert
            .suggested_actions
            .iter()
            .any(|a| a.command.contains("SIGCHLD")),
        "Expected suggested actions with SIGCHLD commands for zombie parents"
    );
    assert_eq!(
        zombie_alert.suggested_actions.len(),
        3,
        "Expected 3 SIGCHLD actions for 3 different parent PIDs"
    );
}

#[test]
fn custom_thresholds_change_sensitivity() {
    let mut snapshot = make_base_snapshot();
    snapshot.memory.usage_percent = 70.0;
    snapshot.memory.used_mb = 11_469;
    snapshot.memory.available_mb = 4_915;

    let engine = RuleEngine::new(default_rules());

    let default_thresholds = ThresholdSet::default();
    let alerts_default = engine.analyze(&snapshot, &default_thresholds);
    let ram_alert_default = alerts_default.iter().find(|a| a.rule.contains("ram"));
    assert!(
        ram_alert_default.is_none(),
        "At 70% RAM, no RAM alert should fire with default thresholds (warning=80%)"
    );

    let custom_thresholds = ThresholdSet {
        ram_warning: 60.0,
        ..ThresholdSet::default()
    };
    let alerts_custom = engine.analyze(&snapshot, &custom_thresholds);
    let ram_warning_alert = alerts_custom
        .iter()
        .find(|a| a.rule == "ram_warning")
        .expect("Expected ram_warning alert with custom threshold of 60%");
    assert_eq!(ram_warning_alert.severity, Severity::High);
}

#[test]
fn multiple_rules_fire_simultaneously() {
    let mut snapshot = make_base_snapshot();

    // High RAM: 88%, between warning (80%) and critical (95%)
    snapshot.memory.usage_percent = 88.0;
    snapshot.memory.used_mb = 14_418;
    snapshot.memory.available_mb = 1_966;

    // Critical disk
    snapshot.disks = vec![DiskInfo {
        mount_point: "/data".to_string(),
        total_gb: 1000.0,
        available_gb: 30.0,
        usage_percent: 97.0,
        filesystem: "ext4".to_string(),
    }];

    // Zombie processes
    snapshot.processes = vec![
        make_process(500, 200, "zombie1", "zombie1", ProcessState::Zombie),
        make_process(501, 201, "zombie2", "zombie2", ProcessState::Zombie),
    ];

    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    let rule_names: Vec<&str> = alerts.iter().map(|a| a.rule.as_str()).collect();

    assert!(
        rule_names.contains(&"ram_warning"),
        "Expected ram_warning alert, got: {rule_names:?}"
    );
    assert!(
        rule_names.contains(&"disk_space_low"),
        "Expected disk_space_low alert, got: {rule_names:?}"
    );
    assert!(
        rule_names.contains(&"zombie_processes"),
        "Expected zombie_processes alert, got: {rule_names:?}"
    );
}

#[test]
fn alerts_sorted_by_severity() {
    let mut snapshot = make_base_snapshot();

    // Trigger Critical: disk at 97%
    snapshot.disks = vec![DiskInfo {
        mount_point: "/".to_string(),
        total_gb: 500.0,
        available_gb: 15.0,
        usage_percent: 97.0,
        filesystem: "ext4".to_string(),
    }];

    // Trigger High: RAM at 85% (between warning 80% and critical 95%)
    snapshot.memory.usage_percent = 85.0;
    snapshot.memory.used_mb = 13_926;
    snapshot.memory.available_mb = 2_458;

    // Trigger Medium: zombie processes
    snapshot.processes = vec![make_process(
        999,
        100,
        "zombie",
        "zombie",
        ProcessState::Zombie,
    )];

    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    assert!(
        alerts.len() >= 3,
        "Expected at least 3 alerts (Critical, High, Medium), got: {}",
        alerts.len()
    );

    for window in alerts.windows(2) {
        assert!(
            window[0].severity >= window[1].severity,
            "Alerts not sorted by severity descending: {:?} before {:?}",
            window[0].severity,
            window[1].severity
        );
    }

    assert_eq!(
        alerts[0].severity,
        Severity::Critical,
        "First alert should be Critical"
    );

    let has_medium = alerts.iter().any(|a| a.severity == Severity::Medium);
    assert!(has_medium, "Expected at least one Medium severity alert");

    let critical_count = alerts
        .iter()
        .filter(|a| a.severity == Severity::Critical)
        .count();
    let medium_idx = alerts
        .iter()
        .position(|a| a.severity == Severity::Medium)
        .expect("Expected a Medium alert");
    let high_idx = alerts.iter().position(|a| a.severity == Severity::High);

    if let Some(high_idx) = high_idx {
        assert!(
            high_idx < medium_idx,
            "High alerts should come before Medium alerts, got high_idx={high_idx}, medium_idx={medium_idx}"
        );
    }

    assert!(
        medium_idx >= critical_count,
        "Medium alerts should come after Critical alerts"
    );
}

#[test]
fn journal_oom_entries_trigger_oom_killer_rule() {
    let mut snapshot = make_base_snapshot();
    snapshot.journal_entries = vec![
        JournalEntry {
            timestamp: Utc::now(),
            priority: 3,
            unit: "kernel".to_string(),
            message: "Out of memory: Kill process 1234 (firefox) score 850 or sacrifice child"
                .to_string(),
        },
        JournalEntry {
            timestamp: Utc::now(),
            priority: 3,
            unit: "kernel".to_string(),
            message: "Killed process 1234 (firefox) total-vm:4000000kB, anon-rss:2000000kB"
                .to_string(),
        },
    ];

    let engine = RuleEngine::new(default_rules());
    let thresholds = ThresholdSet::default();
    let alerts = engine.analyze(&snapshot, &thresholds);

    let oom_alert = alerts
        .iter()
        .find(|a| a.rule == "oom_killer")
        .expect("Expected oom_killer alert when journal contains OOM entries");
    assert_eq!(oom_alert.severity, Severity::Critical);
}
