# Vigil — Clean Architecture Structure

## Principles

```
┌─────────────────────────────────────────────────────────┐
│                    Presentation                         │
│                  (CLI, TUI, API)                        │
│    ┌───────────────────────────────────────────────┐    │
│    │              Application                      │    │
│    │          (Use Cases, Services)                 │    │
│    │    ┌─────────────────────────────────────┐    │    │
│    │    │            Domain                    │    │    │
│    │    │    (Entities, Traits, Rules)          │    │    │
│    │    │       ⟵ NO dependencies ⟶           │    │    │
│    │    └─────────────────────────────────────┘    │    │
│    └───────────────────────────────────────────────┘    │
│                    Infrastructure                       │
│        (OS, DB, external API, Notifications)            │
└─────────────────────────────────────────────────────────┘

Golden rule: dependencies point inward.
The Domain knows NOTHING about outer layers.
```

## Structure

```
vigil/
├── Cargo.toml
├── README.md
├── ARCHITECTURE.md
├── config.default.toml              # Documented reference config
│
├── src/
│   ├── main.rs                      # Entry point, DI wiring, bootstrap
│   ├── lib.rs                       # Public re-exports for tests/lib usage
│   │
│   ├── domain/                      # 🟢 CORE — Zero external dependencies
│   │   ├── mod.rs
│   │   │
│   │   ├── entities/                # Business data structures
│   │   │   ├── mod.rs
│   │   │   ├── snapshot.rs          # SystemSnapshot, MemoryInfo, CpuInfo
│   │   │   ├── process.rs           # ProcessInfo, ProcessState
│   │   │   ├── disk.rs              # DiskInfo
│   │   │   ├── journal.rs           # JournalEntry
│   │   │   └── alert.rs             # Alert, Severity, SuggestedAction
│   │   │
│   │   ├── rules/                   # Detection rules (pure logic)
│   │   │   ├── mod.rs               # Trait Rule + RuleEngine
│   │   │   ├── ram.rs               # RamWarningRule, RamCriticalRule
│   │   │   ├── cpu.rs               # CpuOverloadRule
│   │   │   ├── swap.rs              # SwapWarningRule
│   │   │   ├── disk.rs              # DiskSpaceRule
│   │   │   ├── zombie.rs            # ZombieProcessRule
│   │   │   ├── duplicates.rs        # DuplicateProcessRule (MCP case)
│   │   │   ├── orphans.rs           # OrphanDevProcessRule
│   │   │   └── oom.rs               # OomKillerRule
│   │   │
│   │   ├── ports/                   # Traits (interfaces) — contracts
│   │   │   ├── mod.rs
│   │   │   ├── collector.rs         # trait SystemCollector
│   │   │   ├── analyzer.rs          # trait AiAnalyzer
│   │   │   ├── notifier.rs          # trait Notifier
│   │   │   ├── store.rs             # trait AlertStore, SnapshotStore
│   │   │   └── process_manager.rs   # trait ProcessManager (kill, signal)
│   │   │
│   │   └── value_objects/           # Immutable value types
│   │       ├── mod.rs
│   │       ├── severity.rs          # Severity (Low..Critical)
│   │       ├── action_risk.rs       # ActionRisk (Safe, Moderate, Dangerous)
│   │       ├── thresholds.rs        # ThresholdSet (typed thresholds)
│   │       └── operation_mode.rs    # OperationMode (Observe, Suggest, Auto)
│   │
│   ├── application/                 # 🔵 ORCHESTRATION — Use cases
│   │   ├── mod.rs
│   │   │
│   │   ├── services/                # Application services
│   │   │   ├── mod.rs
│   │   │   ├── monitor.rs           # MonitorService — collect→analyze→notify loop
│   │   │   ├── scanner.rs           # ScanService — one-shot scan
│   │   │   ├── explainer.rs         # ExplainService — explain a PID via AI
│   │   │   └── killer.rs            # KillService — kill with logging and confirmation
│   │   │
│   │   ├── dto/                     # Data Transfer Objects (between layers)
│   │   │   ├── mod.rs
│   │   │   ├── scan_result.rs       # ScanResult (snapshot + alerts + ai_diagnostic)
│   │   │   ├── status_report.rs     # StatusReport (for display)
│   │   │   └── ai_request.rs        # AiAnalysisRequest, AiDiagnostic
│   │   │
│   │   └── config.rs               # AppConfig (validation, defaults, loading)
│   │
│   ├── infrastructure/              # 🟠 EXTERNAL ADAPTERS
│   │   ├── mod.rs
│   │   │
│   │   ├── collectors/              # Implementations of SystemCollector
│   │   │   ├── mod.rs
│   │   │   ├── sysinfo_collector.rs # Via sysinfo crate (RAM, CPU, processes)
│   │   │   ├── procfs_collector.rs  # Via /proc for detailed data
│   │   │   ├── disk_collector.rs    # Disk space via statvfs
│   │   │   ├── journal_collector.rs # journald reading via journalctl
│   │   │   ├── gpu_collector.rs     # NVIDIA via nvml-wrapper (optional)
│   │   │   └── composite.rs         # CompositeCollector (aggregates all)
│   │   │
│   │   ├── ai/                      # Implementations of AiAnalyzer
│   │   │   ├── mod.rs
│   │   │   ├── claude.rs            # ClaudeAnalyzer (Anthropic API)
│   │   │   ├── prompt_builder.rs    # Prompt construction
│   │   │   └── noop.rs              # NoopAnalyzer (when AI disabled)
│   │   │
│   │   ├── notifications/           # Implementations of Notifier
│   │   │   ├── mod.rs
│   │   │   ├── terminal.rs          # Colored terminal output (ANSI)
│   │   │   ├── desktop.rs           # notify-rust (freedesktop)
│   │   │   ├── log_file.rs          # JSON append to file
│   │   │   ├── webhook.rs           # HTTP POST (Slack, Discord)
│   │   │   └── composite.rs         # CompositeNotifier (fan-out)
│   │   │
│   │   ├── persistence/             # Implementations of Store
│   │   │   ├── mod.rs
│   │   │   ├── sqlite_store.rs      # SQLite via rusqlite
│   │   │   ├── migrations.rs        # Schema and DB migrations
│   │   │   └── in_memory_store.rs   # For testing
│   │   │
│   │   └── os/                      # System interactions
│   │       ├── mod.rs
│   │       ├── process_manager.rs   # Kill/signal via nix
│   │       └── system_info.rs       # OS helpers (uptime, hostname, etc.)
│   │
│   └── presentation/                # 🟣 USER INTERFACES
│       ├── mod.rs
│       │
│       ├── cli/                     # Command-line interface
│       │   ├── mod.rs
│       │   ├── app.rs               # clap definition (Cli, Commands)
│       │   ├── commands/
│       │   │   ├── mod.rs
│       │   │   ├── daemon.rs        # vigil (daemon)
│       │   │   ├── status.rs        # vigil status
│       │   │   ├── scan.rs          # vigil scan [--ai]
│       │   │   ├── explain.rs       # vigil explain <pid>
│       │   │   ├── kill.rs          # vigil kill <pid>
│       │   │   └── config.rs        # vigil config [--edit]
│       │   └── formatters/
│       │       ├── mod.rs
│       │       ├── status_fmt.rs    # Status formatting (bars, colors)
│       │       ├── alert_fmt.rs     # Alert formatting
│       │       └── table_fmt.rs     # Table formatting
│       │
│       └── tui/                     # Interactive terminal interface (future)
│           ├── mod.rs
│           ├── app.rs               # State and ratatui loop
│           ├── widgets/
│           │   ├── mod.rs
│           │   ├── dashboard.rs     # Main view
│           │   ├── process_list.rs  # Process list
│           │   └── alert_panel.rs   # Alert panel
│           └── event.rs             # Keyboard event handling
│
└── tests/
    ├── integration/
    │   ├── scan_test.rs             # End-to-end scan test
    │   ├── rules_test.rs            # Rule tests with mocked snapshots
    │   └── ai_test.rs               # AI integration test (with HTTP mock)
    │
    └── fixtures/
        ├── snapshot_normal.json     # Healthy system snapshot
        ├── snapshot_ram_critical.json
        ├── snapshot_mcp_zombies.json # MCP Python in loop case
        └── snapshot_oom.json
```

## Responsibilities per Layer

### 🟢 Domain — The Pure Core

**Zero external `use`** (no tokio, sysinfo, reqwest, etc.).
Only `std`, `serde` (for Serialize/Deserialize derive), `chrono`, `thiserror`.

```rust
// domain/ports/collector.rs
use crate::domain::entities::snapshot::SystemSnapshot;

pub trait SystemCollector: Send + Sync {
    fn collect(&mut self) -> Result<SystemSnapshot, CollectionError>;
}

// domain/ports/analyzer.rs
use crate::domain::entities::{alert::Alert, snapshot::SystemSnapshot};
use crate::application::dto::ai_request::AiDiagnostic;

#[async_trait::async_trait]
pub trait AiAnalyzer: Send + Sync {
    async fn analyze(
        &mut self,
        snapshot: &SystemSnapshot,
        alerts: &[Alert],
    ) -> Result<Option<AiDiagnostic>, AnalysisError>;
}

// domain/ports/notifier.rs
use crate::domain::entities::alert::Alert;

pub trait Notifier: Send + Sync {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError>;
}

// domain/ports/store.rs
use crate::domain::entities::{alert::Alert, snapshot::SystemSnapshot};

pub trait AlertStore: Send + Sync {
    fn save_alert(&self, alert: &Alert) -> Result<(), StoreError>;
    fn recent_alerts(&self, limit: usize) -> Result<Vec<Alert>, StoreError>;
}

pub trait SnapshotStore: Send + Sync {
    fn save_snapshot(&self, snapshot: &SystemSnapshot) -> Result<(), StoreError>;
}
```

```rust
// domain/rules/mod.rs — Each rule is a pure function
use crate::domain::entities::{alert::Alert, snapshot::SystemSnapshot};
use crate::domain::value_objects::thresholds::ThresholdSet;

pub trait Rule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert>;
}

pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }

    pub fn analyze(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.rules
            .iter()
            .flat_map(|rule| rule.evaluate(snapshot, thresholds))
            .collect();
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
        alerts
    }
}
```

```rust
// domain/rules/duplicates.rs — Example of pure rule
pub struct DuplicateProcessRule;

impl Rule for DuplicateProcessRule {
    fn name(&self) -> &str { "duplicate_processes" }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        // Pure logic: group, count, alert
        // No system access, no I/O
    }
}
```

### 🔵 Application — Orchestration

Depends on Domain (traits + entities). Does NOT know concrete implementations.
Receives dependencies via injection (constructor).

```rust
// application/services/monitor.rs
pub struct MonitorService<C, A, N, S>
where
    C: SystemCollector,
    A: AiAnalyzer,
    N: Notifier,
    S: AlertStore,
{
    collector: C,
    ai: A,
    notifier: N,
    store: S,
    rule_engine: RuleEngine,
    config: AppConfig,
}

impl<C, A, N, S> MonitorService<C, A, N, S>
where
    C: SystemCollector,
    A: AiAnalyzer,
    N: Notifier,
    S: AlertStore,
{
    pub async fn tick(&mut self) -> Result<()> {
        let snapshot = self.collector.collect()?;
        let alerts = self.rule_engine.analyze(&snapshot, &self.config.thresholds);

        for alert in &alerts {
            self.notifier.notify(alert)?;
            self.store.save_alert(alert)?;
        }

        if self.should_invoke_ai(&alerts) {
            if let Some(diagnostic) = self.ai.analyze(&snapshot, &alerts).await? {
                self.handle_ai_diagnostic(&diagnostic)?;
            }
        }

        Ok(())
    }
}
```

### 🟠 Infrastructure — The Real World

Implements Domain traits. Contains ALL external dependencies.

```rust
// infrastructure/collectors/sysinfo_collector.rs
use sysinfo::System;
use crate::domain::ports::collector::SystemCollector;

pub struct SysinfoCollector {
    sys: System,
}

impl SystemCollector for SysinfoCollector {
    fn collect(&mut self) -> Result<SystemSnapshot, CollectionError> {
        self.sys.refresh_all();
        // ... conversion sysinfo → domain entities
    }
}

// infrastructure/ai/claude.rs
use reqwest::Client;
use crate::domain::ports::analyzer::AiAnalyzer;

pub struct ClaudeAnalyzer {
    client: Client,
    model: String,
    api_key: String,
}

#[async_trait::async_trait]
impl AiAnalyzer for ClaudeAnalyzer {
    async fn analyze(&mut self, snapshot: &SystemSnapshot, alerts: &[Alert])
        -> Result<Option<AiDiagnostic>, AnalysisError>
    {
        // HTTP call to Anthropic API
    }
}

// infrastructure/ai/noop.rs
pub struct NoopAnalyzer;

#[async_trait::async_trait]
impl AiAnalyzer for NoopAnalyzer {
    async fn analyze(&mut self, _: &SystemSnapshot, _: &[Alert])
        -> Result<Option<AiDiagnostic>, AnalysisError>
    {
        Ok(None) // AI disabled
    }
}
```

### 🟣 Presentation — User Interface

Depends on Application (services, DTOs). Converts DTOs to display.

```rust
// presentation/cli/commands/scan.rs
pub async fn execute(service: &mut ScanService<...>, args: &ScanArgs) -> Result<()> {
    let result = service.run(args.use_ai).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        AlertFormatter::print_alerts(&result.alerts);
        if let Some(diag) = &result.ai_diagnostic {
            AiFormatter::print_diagnostic(diag);
        }
    }

    Ok(())
}
```

### main.rs — The Wiring (Composition Root)

```rust
// main.rs — Only place that knows ALL concrete implementations
#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load()?;

    // Manual dependency injection (no DI framework needed in Rust)
    let collector = SysinfoCollector::new();
    let notifier = CompositeNotifier::from_config(&config.notifications);
    let store = SqliteStore::open(&config.database_path)?;

    let ai: Box<dyn AiAnalyzer> = if config.ai.enabled {
        Box::new(ClaudeAnalyzer::new(&config.ai)?)
    } else {
        Box::new(NoopAnalyzer)
    };

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(RamCriticalRule),
        Box::new(RamWarningRule),
        Box::new(SwapWarningRule),
        Box::new(CpuOverloadRule),
        Box::new(ZombieProcessRule),
        Box::new(DuplicateProcessRule),
        Box::new(OrphanDevProcessRule),
        Box::new(DiskSpaceRule),
        Box::new(OomKillerRule),
    ];
    let rule_engine = RuleEngine::new(rules);

    // Dispatch CLI command → service
    match cli.command {
        Commands::Daemon { .. } => {
            let mut service = MonitorService::new(
                collector, ai, notifier, store, rule_engine, config
            );
            service.run_loop().await
        }
        Commands::Scan { ai, json } => { /* ... */ }
        // ...
    }
}
```

## Dependency Flow

```
main.rs (composition root)
   │
   ├── presentation/cli ──→ application/services ──→ domain/ports (traits)
   │                                                      ↑
   └── infrastructure/* ──────────────────────────────────┘
                         (implements traits)
```

**Never:**
- ❌ domain → infrastructure
- ❌ domain → presentation
- ❌ application → infrastructure (directly)
- ❌ presentation → infrastructure (directly)

**Always:**
- ✅ infrastructure → domain (implements ports)
- ✅ application → domain (uses ports/entities)
- ✅ presentation → application (calls services)
- ✅ main.rs → everything (unique wiring)

## Testability

Thanks to traits, each layer tests independently:

```
tests/
├── integration/           # End-to-end tests with real components
├── fixtures/              # JSON snapshots to feed tests
```

```rust
// Unit test of a rule (pure logic, no mock)
#[test]
fn duplicate_rule_detects_mcp_storm() {
    let snapshot = load_fixture("snapshot_mcp_zombies.json");
    let thresholds = ThresholdSet::default();
    let rule = DuplicateProcessRule;

    let alerts = rule.evaluate(&snapshot, &thresholds);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::High);
    assert!(alerts[0].title.contains("python"));
}

// Test of a service with mocks
#[tokio::test]
async fn monitor_notifies_on_critical_ram() {
    let collector = MockCollector::with_snapshot(critical_ram_snapshot());
    let notifier = MockNotifier::new();
    let store = InMemoryStore::new();
    let ai = NoopAnalyzer;

    let mut service = MonitorService::new(collector, ai, notifier.clone(), store, ...);
    service.tick().await.unwrap();

    assert_eq!(notifier.alerts_sent(), 1);
}
```
