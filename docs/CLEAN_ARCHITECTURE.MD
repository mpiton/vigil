# Vigil — Clean Architecture Structure

## Principes

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
│    │    │       ⟵ AUCUNE dépendance ⟶         │    │    │
│    │    └─────────────────────────────────────┘    │    │
│    └───────────────────────────────────────────────┘    │
│                    Infrastructure                       │
│        (OS, DB, API externe, Notifications)             │
└─────────────────────────────────────────────────────────┘

Règle d'or : les dépendances pointent vers l'intérieur.
Le Domain ne connaît RIEN des couches extérieures.
```

## Structure

```
vigil/
├── Cargo.toml
├── README.md
├── ARCHITECTURE.md
├── config.default.toml              # Config de référence documentée
│
├── src/
│   ├── main.rs                      # Point d'entrée, wiring DI, bootstrap
│   ├── lib.rs                       # Re-exports publics pour tests/lib usage
│   │
│   ├── domain/                      # 🟢 CŒUR — Zéro dépendance externe
│   │   ├── mod.rs
│   │   │
│   │   ├── entities/                # Structures de données métier
│   │   │   ├── mod.rs
│   │   │   ├── snapshot.rs          # SystemSnapshot, MemoryInfo, CpuInfo
│   │   │   ├── process.rs           # ProcessInfo, ProcessState
│   │   │   ├── disk.rs              # DiskInfo
│   │   │   ├── journal.rs           # JournalEntry
│   │   │   └── alert.rs             # Alert, Severity, SuggestedAction
│   │   │
│   │   ├── rules/                   # Règles de détection (logique pure)
│   │   │   ├── mod.rs               # Trait Rule + RuleEngine
│   │   │   ├── ram.rs               # RamWarningRule, RamCriticalRule
│   │   │   ├── cpu.rs               # CpuOverloadRule
│   │   │   ├── swap.rs              # SwapWarningRule
│   │   │   ├── disk.rs              # DiskSpaceRule
│   │   │   ├── zombie.rs            # ZombieProcessRule
│   │   │   ├── duplicates.rs        # DuplicateProcessRule (cas MCP)
│   │   │   ├── orphans.rs           # OrphanDevProcessRule
│   │   │   └── oom.rs               # OomKillerRule
│   │   │
│   │   ├── ports/                   # Traits (interfaces) — contrats
│   │   │   ├── mod.rs
│   │   │   ├── collector.rs         # trait SystemCollector
│   │   │   ├── analyzer.rs          # trait AiAnalyzer
│   │   │   ├── notifier.rs          # trait Notifier
│   │   │   ├── store.rs             # trait AlertStore, SnapshotStore
│   │   │   └── process_manager.rs   # trait ProcessManager (kill, signal)
│   │   │
│   │   └── value_objects/           # Types valeur immuables
│   │       ├── mod.rs
│   │       ├── severity.rs          # Severity (Low..Critical)
│   │       ├── action_risk.rs       # ActionRisk (Safe, Moderate, Dangerous)
│   │       ├── thresholds.rs        # ThresholdSet (seuils typés)
│   │       └── operation_mode.rs    # OperationMode (Observe, Suggest, Auto)
│   │
│   ├── application/                 # 🔵 ORCHESTRATION — Use cases
│   │   ├── mod.rs
│   │   │
│   │   ├── services/                # Services applicatifs
│   │   │   ├── mod.rs
│   │   │   ├── monitor.rs           # MonitorService — boucle collect→analyze→notify
│   │   │   ├── scanner.rs           # ScanService — one-shot scan
│   │   │   ├── explainer.rs         # ExplainService — explain un PID via IA
│   │   │   └── killer.rs            # KillService — kill avec log et confirmation
│   │   │
│   │   ├── dto/                     # Data Transfer Objects (entre couches)
│   │   │   ├── mod.rs
│   │   │   ├── scan_result.rs       # ScanResult (snapshot + alerts + ai_diagnostic)
│   │   │   ├── status_report.rs     # StatusReport (pour affichage)
│   │   │   └── ai_request.rs        # AiAnalysisRequest, AiDiagnostic
│   │   │
│   │   └── config.rs               # AppConfig (validation, defaults, chargement)
│   │
│   ├── infrastructure/              # 🟠 ADAPTATEURS EXTERNES
│   │   ├── mod.rs
│   │   │
│   │   ├── collectors/              # Implémentations de SystemCollector
│   │   │   ├── mod.rs
│   │   │   ├── sysinfo_collector.rs # Via crate sysinfo (RAM, CPU, processus)
│   │   │   ├── procfs_collector.rs  # Via /proc pour données détaillées
│   │   │   ├── disk_collector.rs    # Espace disque via statvfs
│   │   │   ├── journal_collector.rs # Lecture journald via journalctl
│   │   │   ├── gpu_collector.rs     # NVIDIA via nvml-wrapper (optionnel)
│   │   │   └── composite.rs         # CompositeCollector (agrège tous les collectors)
│   │   │
│   │   ├── ai/                      # Implémentations de AiAnalyzer
│   │   │   ├── mod.rs
│   │   │   ├── claude.rs            # ClaudeAnalyzer (API Anthropic)
│   │   │   ├── prompt_builder.rs    # Construction des prompts
│   │   │   └── noop.rs              # NoopAnalyzer (quand IA désactivée)
│   │   │
│   │   ├── notifications/           # Implémentations de Notifier
│   │   │   ├── mod.rs
│   │   │   ├── terminal.rs          # Sortie terminal colorée (ANSI)
│   │   │   ├── desktop.rs           # notify-rust (freedesktop)
│   │   │   ├── log_file.rs          # JSON append dans fichier
│   │   │   ├── webhook.rs           # HTTP POST (Slack, Discord)
│   │   │   └── composite.rs         # CompositeNotifier (fan-out)
│   │   │
│   │   ├── persistence/             # Implémentations de Store
│   │   │   ├── mod.rs
│   │   │   ├── sqlite_store.rs      # SQLite via rusqlite
│   │   │   ├── migrations.rs        # Schéma et migrations DB
│   │   │   └── in_memory_store.rs   # Pour tests
│   │   │
│   │   └── os/                      # Interactions système
│   │       ├── mod.rs
│   │       ├── process_manager.rs   # Kill/signal via nix
│   │       └── system_info.rs       # Helpers OS (uptime, hostname, etc.)
│   │
│   └── presentation/                # 🟣 INTERFACES UTILISATEUR
│       ├── mod.rs
│       │
│       ├── cli/                     # Interface ligne de commande
│       │   ├── mod.rs
│       │   ├── app.rs               # Définition clap (Cli, Commands)
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
│       │       ├── status_fmt.rs    # Formatage du status (barres, couleurs)
│       │       ├── alert_fmt.rs     # Formatage des alertes
│       │       └── table_fmt.rs     # Formatage en tableaux
│       │
│       └── tui/                     # Interface terminal interactive (futur)
│           ├── mod.rs
│           ├── app.rs               # État et boucle ratatui
│           ├── widgets/
│           │   ├── mod.rs
│           │   ├── dashboard.rs     # Vue principale
│           │   ├── process_list.rs  # Liste de processus
│           │   └── alert_panel.rs   # Panneau d'alertes
│           └── event.rs             # Gestion des événements clavier
│
└── tests/
    ├── integration/
    │   ├── scan_test.rs             # Test scan end-to-end
    │   ├── rules_test.rs            # Test des règles avec snapshots mockés
    │   └── ai_test.rs               # Test intégration IA (avec mock HTTP)
    │
    └── fixtures/
        ├── snapshot_normal.json     # Snapshot système sain
        ├── snapshot_ram_critical.json
        ├── snapshot_mcp_zombies.json # Cas MCP Python en boucle
        └── snapshot_oom.json
```

## Responsabilités par couche

### 🟢 Domain — Le cœur pur

**Zéro `use` externe** (pas de tokio, sysinfo, reqwest, etc.).
Uniquement `std`, `serde` (pour dériver Serialize/Deserialize), `chrono`, `thiserror`.

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
// domain/rules/mod.rs — Chaque règle est une fonction pure
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
// domain/rules/duplicates.rs — Exemple de règle pure
pub struct DuplicateProcessRule;

impl Rule for DuplicateProcessRule {
    fn name(&self) -> &str { "duplicate_processes" }

    fn evaluate(&self, snapshot: &SystemSnapshot, thresholds: &ThresholdSet) -> Vec<Alert> {
        // Logique pure : grouper, compter, alerter
        // Aucun accès système, aucun I/O
    }
}
```

### 🔵 Application — Orchestration

Dépend du Domain (traits + entities). Ne connaît PAS les implémentations concrètes.
Reçoit les dépendances par injection (constructeur).

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

### 🟠 Infrastructure — Le monde réel

Implémente les traits du Domain. Contient TOUTES les dépendances externes.

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
        Ok(None) // IA désactivée
    }
}
```

### 🟣 Presentation — Interface utilisateur

Dépend de Application (services, DTOs). Convertit les DTOs en affichage.

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

### main.rs — Le câblage (Composition Root)

```rust
// main.rs — Seul endroit qui connaît TOUTES les implémentations concrètes
#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load()?;

    // Injection de dépendances manuelle (pas besoin de framework DI en Rust)
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

## Flux de dépendances

```
main.rs (composition root)
   │
   ├── presentation/cli ──→ application/services ──→ domain/ports (traits)
   │                                                      ↑
   └── infrastructure/* ──────────────────────────────────┘
                         (implémente les traits)
```

**Jamais** :
- ❌ domain → infrastructure
- ❌ domain → presentation
- ❌ application → infrastructure (directement)
- ❌ presentation → infrastructure (directement)

**Toujours** :
- ✅ infrastructure → domain (implémente les ports)
- ✅ application → domain (utilise les ports/entities)
- ✅ presentation → application (appelle les services)
- ✅ main.rs → tout (câblage unique)

## Testabilité

Grâce aux traits, chaque couche se teste indépendamment :

```
tests/
├── integration/           # Tests end-to-end avec vrais composants
├── fixtures/              # Snapshots JSON pour alimenter les tests
```

```rust
// Test unitaire d'une règle (logique pure, pas de mock)
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

// Test d'un service avec mocks
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
