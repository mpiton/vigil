# Vigil — AI-Powered Linux System Guardian

## Vision

Vigil est un daemon Linux écrit en Rust qui surveille en continu les ressources système
(processus, RAM, CPU, GPU, disques, journaux), détecte les anomalies et propose des
corrections intelligentes via l'API Claude. Pensé pour les développeurs qui utilisent
des outils comme Claude Code, des MCP servers, et d'autres processus qui peuvent
dégénérer silencieusement.

---

## Architecture Haut Niveau

```
┌─────────────────────────────────────────────────────────────────┐
│                        VIGIL DAEMON                             │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Collectors   │  │   Analyzer   │  │   Action Engine       │  │
│  │              │  │              │  │                       │  │
│  │ • procfs     │──▶│ • Rules      │──▶│ • Desktop Notify     │  │
│  │ • sysinfo    │  │ • Anomaly    │  │ • Terminal Alert      │  │
│  │ • journald   │  │ • Trends     │  │ • Auto-remediation    │  │
│  │ • GPU (nvml) │  │ • AI (Claude)│  │ • Log & Report        │  │
│  │ • disk stats  │  │              │  │                       │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│         │                 │                      │               │
│         ▼                 ▼                      ▼               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    State Store (SQLite)                   │   │
│  │  • Snapshots historiques   • Alertes émises               │   │
│  │  • Baselines apprises      • Actions exécutées            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    CLI Interface                          │   │
│  │  vigil status | vigil report | vigil kill <pid>          │   │
│  │  vigil watch  | vigil config | vigil explain <pid>       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Modules Détaillés

### 1. Collectors (`src/collectors/`)

Chaque collector implémente le trait `Collector` et fournit des snapshots à intervalle régulier.

| Collector | Source | Données |
|-----------|--------|---------|
| `ProcessCollector` | `/proc/[pid]/*` | PID, nom, cmdline, CPU%, RSS, état, parent, durée, open FDs |
| `MemoryCollector` | `/proc/meminfo` + sysinfo | RAM totale/utilisée/cache, swap, pression mémoire |
| `CpuCollector` | `/proc/stat` + sysinfo | Usage par cœur, load average, fréquence, température |
| `GpuCollector` | NVML / sysfs | VRAM, utilisation GPU, température, processus GPU |
| `DiskCollector` | `/proc/diskstats` + statvfs | I/O rates, espace libre, inodes, latence |
| `JournalCollector` | `journald` (sd-journal) | Entrées récentes filtrées (priority ≤ warning) |
| `NetworkCollector` | `/proc/net/dev` | Bandwidth par interface, connexions ouvertes |

### 2. Analyzer (`src/analyzer/`)

Deux niveaux d'analyse qui fonctionnent en pipeline :

#### Niveau 1 — Règles Déterministes (rapide, local, gratuit)
```
- RAM utilisée > 85% pendant > 30s        → ALERTE haute
- Processus zombie (état Z) > 5 min       → ALERTE moyenne
- Processus orphelin avec CPU > 0          → ALERTE moyenne
- Même cmdline × N instances (N > seuil)  → ALERTE (cas MCP/Python)
- Swap usage > 50%                         → ALERTE haute
- Disque < 5% espace libre                → ALERTE critique
- OOM killer dans journald                 → ALERTE critique
- Load average > 2× nb_cores pendant 5min → ALERTE haute
- Température CPU/GPU > seuil              → ALERTE haute
- Processus avec memory leak (RSS croissant monotone sur fenêtre) → ALERTE
```

#### Niveau 2 — Analyse IA (Claude API, optionnel)
Activé uniquement quand le Niveau 1 détecte une anomalie, pour :
- Comprendre le contexte (pourquoi ces processus existent)
- Proposer des actions de remédiation explicites
- Prioriser les actions si multiples problèmes
- Expliquer en langage naturel ce qui se passe

**Prompt pattern envoyé à Claude :**
```
Système: Tu es un expert Linux sysadmin. Analyse cette situation et propose des actions.

Contexte système :
- RAM: {used}/{total} ({percent}%), swap: {swap_used}/{swap_total}
- CPU load: {load_1m}/{load_5m}/{load_15m} ({n_cores} cores)
- Top processus par RAM: [liste]
- Top processus par CPU: [liste]
- Processus suspects détectés: [liste avec raison]
- Dernières entrées journald anormales: [liste]

Réponds en JSON structuré :
{
  "diagnostic": "explication claire du problème",
  "severity": "critical|high|medium|low",
  "actions": [
    {
      "type": "kill_process|restart_service|free_cache|custom",
      "target": "pid ou service",
      "command": "commande exacte",
      "risk": "safe|moderate|dangerous",
      "explanation": "pourquoi cette action"
    }
  ],
  "prevention": "conseil pour éviter ce problème à l'avenir"
}
```

### 3. Action Engine (`src/actions/`)

Trois modes d'opération configurables :

| Mode | Comportement |
|------|-------------|
| `observe` | Notifie seulement (défaut) |
| `suggest` | Notifie + propose des commandes à copier/coller |
| `auto` | Exécute automatiquement les actions "safe" |

**Canaux de notification :**
- `notify-send` (desktop notifications)
- Terminal (ANSI coloré dans stdout)
- Fichier log structuré (JSON)
- Webhook optionnel (Slack, Discord, etc.)

### 4. State Store (`src/store/`)

SQLite embarqué via `rusqlite` pour :
- Historique des snapshots (rolling window de 24h)
- Baseline apprise (moyennes/écarts-types par heure du jour)
- Historique des alertes et actions
- Configuration des seuils personnalisés

### 5. CLI (`src/cli/`)

```bash
vigil                      # Lance le daemon (mode observe par défaut)
vigil status               # Snapshot instantané du système
vigil report               # Rapport détaillé des dernières 24h
vigil watch                # Mode interactif (comme htop + IA)
vigil explain <pid>        # Demande à l'IA d'expliquer un processus
vigil kill <pid> [--force] # Kill avec confirmation et logging
vigil config               # Éditer la configuration
vigil health               # Self-check du daemon
```

---

## Stack Technique

| Composant | Crate | Justification |
|-----------|-------|---------------|
| Async runtime | `tokio` | Standard pour daemon async |
| System info | `sysinfo` | Cross-platform, API propre |
| Proc filesystem | `procfs` | Accès détaillé Linux /proc |
| Journal | `systemd-journal-logger` ou `journal-reader` | Lecture journald native |
| GPU NVIDIA | `nvml-wrapper` | Bindings NVML safe |
| CLI | `clap` | Standard, derive macros |
| Config | `serde` + `toml` | Fichier config lisible |
| DB | `rusqlite` | Embedded, zero setup |
| HTTP client | `reqwest` | Pour API Claude |
| Notifications | `notify-rust` | Desktop notifications Linux |
| Logging | `tracing` + `tracing-subscriber` | Structured logging |
| Errors | `anyhow` + `thiserror` | Per tes best practices |
| TUI (optionnel) | `ratatui` | Pour mode `vigil watch` |

---

## Configuration (`~/.config/vigil/config.toml`)

```toml
[general]
mode = "suggest"           # observe | suggest | auto
interval_secs = 5          # fréquence de collecte
language = "fr"            # langue des notifications

[thresholds]
ram_warn_percent = 80
ram_critical_percent = 90
swap_warn_percent = 40
cpu_load_factor = 2.0      # alerte si load > factor × n_cores
disk_min_free_percent = 10
max_duplicate_processes = 5
zombie_timeout_secs = 300
temperature_cpu_max = 85
temperature_gpu_max = 80

[ai]
enabled = true
provider = "anthropic"
model = "claude-sonnet-4-20250514"
api_key_env = "ANTHROPIC_API_KEY"  # lire depuis env var
max_tokens = 1024
cooldown_secs = 60         # min entre 2 appels IA

[notifications]
desktop = true
terminal = true
log_file = "~/.local/share/vigil/vigil.log"
# webhook_url = "https://hooks.slack.com/..."

[allowlist]
# Processus à ne jamais signaler
ignore_commands = ["Xorg", "systemd", "dbus-daemon"]
# Processus à ne jamais tuer automatiquement
protected_pids = [1]
protected_commands = ["sshd", "systemd", "dbus*"]

[history]
retention_hours = 168      # 7 jours
snapshot_interval_secs = 60
```

---

## Détection Spécifique : Cas "MCP Python Zombies"

Le scénario exact de Mathieu est couvert par cette règle composite :

```
RULE: ghost_process_storm
TRIGGERS WHEN:
  1. N processus avec la même cmdline (ex: "python3 mcp_server.py")
     ET N > max_duplicate_processes (défaut: 5)
  2. OU processus orphelins (ppid=1 ou ppid=reaper) dont le parent
     original était "claude-code" ou "node" (détecté via cmdline/cgroup)
  3. ET ces processus consomment collectivement > X% RAM

ACTION:
  - Notifier: "⚠️ {N} processus Python identiques détectés ({total_ram}MB).
    Probablement des MCP servers non terminés par Claude Code."
  - Proposer: kill groupé par PGID ou pattern cmdline
  - Commande suggérée: `kill $(pgrep -f "mcp_server.py")`
```

---

## Plan de Développement (Sprints)

### Sprint 1 — Foundation (Semaine 1-2)
- [ ] Scaffolding projet Cargo workspace
- [ ] Collectors : Process, Memory, CPU
- [ ] Règles déterministes de base (RAM, CPU, zombies)
- [ ] CLI basique (`vigil status`)
- [ ] Notifications terminal

### Sprint 2 — Intelligence (Semaine 3-4)
- [ ] Intégration API Claude
- [ ] Collector journald
- [ ] Détection processus dupliqués (cas MCP)
- [ ] Desktop notifications
- [ ] Configuration TOML

### Sprint 3 — Persistence & History (Semaine 5-6)
- [ ] SQLite state store
- [ ] Baseline learning
- [ ] `vigil report` avec historique
- [ ] Collector Disk + GPU

### Sprint 4 — UX Polish (Semaine 7-8)
- [ ] Mode `vigil watch` (TUI ratatui)
- [ ] `vigil explain <pid>`
- [ ] Mode auto-remediation (safe actions)
- [ ] Webhook notifications
- [ ] Tests d'intégration + packaging

---

## Sécurité & Considérations

- **Principe du moindre privilège** : tourne en userspace, pas root (sauf pour kill de processus d'autres users)
- **API key** : jamais en clair dans la config, toujours via env var ou keyring
- **Mode auto** : uniquement pour les actions classées "safe" (kill de ses propres processus)
- **Rate limiting IA** : cooldown configurable pour éviter les coûts API
- **Pas de telemetry** : 100% local, sauf les appels Claude opt-in
