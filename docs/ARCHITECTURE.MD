# Vigil — AI-Powered Linux System Guardian

## Vision

Vigil is a Linux daemon written in Rust that continuously monitors system resources
(processes, RAM, CPU, GPU, disks, logs), detects anomalies and proposes
intelligent corrections via the Claude API. Designed for developers who use
tools like Claude Code, MCP servers, and other processes that can degrade silently.

---

## High-Level Architecture

```text
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
│  │  • Historical snapshots    • Alerts issued                │   │
│  │  • Learned baselines       • Actions executed             │   │
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

## Detailed Modules

### 1. Collectors (`src/collectors/`)

Each collector implements the `Collector` trait and provides snapshots at regular intervals.

| Collector | Source | Data |
|-----------|--------|------|
| `ProcessCollector` | `/proc/[pid]/*` | PID, name, cmdline, CPU%, RSS, state, parent, duration, open FDs |
| `MemoryCollector` | `/proc/meminfo` + sysinfo | Total/used/cached RAM, swap, memory pressure |
| `CpuCollector` | `/proc/stat` + sysinfo | Usage per core, load average, frequency, temperature |
| `GpuCollector` | NVML / sysfs | VRAM, GPU utilization, temperature, GPU processes |
| `DiskCollector` | `/proc/diskstats` + statvfs | I/O rates, free space, inodes, latency |
| `JournalCollector` | `journald` (sd-journal) | Recent entries filtered (priority ≤ warning) |
| `NetworkCollector` | `/proc/net/dev` | Bandwidth per interface, open connections |

### 2. Analyzer (`src/analyzer/`)

Two levels of analysis working in pipeline:

#### Level 1 — Deterministic Rules (fast, local, free)
```text
- RAM used > 85% for > 30s        → HIGH alert
- Zombie process (state Z) > 5 min → MEDIUM alert
- Orphaned process with CPU > 0    → MEDIUM alert
- Same cmdline × N instances (N > threshold) → ALERT (MCP/Python case)
- Swap usage > 50%                 → HIGH alert
- Disk < 5% free space             → CRITICAL alert
- OOM killer in journald           → CRITICAL alert
- Load average > 2× nb_cores for 5min → HIGH alert
- CPU/GPU temperature > threshold  → HIGH alert
- Process with memory leak (monotone RSS increase) → ALERT
```

#### Level 2 — AI Analysis (Claude API, optional)
Activated only when Level 1 detects an anomaly, to:
- Understand context (why these processes exist)
- Propose explicit remediation actions
- Prioritize actions if multiple problems
- Explain in natural language what's happening

**Prompt pattern sent to Claude:**
```text
System: You are an expert Linux sysadmin. Analyze this situation and propose actions.

System context:
- RAM: {used}/{total} ({percent}%), swap: {swap_used}/{swap_total}
- CPU load: {load_1m}/{load_5m}/{load_15m} ({n_cores} cores)
- Top processes by RAM: [list]
- Top processes by CPU: [list]
- Suspicious processes detected: [list with reason]
- Recent abnormal journald entries: [list]

Reply in structured JSON:
{
  "diagnostic": "clear explanation of the problem",
  "severity": "critical|high|medium|low",
  "actions": [
    {
      "type": "kill_process|restart_service|free_cache|custom",
      "target": "pid or service",
      "command": "exact command",
      "risk": "safe|moderate|dangerous",
      "explanation": "why this action"
    }
  ],
  "prevention": "advice to prevent this problem in the future"
}
```

### 3. Action Engine (`src/actions/`)

Three configurable operation modes:

| Mode | Behavior |
|------|----------|
| `observe` | Notify only (default) |
| `suggest` | Notify + propose commands to copy/paste |
| `auto` | Automatically execute "safe" actions |

**Notification channels:**
- `notify-send` (desktop notifications)
- Terminal (ANSI colored output to stdout)
- Structured log file (JSON)
- Optional webhook (Slack, Discord, etc.)

### 4. State Store (`src/store/`)

Embedded SQLite via `rusqlite` for:
- Snapshot history (24-hour rolling window)
- Learned baseline (averages/standard deviations per hour of day)
- Alert and action history
- Custom threshold configuration

### 5. CLI (`src/cli/`)

```bash
vigil                      # Launch daemon (observe mode by default)
vigil status               # Instant system snapshot
vigil report               # Detailed report of last 24h
vigil watch                # Interactive mode (like htop + AI)
vigil explain <pid>        # Ask AI to explain a process
vigil kill <pid> [--force] # Kill with confirmation and logging
vigil config               # Edit configuration
vigil health               # Self-check of the daemon
```

---

## Technical Stack

| Component | Crate | Justification |
|-----------|-------|---------------|
| Async runtime | `tokio` | Standard for async daemon |
| System info | `sysinfo` | Cross-platform, clean API |
| Proc filesystem | `procfs` | Detailed Linux /proc access |
| Journal | `systemd-journal-logger` or `journal-reader` | Native journald reading |
| NVIDIA GPU | `nvml-wrapper` | Safe NVML bindings |
| CLI | `clap` | Standard, derive macros |
| Config | `serde` + `toml` | Readable config file |
| DB | `rusqlite` | Embedded, zero setup |
| HTTP client | `reqwest` | For Claude API |
| Notifications | `notify-rust` | Linux desktop notifications |
| Logging | `tracing` + `tracing-subscriber` | Structured logging |
| Errors | `anyhow` + `thiserror` | Per your best practices |
| TUI (optional) | `ratatui` | For `vigil watch` mode |

---

## Configuration (`~/.config/vigil/config.toml`)

```toml
[general]
mode = "suggest"           # observe | suggest | auto
interval_secs = 5          # collection frequency
language = "en"            # notification language

[thresholds]
ram_warn_percent = 80
ram_critical_percent = 90
swap_warn_percent = 40
cpu_load_factor = 2.0      # alert if load > factor × n_cores
disk_min_free_percent = 10
max_duplicate_processes = 5
zombie_timeout_secs = 300
temperature_cpu_max = 85
temperature_gpu_max = 80

[ai]
enabled = true
provider = "anthropic"
model = "claude-sonnet-4-20250514"
api_key_env = "ANTHROPIC_API_KEY"  # read from env var
max_tokens = 1024
cooldown_secs = 60         # minimum between 2 AI calls

[notifications]
desktop = true
terminal = true
log_file = "~/.local/share/vigil/vigil.log"
# webhook_url = "https://hooks.slack.com/..."

[allowlist]
# Processes to never report
ignore_commands = ["Xorg", "systemd", "dbus-daemon"]
# Processes to never kill automatically
protected_pids = [1]
protected_commands = ["sshd", "systemd", "dbus*"]

[history]
retention_hours = 168      # 7 days
snapshot_interval_secs = 60
```

---

## Specific Detection: "MCP Python Zombies" Case

Mathieu's exact scenario is covered by this composite rule:

```text
RULE: ghost_process_storm
TRIGGERS WHEN:
  1. N processes with same cmdline (ex: "python3 mcp_server.py")
     AND N > max_duplicate_processes (default: 5)
  2. OR orphaned processes (ppid=1 or ppid=reaper) whose original
     parent was "claude-code" or "node" (detected via cmdline/cgroup)
  3. AND these processes collectively consume > X% RAM

ACTION:
  - Notify: "⚠️ {N} identical Python processes detected ({total_ram}MB).
    Probably MCP servers not terminated by Claude Code."
  - Propose: grouped kill by PGID or cmdline pattern
  - Suggested command: `kill $(pgrep -f "mcp_server.py")`
```

---

## Development Plan (Sprints)

### Sprint 1 — Foundation (Week 1-2)
- [ ] Cargo workspace scaffolding
- [ ] Collectors: Process, Memory, CPU
- [ ] Basic deterministic rules (RAM, CPU, zombies)
- [ ] Basic CLI (`vigil status`)
- [ ] Terminal notifications

### Sprint 2 — Intelligence (Week 3-4)
- [ ] Claude API integration
- [ ] journald collector
- [ ] Duplicate process detection (MCP case)
- [ ] Desktop notifications
- [ ] TOML configuration

### Sprint 3 — Persistence & History (Week 5-6)
- [ ] SQLite state store
- [ ] Baseline learning
- [ ] `vigil report` with history
- [ ] Disk + GPU collectors

### Sprint 4 — UX Polish (Week 7-8)
- [ ] `vigil watch` mode (TUI ratatui)
- [ ] `vigil explain <pid>`
- [ ] Auto-remediation mode (safe actions)
- [ ] Webhook notifications
- [ ] Integration tests + packaging

---

## Security & Considerations

- **Principle of Least Privilege**: runs in userspace, not root (except for killing other users' processes)
- **API key**: never in plaintext in config, always via env var or keyring
- **Auto mode**: only for actions classified "safe" (kill own processes)
- **AI Rate Limiting**: configurable cooldown to avoid API costs
- **No telemetry**: 100% local, except opt-in Claude calls
