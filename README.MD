# 🛡️ Vigil — AI-Powered Linux System Guardian

Vigil continuously monitors your processes, RAM, CPU, disks, and system logs.
It detects anomalies and proposes intelligent fixes via Claude AI
to prevent your PC from slowing down or crashing.

## The Problem

You use Claude Code, MCP servers, or other development tools that create
background processes. Sometimes these processes don't terminate properly
and accumulate silently until your RAM is saturated → freeze → crash.

**Vigil detects this and alerts you before it degenerates.**

## Features

- 📊 **Continuous Monitoring** — RAM, CPU, swap, disks, processes, logs
- 🔍 **Ghost Process Detection** — identifies orphaned MCP/Python/Node processes
- 🧟 **Zombie Detection** — zombie processes consuming resources
- 🤖 **AI Analysis** — Claude explains the problem and proposes solutions
- 🔔 **Notifications** — terminal, desktop, JSON logs, webhooks
- ⚡ **Auto Mode** — automatically executes safe actions

## Installation

### Build

```bash
git clone <repo_url>
cd vigil
cargo build --release
```

### Systemd Service (recommended)

```bash
# Build the release binary first
make build

# Install binary, service, and config
sudo make install

# Enable automatic startup
sudo systemctl enable vigil

# Start the service
sudo systemctl start vigil

# Check status
systemctl status vigil

# View logs
journalctl -u vigil -f
```

### Manual Installation

```bash
# Copy binary
sudo install -m 0755 target/release/vigil /usr/local/bin/

# Copy systemd service
sudo install -m 0644 contrib/vigil.service /etc/systemd/system/

# Create config folder and copy default config
sudo mkdir -p /etc/vigil
sudo cp config.default.toml /etc/vigil/config.toml

# Reload systemd
sudo systemctl daemon-reload
```

### Uninstall

```bash
sudo make uninstall
# Optional: remove config
sudo rm -rf /etc/vigil
```

## Usage

```bash
# Instant system scan
vigil scan

# Scan with AI analysis
vigil scan --ai

# Quick status
vigil status

# Launch the daemon (continuous monitoring)
vigil

# Explain a suspicious process
vigil explain 12345

# Kill a process
vigil kill 12345
vigil kill 12345 --force

# View/edit config
vigil config
vigil config --edit
```

## Configuration

In user mode, the config is automatically created in `~/.config/vigil/config.toml`.
In systemd service mode, the config is in `/etc/vigil/config.toml` (installed by `sudo make install`).

```toml
[general]
mode = "suggest"     # observe | suggest | auto
interval_secs = 5

[thresholds]
ram_warn_percent = 80
ram_critical_percent = 90
max_duplicate_processes = 5

[ai]
enabled = true
provider = "claude-cli"  # claude-cli | ollama | noop
model = "claude-sonnet-4-20250514"
cooldown_secs = 60
```

## Requirements

- Linux (Ubuntu/Fedora/Arch/NixOS)
- Rust 1.75+
- `claude` CLI (for AI analysis via Claude subscription) **or** Ollama (for a local LLM)
- `journalctl` accessible (for system logs)
- `libdbus` (for desktop notifications)

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.MD) for complete technical details.

## License

MIT
