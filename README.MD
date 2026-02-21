# 🛡️ Vigil — AI-Powered Linux System Guardian

Vigil surveille en continu vos processus, RAM, CPU, disques et journaux système.
Il détecte les anomalies et propose des corrections intelligentes via Claude AI
pour empêcher votre PC de ralentir ou crasher.

## Le problème

Vous utilisez Claude Code, des MCP servers, ou d'autres outils de dev qui créent
des processus en arrière-plan. Parfois ces processus ne se terminent pas proprement
et s'accumulent silencieusement jusqu'à saturer votre RAM → freeze → crash.

**Vigil détecte ça et vous alerte avant que ça ne dégénère.**

## Fonctionnalités

- 📊 **Monitoring continu** — RAM, CPU, swap, disques, processus, journaux
- 🔍 **Détection de processus fantômes** — identifie les MCP/Python/Node orphelins
- 🧟 **Détection de zombies** — processus zombie qui consomment des ressources
- 🤖 **Analyse IA** — Claude explique le problème et propose des solutions
- 🔔 **Notifications** — terminal, desktop, logs JSON, webhooks
- ⚡ **Mode auto** — exécute automatiquement les actions sûres

## Installation

### Compilation

```bash
git clone <repo_url>
cd vigil
cargo build --release
```

### Service systemd (recommandé)

```bash
# Installer le binaire, le service et la config
sudo make install

# Activer le démarrage automatique
sudo systemctl enable vigil

# Démarrer le service
sudo systemctl start vigil

# Vérifier le statut
systemctl status vigil

# Consulter les logs
journalctl -u vigil -f
```

### Installation manuelle

```bash
# Copier le binaire
sudo install -m 0755 target/release/vigil /usr/local/bin/

# Copier le service systemd
sudo install -m 0644 contrib/vigil.service /etc/systemd/system/

# Créer le dossier de config et copier la config par défaut
sudo mkdir -p /etc/vigil
sudo cp config.default.toml /etc/vigil/config.toml

# Recharger systemd
sudo systemctl daemon-reload
```

### Désinstallation

```bash
sudo make uninstall
# Optionnel : supprimer la config
sudo rm -rf /etc/vigil
```

## Utilisation

```bash
# Scan instantané du système
vigil scan

# Scan avec analyse IA
vigil scan --ai

# Status rapide
vigil status

# Lancer le daemon (surveillance continue)
vigil

# Expliquer un processus suspect
vigil explain 12345

# Tuer un processus
vigil kill 12345
vigil kill 12345 --force

# Voir/éditer la config
vigil config
vigil config --edit
```

## Configuration

En mode utilisateur, la config est créée automatiquement dans `~/.config/vigil/config.toml`.
En mode service systemd, la config se trouve dans `/etc/vigil/config.toml` (installée par `sudo make install`).

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

## Prérequis

- Linux (Ubuntu/Fedora/Arch/NixOS)
- Rust 1.75+
- `claude` CLI (pour l'analyse IA via abonnement Claude) **ou** Ollama (pour un LLM local)
- `journalctl` accessible (pour les logs système)
- `libdbus` (pour les notifications desktop)

## Architecture

Voir [ARCHITECTURE.md](ARCHITECTURE.md) pour les détails techniques complets.

## License

MIT
