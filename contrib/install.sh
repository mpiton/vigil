#!/usr/bin/env bash
set -euo pipefail

# Installation script for Vigil system guardian
# User-facing text is in French

# Variables
BINARY_NAME="vigil"
BINARY_PATH="target/release/vigil"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/vigil"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="contrib/vigil.service"
CONFIG_FILE="config.default.toml"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Erreur : Ce script doit être exécuté en tant que root." >&2
    exit 1
fi

# Verify release binary exists
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Erreur : Le binaire $BINARY_PATH n'existe pas." >&2
    echo "Veuillez compiler le projet avec : cargo build --release" >&2
    exit 1
fi

# Verify config template exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Erreur : Le fichier de configuration $CONFIG_FILE n'existe pas." >&2
    exit 1
fi

# Copy binary
echo "Installation du binaire..."
install -m 0755 "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"

# Copy service file
echo "Installation du fichier de service systemd..."
install -m 0644 "$SERVICE_FILE" "$SYSTEMD_DIR/$BINARY_NAME.service"

# Create config directory
echo "Création du répertoire de configuration..."
mkdir -p "$CONFIG_DIR"

# Copy config file if it doesn't already exist
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    echo "Installation du fichier de configuration..."
    install -m 0640 "$CONFIG_FILE" "$CONFIG_DIR/config.toml"
else
    echo "Le fichier de configuration existe déjà, pas d'écrasement."
fi

# Reload systemd
echo "Rechargement de systemd..."
systemctl daemon-reload

# Success message
echo ""
echo "✓ Installation réussie !"
echo ""
echo "Prochaines étapes :"
echo "  1. Vérifier la configuration : sudo nano $CONFIG_DIR/config.toml"
echo "  2. Activer le service : sudo systemctl enable $BINARY_NAME"
echo "  3. Démarrer le service : sudo systemctl start $BINARY_NAME"
echo "  4. Vérifier le statut : sudo systemctl status $BINARY_NAME"
