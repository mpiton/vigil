#!/usr/bin/env bash
set -euo pipefail

# Installation script for Vigil system guardian
# User-facing text is in English

# Variables
BINARY_NAME="vigil"
BINARY_PATH="target/release/vigil"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/vigil"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="contrib/vigil.service"
CONFIG_FILE="config.default.toml"

# Detect the real user behind sudo
RUN_USER="${SUDO_USER:-$(whoami)}"
RUN_GROUP="$(id -gn "$RUN_USER")"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Verify release binary exists
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: Binary $BINARY_PATH does not exist." >&2
    echo "Please build the project with: cargo build --release" >&2
    exit 1
fi

# Verify config template exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file $CONFIG_FILE does not exist." >&2
    exit 1
fi

# Copy binary
echo "Installing binary..."
install -m 0755 "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"

# Install systemd service file with User= set to the installing user
echo "Installing systemd service file (User=$RUN_USER)..."
sed "s/^# User= is set by install.sh.*/User=$RUN_USER\nGroup=$RUN_GROUP/" \
    "$SERVICE_FILE" > "$SYSTEMD_DIR/$BINARY_NAME.service"
chmod 0644 "$SYSTEMD_DIR/$BINARY_NAME.service"

# Create config directory
echo "Creating configuration directory..."
mkdir -p "$CONFIG_DIR"

# Copy config file if it doesn't already exist
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    echo "Installing configuration file..."
    install -m 0640 "$CONFIG_FILE" "$CONFIG_DIR/config.toml"
    chown "$RUN_USER:$RUN_GROUP" "$CONFIG_DIR/config.toml"
else
    echo "Configuration file already exists, not overwriting."
fi

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Success message
echo ""
echo "Installation successful!"
echo ""
echo "Next steps:"
echo "  1. Check the configuration: sudo nano $CONFIG_DIR/config.toml"
echo "  2. Enable the service: sudo systemctl enable $BINARY_NAME"
echo "  3. Start the service: sudo systemctl start $BINARY_NAME"
echo "  4. Check the status: sudo systemctl status $BINARY_NAME"
