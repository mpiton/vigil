BINARY_NAME := vigil
INSTALL_DIR := /usr/local/bin
SYSTEMD_DIR := /etc/systemd/system
CONFIG_DIR := /etc/vigil

.PHONY: build install uninstall test fmt lint clean help

build:
	cargo build --release

install: build
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: this command requires root privileges (sudo make install)"; \
		exit 1; \
	fi
	./contrib/install.sh

uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: this command requires root privileges (sudo make uninstall)"; \
		exit 1; \
	fi
	systemctl stop vigil.service 2>/dev/null || echo "Note: the service is not active"
	systemctl disable vigil.service 2>/dev/null || echo "Note: the service is not enabled"
	rm -f $(SYSTEMD_DIR)/vigil.service
	rm -f $(INSTALL_DIR)/vigil
	systemctl daemon-reload
	@echo "Vigil has been successfully uninstalled"

test:
	cargo test

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets

clean:
	cargo clean

help:
	@echo "Available targets:"
	@echo "  build       - Build the project in release mode"
	@echo "  install     - Install Vigil (requires sudo)"
	@echo "  uninstall   - Uninstall Vigil (requires sudo)"
	@echo "  test        - Run tests"
	@echo "  fmt         - Format the code"
	@echo "  lint        - Check with clippy"
	@echo "  clean       - Clean build artifacts"
	@echo "  help        - Display this help"
