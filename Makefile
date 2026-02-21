BINARY_NAME := vigil
INSTALL_DIR := /usr/local/bin
SYSTEMD_DIR := /etc/systemd/system
CONFIG_DIR := /etc/vigil

.PHONY: build install uninstall test fmt lint clean help

build:
	cargo build --release

install: build
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Erreur : cette commande nécessite les droits root (sudo make install)"; \
		exit 1; \
	fi
	./contrib/install.sh

uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Erreur : cette commande nécessite les droits root (sudo make uninstall)"; \
		exit 1; \
	fi
	systemctl stop vigil.service 2>/dev/null || echo "Note : le service n'est pas actif"
	systemctl disable vigil.service 2>/dev/null || echo "Note : le service n'est pas activé"
	rm -f $(SYSTEMD_DIR)/vigil.service
	rm -f $(INSTALL_DIR)/vigil
	systemctl daemon-reload
	@echo "Vigil a été désinstallé avec succès"

test:
	cargo test

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets

clean:
	cargo clean

help:
	@echo "Cibles disponibles :"
	@echo "  build       - Compiler le projet en mode release"
	@echo "  install     - Installer Vigil (nécessite sudo)"
	@echo "  uninstall   - Désinstaller Vigil (nécessite sudo)"
	@echo "  test        - Exécuter les tests"
	@echo "  fmt         - Formater le code"
	@echo "  lint        - Vérifier avec clippy"
	@echo "  clean       - Nettoyer les artefacts de compilation"
	@echo "  help        - Afficher cette aide"
