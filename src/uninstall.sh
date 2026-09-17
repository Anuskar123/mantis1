#!/bin/bash

# MANTIS Uninstallation Script
# Removes the tool from the Linux system

# 1. Check for Root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Error: Please run as root (sudo ./uninstall.sh)"
  exit 1
fi

echo "[*] Starting MANTIS Uninstallation..."

INSTALL_DIR="/opt/mantis"
BIN_DIRS="/usr/local/bin /usr/bin"
COMMANDS="mantis mantis-siem mantis-train mantis-eval mantis-replay mantis-benchmark mantis-demo-attacks mantis-server"

# 2. Remove Symlinks
for BIN_DIR in $BIN_DIRS; do
    echo "[*] Removing MANTIS symlinks from $BIN_DIR..."
    for COMMAND in $COMMANDS; do
        LINK_PATH="$BIN_DIR/$COMMAND"
        if [ -L "$LINK_PATH" ]; then
            rm "$LINK_PATH"
            echo "    - Removed $LINK_PATH"
        fi
    done
done

# 3. Remove Directory
if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Removing installation directory $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    echo "    - Removed $INSTALL_DIR"
fi

echo ""
echo "[SUCCESS] MANTIS Uninstalled Successfully!"
