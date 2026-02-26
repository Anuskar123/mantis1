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
BIN_DIR="/usr/bin"

# 2. Remove Symlinks
echo "[*] Removing symlinks from $BIN_DIR..."
if [ -L "$BIN_DIR/mantis" ]; then
    rm "$BIN_DIR/mantis"
    echo "    - Removed mantis"
fi

if [ -L "$BIN_DIR/mantis-server" ]; then
    rm "$BIN_DIR/mantis-server"
    echo "    - Removed mantis-server (legacy)"
fi

if [ -L "$BIN_DIR/mantis-siem" ]; then
    rm "$BIN_DIR/mantis-siem"
    echo "    - Removed mantis-siem"
fi

# 3. Remove Directory
if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Removing installation directory $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    echo "    - Removed $INSTALL_DIR"
fi

echo ""
echo "[SUCCESS] MANTIS Uninstalled Successfully!"
