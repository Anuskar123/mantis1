#!/bin/bash

# MANTIS Installation Script
# Automated deployment for Linux Systems

# 1. Check for Root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Error: Please run as root (sudo ./install.sh)"
  exit 1
fi

echo "[*] Starting MANTIS Installation..."

# 2. Define Paths
INSTALL_DIR="/opt/mantis"
BIN_DIR="/usr/bin"
SOURCE_DIR=$(pwd)

# 3. Check Installation Mode
if [ "$SOURCE_DIR" == "$INSTALL_DIR" ]; then
    echo "[*] Detected running INSIDE install directory. Performing IN-PLACE installation."
    # We are already in /opt/mantis, so we DON'T delete ourselves.
else
    echo "[*] Performing FRESH installation to $INSTALL_DIR..."
    
    if [ -d "$INSTALL_DIR" ]; then
        echo "[*] Removing old installation..."
        rm -rf "$INSTALL_DIR"
    fi

    echo "[*] Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"

    echo "[*] Copying files..."
    # Copy contents of current directory to install directory
    cp -r ./* "$INSTALL_DIR"
fi

# 4. Verify Files Exist
if [ ! -f "$INSTALL_DIR/main.py" ]; then
    echo "[!] Error: main.py not found in $INSTALL_DIR"
    echo "    Did the copy fail? Or are you running this from an empty folder?"
    exit 1
fi

# 4.5. Fix Windows Line Endings (CRLF -> LF)
if command -v sed >/dev/null 2>&1; then
    echo "[*] Converting Line Endings (Recursively)..."
    find "$INSTALL_DIR" -type f \( -name "*.py" -o -name "*.sh" -o -name "*.md" \) -exec sed -i 's/\r$//' {} \; 2>/dev/null
    sed -i 's/\r$//' "$INSTALL_DIR"/LICENSE 2>/dev/null
else
    echo "[!] Warning: 'sed' not found. You might have line-ending issues."
fi

# 5. Set Permissions
echo "[*] Setting execute permissions..."
chmod +x "$INSTALL_DIR/main.py"
# chmod +x "$INSTALL_DIR/log_server.py" # Removed legacy file
chmod +x "$INSTALL_DIR/dashboard_ui/siem.py"
chmod +x "$INSTALL_DIR/sensor_node/sensor.py"

# 6. Create Symlinks
echo "[*] Creating symlinks in $BIN_DIR..."

# Client (Sensor)
if [ -L "$BIN_DIR/mantis" ]; then
    rm "$BIN_DIR/mantis"
fi
ln -sf "$INSTALL_DIR/main.py" "$BIN_DIR/mantis"


# SIEM (New Web Dashboard)
if [ -L "$BIN_DIR/mantis-siem" ]; then
    rm "$BIN_DIR/mantis-siem"
fi
ln -sf "$INSTALL_DIR/dashboard_ui/siem.py" "$BIN_DIR/mantis-siem"

# 7. Final Check
if command -v mantis >/dev/null 2>&1; then
    echo ""
    echo "[SUCCESS] MANTIS Installed Successfully!"
    echo "    Mode: $(if [ "$SOURCE_DIR" == "$INSTALL_DIR" ]; then echo "In-Place"; else echo "System-Wide"; fi)"
    echo ""
    echo "Usage:"
    echo "  sudo mantis              # Run HIDS Sensor"
    echo "  sudo mantis --help       # Show options"
    echo "  mantis-siem              # Run Enterprise Web Dashboard"
    echo ""
else
    echo ""
    echo "[!] Installation Failed. Please check errors above."
fi
