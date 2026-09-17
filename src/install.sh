#!/bin/bash
# mantis installer - works on most linux distros
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[!] run as root: sudo ./install.sh"
  exit 1
fi

# detect distro
DISTRO="unknown"
PKG=""
INSTALL=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO=$ID
fi

case "$DISTRO" in
  ubuntu|debian|kali|raspbian|linuxmint|pop|elementary)
    PKG="apt-get"; INSTALL="apt-get install -y --no-install-recommends" ;;
  fedora|rhel|centos|rocky|almalinux)
    if command -v dnf >/dev/null 2>&1; then
      PKG="dnf"; INSTALL="dnf install -y"
    else
      PKG="yum"; INSTALL="yum install -y"
    fi ;;
  arch|manjaro|endeavouros)
    PKG="pacman"; INSTALL="pacman -S --noconfirm --needed" ;;
  opensuse*|sles)
    PKG="zypper"; INSTALL="zypper install -y" ;;
  alpine)
    PKG="apk"; INSTALL="apk add --no-cache" ;;
  *)
    echo "[!] unknown distro '$DISTRO' - continuing with generic install" ;;
esac

echo "[*] distro: $DISTRO  pkg: ${PKG:-none}"

# python check
if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 missing, trying to install..."
  case "$PKG" in
    apt-get|dnf|yum|zypper|apk) $INSTALL python3 ;;
    pacman) $INSTALL python ;;
    *) echo "[!] install python3 manually"; exit 1 ;;
  esac
fi

PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,8) else 0)')
if [ "$PY_OK" != "1" ]; then
  echo "[!] need python 3.8+"
  exit 1
fi

# optional but useful tools
case "$PKG" in
  apt-get) $INSTALL iptables libcap2-bin || true ;;
  dnf|yum) $INSTALL iptables libcap || true ;;
  pacman)  $INSTALL iptables libcap || true ;;
  zypper)  $INSTALL iptables libcap-progs || true ;;
  apk)     $INSTALL iptables libcap || true ;;
esac

# warn if AF_PACKET not available (kernel/container case)
HAS_AF=$(python3 -c 'import socket; print(1 if hasattr(socket,"AF_PACKET") else 0)' 2>/dev/null || echo 0)
if [ "$HAS_AF" != "1" ]; then
  echo "[!] AF_PACKET not available - sensor mode won't work but train/eval will"
fi

INSTALL_DIR="/opt/mantis"
BIN_DIR="/usr/local/bin"
SUDO_BIN_DIR="/usr/bin"
SOURCE_DIR=$(pwd)

if [ "$SOURCE_DIR" = "$INSTALL_DIR" ]; then
  echo "[*] in-place install"
else
  echo "[*] installing to $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  cp -r ./* "$INSTALL_DIR/"
fi

# CRLF -> LF for windows-edited files
if command -v sed >/dev/null 2>&1; then
  find "$INSTALL_DIR" -type f \( -name "*.py" -o -name "*.sh" -o -name "*.md" \) \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true
fi

chmod +x "$INSTALL_DIR/main.py" "$INSTALL_DIR/dashboard_ui/siem.py" \
         "$INSTALL_DIR/sensor_node/sensor.py" "$INSTALL_DIR/benchmark.sh" \
         "$INSTALL_DIR/demo_all_attacks.sh" "$INSTALL_DIR/replay.py" 2>/dev/null || true

mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/main.py" "$BIN_DIR/mantis"
ln -sf "$INSTALL_DIR/dashboard_ui/siem.py" "$BIN_DIR/mantis-siem"
ln -sf "$INSTALL_DIR/training/train.py" "$BIN_DIR/mantis-train" 2>/dev/null || true
ln -sf "$INSTALL_DIR/evaluation/evaluate.py" "$BIN_DIR/mantis-eval" 2>/dev/null || true
ln -sf "$INSTALL_DIR/replay.py" "$BIN_DIR/mantis-replay" 2>/dev/null || true
ln -sf "$INSTALL_DIR/benchmark.sh" "$BIN_DIR/mantis-benchmark" 2>/dev/null || true
ln -sf "$INSTALL_DIR/demo_all_attacks.sh" "$BIN_DIR/mantis-demo-attacks" 2>/dev/null || true

# Some sudo configurations use a restricted PATH that omits /usr/local/bin.
# Keep compatibility links for the commands that need to run through sudo so
# both `sudo mantis` and `sudo mantis-demo-attacks` resolve reliably.
if [ "$SUDO_BIN_DIR" != "$BIN_DIR" ]; then
  mkdir -p "$SUDO_BIN_DIR"
  ln -sf "$INSTALL_DIR/main.py" "$SUDO_BIN_DIR/mantis"
  ln -sf "$INSTALL_DIR/demo_all_attacks.sh" \
    "$SUDO_BIN_DIR/mantis-demo-attacks"
fi

# Do not grant network capabilities to the system-wide Python interpreter.
# That would give every Python program on the machine raw-socket or network-
# administration privileges.  Live capture therefore runs explicitly through
# sudo; all offline commands remain unprivileged.

echo ""
echo "[done] mantis installed"
echo "  sudo mantis         # live sensor with raw-capture privileges"
echo "  mantis --help"
echo "  mantis-siem         # web dashboard"
echo "  mantis-train --help # train from a dataset"
echo "  mantis-eval --help  # evaluate accuracy"
echo "  mantis-replay       # offline .pcap replay lab (no root, repeatable)"
echo "  mantis-benchmark    # train + test + compare models (no root)"
echo "  mantis-demo-attacks # live: scan + flood + SQLi (needs root + MANTIS running)"
