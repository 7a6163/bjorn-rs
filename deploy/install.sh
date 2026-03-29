#!/bin/bash
set -euo pipefail

# Bjorn Rust Edition - Installation Script
# Run on the Raspberry Pi: sudo ./install.sh

BJORN_ROOT="/home/bjorn/Bjorn"
BJORN_BIN="/home/bjorn/bjorn"
SERVICE_FILE="/etc/systemd/system/bjorn.service"

echo "=== Bjorn Rust Edition Installer ==="

# 1. Install required system packages
echo "[1/5] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    nmap \
    smbclient \
    sshpass \
    wget \
    zip \
    redis-tools \
    mysql-client \
    postgresql-client \
    xfreerdp2-x11 \
    network-manager \
    2>/dev/null || true

# MongoDB tools (optional, may not be in default repos)
apt-get install -y -qq mongo-tools mongosh 2>/dev/null || \
    echo "  [warn] mongosh/mongo-tools not available, MongoDB features will be limited"

# 2. Create directory structure
echo "[2/5] Creating directory structure..."
mkdir -p "$BJORN_ROOT"/{config,data/{input/dictionary,output/{crackedpwd,data_stolen,scan_results,vulnerabilities,zombies},logs},backup/{backups,uploads},web,resources/{images/{static,status},fonts,comments}}

# 3. Copy resources from Python project if they exist alongside
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -d "$PYTHON_ROOT/../Bjorn/web" ]; then
    echo "  Copying web UI from Python project..."
    cp -r "$PYTHON_ROOT/../Bjorn/web/"* "$BJORN_ROOT/web/" 2>/dev/null || true
fi
if [ -d "$PYTHON_ROOT/../Bjorn/resources" ]; then
    echo "  Copying resources from Python project..."
    cp -r "$PYTHON_ROOT/../Bjorn/resources/"* "$BJORN_ROOT/resources/" 2>/dev/null || true
fi
if [ -d "$PYTHON_ROOT/../Bjorn/data/input" ]; then
    echo "  Copying wordlists from Python project..."
    cp -r "$PYTHON_ROOT/../Bjorn/data/input/"* "$BJORN_ROOT/data/input/" 2>/dev/null || true
fi

# 4. Install binary
echo "[3/5] Installing bjorn binary..."
if [ -f "$SCRIPT_DIR/../bjorn" ]; then
    cp "$SCRIPT_DIR/../bjorn" "$BJORN_BIN"
elif [ -f "$SCRIPT_DIR/bjorn" ]; then
    cp "$SCRIPT_DIR/bjorn" "$BJORN_BIN"
else
    echo "  [error] bjorn binary not found. Build it first with:"
    echo "    make build-pi-zero   (for Pi Zero W)"
    echo "    make build-pi64      (for Pi Zero W2 / Pi 3/4/5)"
    exit 1
fi
chmod +x "$BJORN_BIN"

# 5. Install systemd service
echo "[4/5] Installing systemd service..."
cp "$SCRIPT_DIR/bjorn.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable bjorn.service

echo "[5/5] Creating default wordlists if missing..."
if [ ! -f "$BJORN_ROOT/data/input/dictionary/users.txt" ]; then
    cat > "$BJORN_ROOT/data/input/dictionary/users.txt" << 'USERS'
root
admin
pi
bjorn
user
test
USERS
fi
if [ ! -f "$BJORN_ROOT/data/input/dictionary/passwords.txt" ]; then
    cat > "$BJORN_ROOT/data/input/dictionary/passwords.txt" << 'PASSWORDS'
password
123456
admin
root
raspberry
toor
test
PASSWORDS
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Start Bjorn:   sudo systemctl start bjorn.service"
echo "Stop Bjorn:    sudo systemctl stop bjorn.service"
echo "View logs:     sudo journalctl -u bjorn.service -f"
echo "Web UI:        http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "To start now:  sudo systemctl start bjorn.service"
