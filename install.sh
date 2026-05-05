#!/bin/bash
# =============================================================================
# go-bt — installer for GOcontroll Linux controllers (L4 / M1 / HMI1)
# =============================================================================
# Modeled on the Twilight-Flow Raspberry-Pi installer
# (github.com/Rick-GO/GOcontroll-Stepper-Hat).
# Run as root on the target controller:
#   sudo bash install.sh
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail() { echo -e "${RED}[FAIL]${NC}  $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
    fail "Run as root: sudo bash install.sh"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/gocontroll/go-bt"

# -----------------------------------------------------------------------------
# 1. Python dependencies
# -----------------------------------------------------------------------------
info "Installing Python dependencies (bluezero, dbus-python, PyGObject)..."
pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages 2>/dev/null \
    || pip3 install -r "$SCRIPT_DIR/requirements.txt"

# -----------------------------------------------------------------------------
# 2. Server script
# -----------------------------------------------------------------------------
info "Copying ble_server.py to $INSTALL_DIR/..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/ble_server.py" "$INSTALL_DIR/ble_server.py"
chmod 755 "$INSTALL_DIR/ble_server.py"

# -----------------------------------------------------------------------------
# 3. BlueZ configuration (LE-only + JustWorks repairing)
# -----------------------------------------------------------------------------
info "Installing /etc/bluetooth/main.conf..."
cp "$SCRIPT_DIR/config/bluetooth_main.conf" /etc/bluetooth/main.conf

# -----------------------------------------------------------------------------
# 4. Systemd unit
# -----------------------------------------------------------------------------
info "Installing systemd service..."
cp "$SCRIPT_DIR/go-bt.service" /etc/systemd/system/go-bt.service
systemctl daemon-reload
systemctl enable go-bt.service

# -----------------------------------------------------------------------------
# 5. Restart services
# -----------------------------------------------------------------------------
info "Restarting bluetooth.service..."
systemctl restart bluetooth.service

info "Starting go-bt.service..."
systemctl restart go-bt.service
sleep 2

if systemctl is-active --quiet go-bt.service; then
    info "go-bt.service is running."
else
    fail "go-bt.service failed to start. Check: journalctl -u go-bt.service -n 50"
fi

echo ""
echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}  Installation complete${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""
echo "  Status:  systemctl status go-bt"
echo "  Logs:    journalctl -fu go-bt"
echo "  Restart: systemctl restart go-bt"
echo ""
