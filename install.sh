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
# Trixie ships PEP 668 ("externally-managed-environment") so plain `pip3 install
# dbus-python` fails on the build step (compiles against libdbus). Use the
# Debian-packaged versions of dbus-python + PyGObject — they're recent enough
# and have all the C-extension build sorted out — and only fall back to pip
# (with --break-system-packages) for bluezero, which is pure-Python.
info "Installing apt-packaged Python deps (python3-dbus, python3-gi)..."
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-dbus python3-gi \
    || warn "apt install failed — continuing in case packages are already present"

info "Installing bluezero via pip (system-wide, --break-system-packages)..."
pip3 install --break-system-packages bluezero \
    || fail "Failed to install bluezero. Run: pip3 install --break-system-packages bluezero"

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
# 4. BD_ADDR helper — flash a deterministic LE address derived from end0 MAC
# -----------------------------------------------------------------------------
# Murata 1YN modules ship without a programmed BD_ADDR; the BCM chip falls
# back to AA:AA:AA:AA:AA:AA which makes multiple controllers in range
# indistinguishable to BLE centrals. The helper runs 60 s after boot via
# go-bt-bdaddr.timer — the BCM4345C0 chip rejects the btmgmt power-off
# needed for an address-change for the first ~60 s after boot, so we
# wait until the chip-init has settled. The script restarts go-bt
# itself once the flip succeeds.
info "Installing BD_ADDR helper..."
install -m 0755 "$SCRIPT_DIR/go-bt-bdaddr.sh" /usr/local/sbin/go-bt-bdaddr.sh
cp "$SCRIPT_DIR/go-bt-bdaddr.service" /etc/systemd/system/go-bt-bdaddr.service
cp "$SCRIPT_DIR/go-bt-bdaddr.timer"   /etc/systemd/system/go-bt-bdaddr.timer

# Tear down a legacy bluetooth.service drop-in from an earlier installer
# version — it tried to flash BD_ADDR as ExecStartPre but hung on the
# pre-init chip and blocked bluetoothd from coming up at all.
if [[ -f /etc/systemd/system/bluetooth.service.d/00-go-bt-bdaddr.conf ]]; then
    info "Removing legacy bluetooth.service drop-in (replaced by timer)..."
    rm -f /etc/systemd/system/bluetooth.service.d/00-go-bt-bdaddr.conf
    rmdir /etc/systemd/system/bluetooth.service.d 2>/dev/null || true
fi

# -----------------------------------------------------------------------------
# 5. Systemd unit
# -----------------------------------------------------------------------------
info "Installing systemd service..."
cp "$SCRIPT_DIR/go-bt.service" /etc/systemd/system/go-bt.service
systemctl daemon-reload
systemctl enable go-bt.service
systemctl enable go-bt-bdaddr.timer

# -----------------------------------------------------------------------------
# 6. Restart services
# -----------------------------------------------------------------------------
# Restarting bluetooth.service triggers our ExecStartPre = bdaddr-flash,
# so the BD_ADDR is applied before bluetoothd starts; go-bt then comes up
# with the correct address already in place.
info "Restarting bluetooth.service..."
systemctl restart bluetooth.service
sleep 2

info "Starting go-bt.service..."
systemctl restart go-bt.service
sleep 2

info "Starting BD_ADDR timer (flashes 60 s after boot)..."
systemctl restart go-bt-bdaddr.timer
warn "BD_ADDR will be flashed in ~60 s. Until then the controller advertises"
warn "on the chip-default AA:AA:AA:AA:AA:AA — multi-controller setups in range"
warn "of each other will dedupe to a single peripheral on iOS until the timer"
warn "fires (controller will then auto-restart go-bt with the correct address)."

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
