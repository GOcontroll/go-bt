#!/bin/bash
# go-bt-bdaddr.sh — flash a deterministic locally-administered BLE address
# onto hci0, derived from the controller's end0 Ethernet MAC.
#
# Why this exists: Murata 1YN modules on Moduline L4/M1/HMI1 ship with
# their Broadcom BCM4345C0 chip in a state where no BD_ADDR is loaded
# from NVRAM. The chip then falls back to AA:AA:AA:AA:AA:AA — the
# Cypress/Broadcom default-zonder-NVRAM placeholder. With multiple
# controllers in range, every BLE central (iOS CoreBluetooth, Android,
# generic scanners) sees the SAME peer address for all of them and
# dedupes them into a single peripheral entry.
#
# Fix: derive a unique-but-traceable LE address from end0 MAC (which IS
# unique per controller, set in the imaging pipeline) and program it
# via btmgmt. The locally-administered bit (bit 1 of the first octet,
# set to 1) marks the address as not-from-IEEE.
#
# Example: end0=00:0c:c6:94:91:77  →  hci0=02:0c:c6:94:91:77
#
# Triggered by `go-bt-bdaddr.timer` 60 s after multi-user.target. The
# 60-second delay is deliberate: the BCM4345C0 chip rejects `btmgmt
# power off` for the first ~60 s after boot (chip-init state machine),
# which is exactly the operation needed to accept a public-addr change.
# Manual btmgmt commands work fine after that window.
#
# Once the flip succeeds the script restarts go-bt.service so the new
# address is broadcast immediately. Idempotent — re-running while the
# correct address is already set is a no-op (no chip cycle, no go-bt
# restart).

set -e

LOG_PREFIX="go-bt-bdaddr"
ETH_PATH="/sys/class/net/end0/address"

if [[ ! -f "$ETH_PATH" ]]; then
    echo "$LOG_PREFIX: $ETH_PATH not present — skipping"
    exit 0
fi

ETH_MAC=$(cat "$ETH_PATH" | tr 'A-Z' 'a-z')
if [[ -z "$ETH_MAC" || "$ETH_MAC" == "00:00:00:00:00:00" ]]; then
    echo "$LOG_PREFIX: end0 MAC empty/zero — skipping" >&2
    exit 0
fi

# Compose locally-administered LE address from end0 MAC.
# First byte: clear bottom 2 bits, set bit 1 (locally-administered, unicast).
ETH_FIRST_HEX="${ETH_MAC%%:*}"
LE_FIRST=$(printf '%02x' $(( (0x${ETH_FIRST_HEX} & 0xfc) | 0x02 )))
ETH_TAIL="${ETH_MAC#*:}"
LE_ADDR="${LE_FIRST}:${ETH_TAIL}"

# Idempotent check: skip the chip-cycle entirely if we're already set.
CURRENT=$(busctl get-property org.bluez /org/bluez/hci0 \
    org.bluez.Adapter1 Address 2>/dev/null \
    | sed -E 's/^s "([^"]+)"$/\1/' | tr 'A-Z' 'a-z')

if [[ "$CURRENT" == "$LE_ADDR" ]]; then
    echo "$LOG_PREFIX: hci0 already at $LE_ADDR (from end0 $ETH_MAC); no change"
    exit 0
fi

echo "$LOG_PREFIX: $CURRENT → $LE_ADDR (derived from end0 $ETH_MAC)"

# Power off — chip-state-machine warm-up. Even at 60 s post-boot the
# BCM4345C0 sometimes still rejects power-off; retry every 15 s for up
# to 3 minutes. Once power-off succeeds the rest of the sequence is
# instant.
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    if timeout 5 btmgmt --index 0 power off >/dev/null 2>&1; then
        echo "$LOG_PREFIX: power off succeeded on attempt $ATTEMPT"
        break
    fi
    if [[ $ATTEMPT -ge 12 ]]; then
        echo "$LOG_PREFIX: WARNING — btmgmt power off failed after $ATTEMPT attempts (~3 min); aborting" >&2
        exit 1
    fi
    echo "$LOG_PREFIX: power off attempt $ATTEMPT failed; retrying in 15 s"
    sleep 15
done

# Set address + power back on. The "power on" call typically returns
# "Invalid Index" because changing the address removes the old adapter
# index from the kernel mgmt API; bluetoothd re-adds it under the new
# address shortly after. We treat that error as benign.
if ! timeout 5 btmgmt --index 0 public-addr "$LE_ADDR" >/dev/null 2>&1; then
    echo "$LOG_PREFIX: WARNING — btmgmt public-addr failed; restoring power" >&2
    timeout 5 btmgmt --index 0 power on >/dev/null 2>&1 || true
    exit 1
fi
timeout 5 btmgmt --index 0 power on >/dev/null 2>&1 || true
sleep 1

echo "$LOG_PREFIX: hci0 now at $LE_ADDR; restarting go-bt to advertise with new address"
systemctl restart go-bt.service || {
    echo "$LOG_PREFIX: WARNING — go-bt restart failed; address is set but adv may need manual restart" >&2
    exit 0
}
echo "$LOG_PREFIX: done"
