#!/usr/bin/env python3
"""
go-bt — BLE GATT server for GOcontroll Linux controllers (L4 / M1 / HMI1).

Stage 1 (Twilight-Flow scope): single primary service, three raw-binary
characteristics, iOS-driven heartbeat watchdog. The goal of this stage is
exclusively to prove the connection layer is rock-solid: scan, connect,
read/notify, write, watchdog timeout, disconnect, reconnect.

This file deliberately lives flat at the repo root and is structured
section-for-section like the Twilight-Flow / Stepper-Hat reference server
(github.com/Rick-GO/GOcontroll-Stepper-Hat — Raspberry BT server) which has
been running stably for months.

Service     4E2C7A1B-F3D5-4890-B6C8-2A9E0F7D3C5B
Heartbeat   4E2C7A30-…   [read, notify]   Pi → iPhone   1 s   1 byte counter
Control     4E2C7A31-…   [write, w/o-r]   iPhone → Pi   ≥1 s  4 bytes [seq, cmd, arg_lo, arg_hi]
Telemetry   4E2C7A32-…   [read, notify]   Pi → iPhone   5 s   16 bytes (see _pack_telemetry)

Run:
    sudo /usr/bin/python3 /opt/gocontroll/go-bt/ble_server.py
"""

import logging
import socket
import struct
import time
import zlib
from logging.handlers import RotatingFileHandler

import dbus
import dbus.service
import dbus.mainloop.glib
from bluezero import adapter, advertisement, async_tools, constants, peripheral

# ──────────────────────────────────────────────────────────────────────────────
# UUIDs — kept identical to the Linux mgmt service the iOS app already knows
# ──────────────────────────────────────────────────────────────────────────────
SERVICE_UUID    = '4E2C7A1B-F3D5-4890-B6C8-2A9E0F7D3C5B'
HEARTBEAT_UUID  = '4E2C7A30-F3D5-4890-B6C8-2A9E0F7D3C5B'
CONTROL_UUID    = '4E2C7A31-F3D5-4890-B6C8-2A9E0F7D3C5B'
TELEMETRY_UUID  = '4E2C7A32-F3D5-4890-B6C8-2A9E0F7D3C5B'

HEARTBEAT_INTERVAL_MS = 1000
TELEMETRY_INTERVAL_S  = 5
WATCHDOG_TIMEOUT_S    = 2.0

# ──────────────────────────────────────────────────────────────────────────────
# Advertising intervals (milliseconds, per the BlueZ LEAdvertisement1 spec).
# bluezero ≤ 0.9.1 doesn't expose MinInterval/MaxInterval on the advertisement
# props, so BlueZ falls back to the kernel default (le_adv_min_interval) which
# on this controller is 2048 (× 0.625 ms = 1280 ms) — far too slow for snappy
# discovery from an iPhone in foreground scan.
#
# 50/100 ms matches what an ESP32 advertises out of the box and what the Pi
# build of BlueZ uses for "fast advertising" before a bond is formed.
# ──────────────────────────────────────────────────────────────────────────────
ADV_MIN_INTERVAL_MS = 50
ADV_MAX_INTERVAL_MS = 100

AGENT_PATH       = '/com/gocontroll/agent'
AGENT_CAPABILITY = 'NoInputNoOutput'

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Globals — written by GLib timers and BlueZ callbacks (single-threaded mainloop)
# ──────────────────────────────────────────────────────────────────────────────
_heartbeat_counter: int = 0
_heartbeat_char = None
_telemetry_char = None

_last_control_ts: float = 0.0
_session_active:  bool  = False

# Cached telemetry inputs (refreshed once per telemetry tick)
_cpu_prev_idle:  int = 0
_cpu_prev_total: int = 0


# ──────────────────────────────────────────────────────────────────────────────
# BlueZ NoInputNoOutput agent — Just-Works pairing, auto-trust on connect.
# Same mechanic Twilight-Flow uses on the Raspberry Pi reference build.
# ──────────────────────────────────────────────────────────────────────────────
def _trust_device(device_path: str) -> None:
    try:
        bus = dbus.SystemBus()
        props = dbus.Interface(
            bus.get_object('org.bluez', device_path),
            'org.freedesktop.DBus.Properties'
        )
        props.Set('org.bluez.Device1', 'Trusted', dbus.Boolean(True))
        logger.info('Trusted device: %s', device_path)
    except dbus.DBusException as exc:
        logger.warning('Trusting %s failed: %s', device_path, exc)


class _NoInputNoOutputAgent(dbus.service.Object):
    @dbus.service.method('org.bluez.Agent1', in_signature='', out_signature='')
    def Release(self):
        pass

    @dbus.service.method('org.bluez.Agent1', in_signature='os', out_signature='')
    def AuthorizeService(self, device, uuid):
        logger.info('Agent: AuthorizeService %s %s — granted', device, uuid)

    @dbus.service.method('org.bluez.Agent1', in_signature='o', out_signature='')
    def RequestAuthorization(self, device):
        logger.info('Agent: RequestAuthorization %s — granted', device)
        _trust_device(device)

    @dbus.service.method('org.bluez.Agent1', in_signature='', out_signature='')
    def Cancel(self):
        pass


def _register_agent() -> None:
    try:
        bus = dbus.SystemBus()
        _NoInputNoOutputAgent(bus, AGENT_PATH)
        manager = dbus.Interface(
            bus.get_object('org.bluez', '/org/bluez'),
            'org.bluez.AgentManager1'
        )
        manager.RegisterAgent(AGENT_PATH, AGENT_CAPABILITY)
        manager.RequestDefaultAgent(AGENT_PATH)
        logger.info('BlueZ agent registered: %s (%s)', AGENT_PATH, AGENT_CAPABILITY)
    except dbus.DBusException as exc:
        logger.warning('Agent registration failed: %s', exc)


def _find_adapter_path() -> str | None:
    """Return the DBus object path of the first BlueZ adapter (e.g. /org/bluez/hci0)."""
    try:
        bus = dbus.SystemBus()
        manager = dbus.Interface(
            bus.get_object('org.bluez', '/'),
            'org.freedesktop.DBus.ObjectManager'
        )
        for path, ifaces in manager.GetManagedObjects().items():
            if 'org.bluez.Adapter1' in ifaces:
                return str(path)
    except dbus.DBusException as exc:
        logger.warning('Adapter path lookup failed: %s', exc)
    return None


def _set_kernel_adv_defaults() -> None:
    """Lower the kernel's default advertising interval too, as a belt to the
    DBus suspenders. The kernel default applies if BlueZ ever forwards an
    advertisement registration without per-ad MinInterval/MaxInterval — and
    other non-go-bt processes that touch this adapter benefit too.

    Values are in HCI units of 0.625 ms. 80 ≈ 50 ms, 160 ≈ 100 ms.
    """
    pairs = [
        ('/sys/kernel/debug/bluetooth/hci0/adv_min_interval',
         int(ADV_MIN_INTERVAL_MS / 0.625)),
        ('/sys/kernel/debug/bluetooth/hci0/adv_max_interval',
         int(ADV_MAX_INTERVAL_MS / 0.625)),
    ]
    for path, value in pairs:
        try:
            with open(path, 'w') as fh:
                fh.write(str(value))
        except OSError as exc:
            logger.warning('Setting %s failed: %s', path, exc)
    logger.info('Kernel adv defaults set: %d–%d ms (%d–%d HCI units)',
                ADV_MIN_INTERVAL_MS, ADV_MAX_INTERVAL_MS,
                pairs[0][1], pairs[1][1])


def _disable_pairing() -> None:
    """Force the adapter into non-bondable mode.

    None of our characteristics require encryption, so iOS has no functional
    reason to pair — yet it does opportunistically when it sees a Just-Works
    capable peripheral, which leaves the controller listed under
    Settings → Bluetooth and slows down every subsequent reconnect because
    iOS prefers its cached LL link over a fresh CoreBluetooth scan.

    Setting `Pairable = false` on the adapter makes BlueZ refuse pairing
    requests at the SMP layer. iOS then connects without bonding, the device
    never lands in Settings, and reconnects use the same fast path as the
    very first connection.
    """
    path = _find_adapter_path()
    if not path:
        logger.warning('Disabling pairing skipped: no adapter found')
        return
    try:
        bus = dbus.SystemBus()
        props = dbus.Interface(
            bus.get_object('org.bluez', path),
            'org.freedesktop.DBus.Properties'
        )
        props.Set('org.bluez.Adapter1', 'Pairable', dbus.Boolean(False))
        logger.info('Adapter %s Pairable=false (no bonding)', path)
    except dbus.DBusException as exc:
        logger.warning('Disabling pairing failed: %s', exc)


# ──────────────────────────────────────────────────────────────────────────────
# Heartbeat — Pi → iPhone, 1 s, 1 byte counter
# ──────────────────────────────────────────────────────────────────────────────
def _heartbeat_tick() -> bool:
    global _heartbeat_counter
    _heartbeat_counter = (_heartbeat_counter + 1) & 0xFF
    if _heartbeat_char is not None and _heartbeat_char.is_notifying:
        _heartbeat_char.set_value([_heartbeat_counter])
    return True


def cb_heartbeat_read():
    return [_heartbeat_counter]


def cb_heartbeat_notify(notifying: bool, characteristic) -> None:
    global _heartbeat_char
    _heartbeat_char = characteristic
    logger.info('Heartbeat notifications %s', 'ON' if notifying else 'OFF')


# ──────────────────────────────────────────────────────────────────────────────
# Control — iPhone → Pi, write / write-without-response, 4 bytes
#   Byte 0   seq      uint8   monotonic per-session sequence number
#   Byte 1   cmd      uint8   reserved for stage 2; ignored in stage 1
#   Bytes 2-3 arg     uint16  little-endian, reserved for stage 2
#
# Every successful write resets the watchdog. The first write of a session
# also flips _session_active = True so the watchdog starts arming.
# ──────────────────────────────────────────────────────────────────────────────
def cb_control_write(value, options) -> None:
    global _last_control_ts, _session_active
    raw = bytes(value)
    if len(raw) < 4:
        logger.warning('Control: short packet (%d bytes), ignored', len(raw))
        return
    seq = raw[0]
    cmd = raw[1]
    arg = struct.unpack_from('<H', raw, 2)[0]
    _last_control_ts = time.monotonic()
    if not _session_active:
        logger.info('Control: session opened (first write)')
        _session_active = True
    logger.info('Control: seq=%d cmd=%d arg=%d', seq, cmd, arg)


# ──────────────────────────────────────────────────────────────────────────────
# Watchdog — 1 Hz; logs once when the iPhone heartbeat times out.
# ──────────────────────────────────────────────────────────────────────────────
def _watchdog() -> bool:
    global _session_active
    if not _session_active:
        return True
    elapsed = time.monotonic() - _last_control_ts
    if elapsed > WATCHDOG_TIMEOUT_S:
        logger.warning('Watchdog: no Control write for %.1fs — session lost', elapsed)
        _session_active = False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Telemetry — Pi → iPhone, 5 s, fixed 16-byte struct (little-endian)
#   B   model           1=L4 2=M1 3=HMI1 0=unknown
#   I   hostname_hash   crc32 of socket.gethostname()
#   I   uptime_s        seconds since boot
#   B   cpu_pct         0..100
#   B   mem_pct         0..100
#   B   eth_up          0/1
#   b   wifi_rssi       dBm, signed (-127..0); 0 means "no Wi-Fi"
#   xxx reserved        3 bytes (set to 0)
# ──────────────────────────────────────────────────────────────────────────────
_MODEL_TO_BYTE = {'l4': 1, 'm1': 2, 'hmi1': 3}


def _detect_model_byte() -> int:
    """Best-effort controller-model detection from the device tree."""
    for path in ('/sys/firmware/devicetree/base/platform',
                 '/sys/firmware/devicetree/base/model'):
        try:
            with open(path, 'rb') as fh:
                raw = fh.read().decode('ascii', errors='ignore').strip('\x00').lower()
            for key, val in _MODEL_TO_BYTE.items():
                if key in raw:
                    return val
        except OSError:
            continue
    return 0


def _read_uptime_s() -> int:
    try:
        with open('/proc/uptime', 'r') as fh:
            return int(float(fh.read().split()[0]))
    except OSError:
        return 0


def _read_mem_pct() -> int:
    try:
        info = {}
        with open('/proc/meminfo', 'r') as fh:
            for line in fh:
                k, _, v = line.partition(':')
                info[k] = int(v.strip().split()[0])
        total = info.get('MemTotal', 0)
        avail = info.get('MemAvailable', 0)
        if total <= 0:
            return 0
        return max(0, min(100, int(round((total - avail) * 100 / total))))
    except OSError:
        return 0


def _read_cpu_pct() -> int:
    """Differential CPU usage between two consecutive telemetry ticks."""
    global _cpu_prev_idle, _cpu_prev_total
    try:
        with open('/proc/stat', 'r') as fh:
            parts = fh.readline().split()
        # parts[0] == 'cpu', then user nice system idle iowait irq softirq …
        nums = [int(p) for p in parts[1:8]]
        idle = nums[3] + nums[4]                    # idle + iowait
        total = sum(nums)
        d_idle = idle - _cpu_prev_idle
        d_total = total - _cpu_prev_total
        _cpu_prev_idle, _cpu_prev_total = idle, total
        if d_total <= 0:
            return 0
        return max(0, min(100, int(round((d_total - d_idle) * 100 / d_total))))
    except OSError:
        return 0


def _read_eth_up() -> int:
    for iface in ('end0', 'eth0'):
        try:
            with open(f'/sys/class/net/{iface}/operstate', 'r') as fh:
                if fh.read().strip() == 'up':
                    return 1
        except OSError:
            continue
    return 0


def _read_wifi_rssi() -> int:
    """Read /proc/net/wireless link-quality column 3 (signal level dBm)."""
    try:
        with open('/proc/net/wireless', 'r') as fh:
            lines = fh.readlines()
        for line in lines[2:]:
            cols = line.split()
            if len(cols) >= 4:
                # cols[3] is signal level, may have a trailing '.'
                rssi = int(float(cols[3].rstrip('.')))
                return max(-127, min(0, rssi))
    except (OSError, ValueError):
        pass
    return 0


def _pack_telemetry() -> list:
    payload = struct.pack(
        '<BIIBBBbxxx',
        _detect_model_byte(),
        zlib.crc32(socket.gethostname().encode('utf-8')) & 0xFFFFFFFF,
        _read_uptime_s() & 0xFFFFFFFF,
        _read_cpu_pct(),
        _read_mem_pct(),
        _read_eth_up(),
        _read_wifi_rssi(),
    )
    return list(payload)


def _telemetry_tick() -> bool:
    if _telemetry_char is not None and _telemetry_char.is_notifying:
        _telemetry_char.set_value(_pack_telemetry())
    return True


def cb_telemetry_read():
    return _pack_telemetry()


def cb_telemetry_notify(notifying: bool, characteristic) -> None:
    global _telemetry_char
    _telemetry_char = characteristic
    logger.info('Telemetry notifications %s', 'ON' if notifying else 'OFF')


# ──────────────────────────────────────────────────────────────────────────────
# Connect / disconnect — log only; bluezero handles all the link-layer plumbing
# ──────────────────────────────────────────────────────────────────────────────
def on_connect(device) -> None:
    logger.info('Connected: %s', device)


def on_disconnect(device) -> None:
    global _session_active
    _session_active = False
    logger.info('Disconnected: %s', device)


# ──────────────────────────────────────────────────────────────────────────────
# Logging — console + rotating file at /var/log/go_bt.log
# ──────────────────────────────────────────────────────────────────────────────
def _setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        fh = RotatingFileHandler('/var/log/go_bt.log',
                                 maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except PermissionError:
        logger.warning('Cannot open /var/log/go_bt.log — logging to console only')


# ──────────────────────────────────────────────────────────────────────────────
# Main — Twilight-Flow advertising pattern: NO LocalName, only Service UUID
# in the primary 31-byte advertisement. iOS scans on the service UUID
# directly, so the controller is invisible to Settings → Bluetooth and to
# generic BLE scanners but immediately discoverable to our app.
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    _setup_logging()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    adapters = list(adapter.Adapter.available())
    if not adapters:
        raise RuntimeError('No Bluetooth adapter found')
    dongle_address = adapters[0].address
    logger.info('Adapter: %s', dongle_address)

    _set_kernel_adv_defaults()

    ble = peripheral.Peripheral(dongle_address)
    ble.on_connect = on_connect
    ble.on_disconnect = on_disconnect

    # Note: bluezero v0.9.1 doesn't expose MinInterval/MaxInterval on its
    # Advertisement object, so BlueZ' MGMT layer forwards 0x0000 for both
    # to the kernel and the kernel resolves to its `adv_min_interval` /
    # `adv_max_interval` debugfs values. We set those above.
    #
    # An earlier attempt subclassed bluezero's Advertisement to expose
    # MinInterval/MaxInterval directly, but that triggered
    # "Add Extended Advertising Data: Invalid Parameters (0x0d)" on this
    # BlueZ 5.82 build (likely an experimental-features gate). The kernel
    # debugfs path achieves the same effective rate without that gate.

    ble.add_service(srv_id=1, uuid=SERVICE_UUID, primary=True)

    ble.add_characteristic(
        srv_id=1, chr_id=1, uuid=HEARTBEAT_UUID,
        value=[0], notifying=False,
        flags=['read', 'notify'],
        read_callback=cb_heartbeat_read,
        notify_callback=cb_heartbeat_notify,
    )

    ble.add_characteristic(
        srv_id=1, chr_id=2, uuid=CONTROL_UUID,
        value=[], notifying=False,
        flags=['write', 'write-without-response'],
        write_callback=cb_control_write,
    )

    ble.add_characteristic(
        srv_id=1, chr_id=3, uuid=TELEMETRY_UUID,
        value=[0] * 16, notifying=False,
        flags=['read', 'notify'],
        read_callback=cb_telemetry_read,
        notify_callback=cb_telemetry_notify,
    )

    async_tools.add_timer_ms(HEARTBEAT_INTERVAL_MS, _heartbeat_tick)
    async_tools.add_timer_seconds(TELEMETRY_INTERVAL_S, _telemetry_tick)
    async_tools.add_timer_seconds(1, _watchdog)

    _register_agent()
    _disable_pairing()

    logger.info('go-bt server starting (no LocalName, UUID-only advertising)')
    logger.info('  Service:    %s', SERVICE_UUID)
    logger.info('  Heartbeat:  %s  [read, notify] @ %d ms', HEARTBEAT_UUID, HEARTBEAT_INTERVAL_MS)
    logger.info('  Control:    %s  [write, w/o-r]', CONTROL_UUID)
    logger.info('  Telemetry:  %s  [read, notify] @ %d s', TELEMETRY_UUID, TELEMETRY_INTERVAL_S)
    ble.publish()


if __name__ == '__main__':
    main()
