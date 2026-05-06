#!/usr/bin/env python3
"""
go-bt — BLE GATT server for GOcontroll Linux controllers (L4 / M1 / HMI1).

Phase 1 — hybrid model:
    Bootstrap-laag (NIET aanraken; bewezen stabiel sinds Sep 2025):
        Heartbeat   …30  notify 1 B   proof-of-life + iOS-side watchdog
        Identity    …33  read   6 B   end0 Ethernet MAC voor pairing
        SystemInfo  …34  read   JSON  hostname/model/serial/...

    RPC-laag (UUIDs blijven; payload-betekenis verandert):
        Request     …31  write       chunked  {id, cmd, params?}
        Response    …32  notify      chunked  {id, ok, data?} of {event, data}

    Frame format (per BLE write/notify):
        byte 0 : seq  (0-based, uint8)
        byte 1 : total (count of frames in this message, uint8 > 0)
        2..    : utf-8 JSON fragment

    Phase-1 commands (all read-only, no auth):
        system.stats   → {cpu, temp_c, mem_pct, uptime_s}
        modules.info   → {slots: [{slot, type, hw_version, fw_version, empty}]}
        network.info   → {ethernet:{...}, wifi:{...}, wwan:{...}}
        can.info       → {interfaces:[{id,present,up,kbps}], load:{canX:pct}}

Backwards-compat met oude iOS-app: de OUDE app schrijft 4-byte keepalive naar
Control en abonneert NIET op Telemetry. Beide cases zijn benign — onze
RPC-reassembler verwerpt ongeldige frames stilzwijgend en de oude app ziet
alleen Heartbeat, Identity en SystemInfo (precies zoals nu).

Run:
    sudo /usr/bin/python3 /opt/gocontroll/go-bt/ble_server.py
"""

import hashlib
import json
import logging
import os
import re
import socket
import struct
import subprocess
import time
import zlib
from collections import deque
from logging.handlers import RotatingFileHandler

import dbus
import dbus.service
import dbus.mainloop.glib
from bluezero import adapter, advertisement, async_tools, constants, peripheral
from gi.repository import GLib

# ──────────────────────────────────────────────────────────────────────────────
# UUIDs — kept identical to the Linux mgmt service the iOS app already knows
# ──────────────────────────────────────────────────────────────────────────────
SERVICE_UUID     = '4E2C7A1B-F3D5-4890-B6C8-2A9E0F7D3C5B'
HEARTBEAT_UUID   = '4E2C7A30-F3D5-4890-B6C8-2A9E0F7D3C5B'
REQUEST_UUID     = '4E2C7A31-F3D5-4890-B6C8-2A9E0F7D3C5B'   # was CONTROL
RESPONSE_UUID    = '4E2C7A32-F3D5-4890-B6C8-2A9E0F7D3C5B'   # was TELEMETRY
IDENTITY_UUID    = '4E2C7A33-F3D5-4890-B6C8-2A9E0F7D3C5B'
SYSTEM_INFO_UUID = '4E2C7A34-F3D5-4890-B6C8-2A9E0F7D3C5B'

HEARTBEAT_INTERVAL_MS = 1000
WATCHDOG_TIMEOUT_S    = 5.0   # iOS heartbeat-write watchdog (informational)

# RPC chunk size — chosen well below the smallest MTU iOS will negotiate
# (185 = effective 182 ATT payload; minus 2 header bytes leaves 180).
# Spreid frames met TX_INTERVAL_MS tussen elke notify zodat BlueZ ze als
# losse PropertiesChanged signals door kan zetten.
RPC_MAX_PAYLOAD = 180
RPC_TX_INTERVAL_MS = 15

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

# Manufacturer Specific Data — 16-bit company ID, payload broadcast in scan
# response. 0xFFFF is the BLE SIG "test/proprietary" range; safe for our use
# until we register an official company ID. The payload is intentionally
# compact so it fits next to the 128-bit Service UUID without crowding the
# primary advertising packet (BlueZ moves it into the scan response).
#
#   payload[0]   version    uint8   currently 0x01
#   payload[1]   model      uint8   1=L4, 2=M1, 3=HMI1, 0=unknown
#   payload[2]   serial_len uint8   N in bytes (≤ 28 to keep the ad legal)
#   payload[3..] serial     ASCII   `go-sn r` output (e.g. "B1AL-B055-B001-A002")
MFG_COMPANY_ID    = 0xFFFF
MFG_PAYLOAD_VERSION = 0x01

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Globals — written by GLib timers and BlueZ callbacks (single-threaded mainloop)
# ──────────────────────────────────────────────────────────────────────────────
_heartbeat_counter: int = 0
_heartbeat_char = None
_response_char = None      # the …32 characteristic — RPC notify channel

_last_control_ts: float = 0.0
_session_active:  bool  = False

# Cached telemetry inputs (kept for system.stats handler)
_cpu_prev_idle:  int = 0
_cpu_prev_total: int = 0

# CAN busload differential state (per-iface deltas across system.stats / can.info)
_can_load_state: dict = {}     # ifc -> {"t": monotonic, "p": packets, "b": bytes}
_can_bitrate_cache: dict = {}  # ifc -> (cached_at_monotonic, bitrate_bps)
_CAN_BITRATE_TTL_S = 30.0

# RPC reassembly state (server-side rx) — frames van de iPhone
_rx_buf:   bytearray = bytearray()
_rx_total: int = 0
_rx_seq:   int = 0   # last seq received (-1 means waiting for seq=0)

# RPC tx queue — frames die naar de iPhone moeten. Eén GLib idle pump verstuurt
# één frame per RPC_TX_INTERVAL_MS; dat geeft BlueZ tijd om elke set_value als
# een losse PropertiesChanged signal door te zetten.
_tx_queue: deque = deque()
_tx_pumping: bool = False

# Reference naar de bluezero Peripheral, gezet in main() zodat on_disconnect
# de LEAdvertisement1 instance opnieuw kan registreren. Op de Murata 1YN-chip
# in de M1 dropt de controller de adv-instance na een central-disconnect en
# hervat 'm niet automatisch — zonder re-register is het apparaat na de
# eerste connect-cycle "verdwenen" voor latere scans tot de service herstart.
_peripheral = None

# Per-session auth flag. Geset door cb_request_write zodra `auth.login` met
# een geldige hash binnenkomt; gewist op disconnect. Write-commando's
# (services.set, ethernet.*, wifi.* met set, can.set_bitrate) checken deze
# vlag; read-commando's en de bootstrap-laag staan altijd open.
_session_authenticated: bool = False

CONF_PATH = '/etc/go_bluetooth.conf'


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
# RPC — chunked JSON over Request (write) + Response (notify)
# ──────────────────────────────────────────────────────────────────────────────
#
# Wire frame (per BLE write or notify):
#   byte 0 : seq   (0-based, uint8)
#   byte 1 : total (>0, uint8)
#   2..    : utf-8 JSON fragment
#
# Een complete bericht is de concatenatie van `total` opeenvolgende frames.
# Server stuurt één bericht volledig voordat het volgende begint (atomic),
# zodat iOS' assembler nooit chunks van twee berichten hoeft te multiplexen.
#
# Envelope (na herassemblage):
#   request : {"id": <int>, "cmd": "<ns>.<verb>", "params": {...optional...}}
#   response: {"id": <int>, "ok": true,  "data": {...}}
#             {"id": <int>, "ok": false, "error": "<msg>"}
#   event   : {"event": "<name>", "data": {...}}     # geen id — push only
#
# De `id` is door de client gekozen en uniek genoeg (uint32 wraparound is OK
# zolang er nooit twee in-flight zijn met dezelfde id; iOS-kant garandeert dit).

def _reset_rx() -> None:
    global _rx_buf, _rx_total, _rx_seq
    _rx_buf = bytearray()
    _rx_total = 0
    _rx_seq = 0


def cb_request_write(value, options) -> None:
    """RPC request frame uit iOS — herassembleer en dispatch zodra compleet."""
    global _last_control_ts, _session_active, _rx_buf, _rx_total, _rx_seq
    raw = bytes(value)
    if len(raw) < 2:
        return
    seq = raw[0]
    total = raw[1]
    payload = raw[2:]

    # Heartbeat: een geldig RPC-frame telt ook als levensteken.
    _last_control_ts = time.monotonic()
    if not _session_active:
        logger.info('RPC: session opened (first request frame)')
        _session_active = True

    if total == 0:
        return

    if seq == 0:
        _rx_buf = bytearray(payload)
        _rx_total = total
        _rx_seq = 0
    elif seq == _rx_seq + 1 and total == _rx_total:
        _rx_buf.extend(payload)
        _rx_seq = seq
    else:
        # Out-of-order of stale fragment — discard alles, wacht op nieuw seq=0.
        logger.warning('RPC: dropped frame (seq=%d total=%d, expected next=%d/%d)',
                       seq, total, _rx_seq + 1, _rx_total)
        _reset_rx()
        return

    if _rx_seq != _rx_total - 1:
        return  # nog niet compleet

    raw_json = bytes(_rx_buf)
    _reset_rx()
    try:
        req = json.loads(raw_json.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning('RPC: bad request JSON (%d B): %s', len(raw_json), exc)
        return

    if not isinstance(req, dict):
        logger.warning('RPC: request not an object: %r', req)
        return

    req_id = req.get('id')
    cmd = req.get('cmd')
    params = req.get('params') or {}
    if not isinstance(cmd, str):
        logger.warning('RPC: missing/invalid cmd in request id=%r', req_id)
        return

    logger.info('RPC ← id=%s cmd=%s params=%s', req_id, cmd, params)
    _dispatch_request(req_id, cmd, params)


def _dispatch_request(req_id, cmd: str, params: dict) -> None:
    handler = _HANDLERS.get(cmd)
    if handler is None:
        _send_response(req_id, ok=False, error=f'unknown cmd: {cmd}')
        return
    try:
        data = handler(params)
        _send_response(req_id, ok=True, data=data)
    except Exception as exc:
        logger.exception('RPC: handler %s raised', cmd)
        _send_response(req_id, ok=False, error=f'{type(exc).__name__}: {exc}')


def _send_response(req_id, ok: bool, data=None, error: str = None) -> None:
    msg = {'id': req_id, 'ok': bool(ok)}
    if ok and data is not None:
        msg['data'] = data
    if not ok and error is not None:
        msg['error'] = error
    _enqueue_tx(msg)


def _send_event(event: str, data=None) -> None:
    msg = {'event': event}
    if data is not None:
        msg['data'] = data
    _enqueue_tx(msg)


def _enqueue_tx(obj) -> None:
    try:
        raw = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    except (TypeError, ValueError) as exc:
        logger.exception('RPC: cannot serialise outbound message: %s', exc)
        return

    n = len(raw)
    chunks = [raw[i:i + RPC_MAX_PAYLOAD] for i in range(0, n, RPC_MAX_PAYLOAD)] or [b'']
    total = len(chunks)
    if total > 255:
        logger.error('RPC: response too large (%d B → %d chunks); dropping', n, total)
        return

    label = obj.get('event') or f"id={obj.get('id')}"
    logger.info('RPC → %s ok=%s bytes=%d chunks=%d',
                label, obj.get('ok', '-'), n, total)

    for seq, chunk in enumerate(chunks):
        _tx_queue.append((seq, total, chunk))
    _kick_tx_pump()


def _kick_tx_pump() -> None:
    global _tx_pumping
    if _tx_pumping or not _tx_queue:
        return
    _tx_pumping = True
    GLib.idle_add(_pump_tx_once)


def _pump_tx_once() -> bool:
    """Stuur één frame en plan het volgende met een korte spacer."""
    global _tx_pumping
    if not _tx_queue:
        _tx_pumping = False
        return False  # remove

    if _response_char is None or not _response_char.is_notifying:
        # Geen subscriber — laat berichten vervallen i.p.v. eindeloos te bufferen.
        dropped = len(_tx_queue)
        _tx_queue.clear()
        _tx_pumping = False
        if dropped:
            logger.info('RPC: response char not notifying — dropped %d queued frames',
                        dropped)
        return False

    seq, total, chunk = _tx_queue.popleft()
    frame = bytes([seq, total]) + chunk
    try:
        _response_char.set_value(list(frame))
    except Exception as exc:
        logger.warning('RPC: notify set_value failed (seq=%d/%d): %s',
                       seq, total, exc)

    if _tx_queue:
        GLib.timeout_add(RPC_TX_INTERVAL_MS, _pump_tx_once)
    else:
        _tx_pumping = False
    return False  # always one-shot; reschedule via timeout/idle above


# ──────────────────────────────────────────────────────────────────────────────
# Watchdog — 1 Hz; logs once when the iPhone heartbeat / RPC traffic stops.
# Phase-1 effect: alleen log + close session marker. Volgende fases kunnen
# RPC-state opruimen en een central-disconnect forceren.
# ──────────────────────────────────────────────────────────────────────────────
def _watchdog() -> bool:
    global _session_active
    if not _session_active:
        return True
    elapsed = time.monotonic() - _last_control_ts
    if elapsed > WATCHDOG_TIMEOUT_S:
        logger.warning('Watchdog: no Request write for %.1fs — session lost', elapsed)
        _session_active = False
        _reset_rx()
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Data-collection helpers — gedeeld tussen system.stats / network.info / can.info
# ──────────────────────────────────────────────────────────────────────────────
_MODEL_TO_BYTE = {'L4': 1, 'M1': 2, 'HMI1': 3}


def _detect_model_name() -> str:
    """Return the canonical short model name (M1 / L4 / HMI1) extracted from
    the device-tree platform string, or an empty string if not detected.

    Token-based matching — substring matching is a trap: "M1" appears inside
    "HMI1", so an `'m1' in raw` check would mis-identify an HMI1 as M1.
    """
    for path in ('/sys/firmware/devicetree/base/platform',
                 '/sys/firmware/devicetree/base/model'):
        try:
            with open(path, 'rb') as fh:
                raw = fh.read().decode('ascii', errors='ignore').strip('\x00 \t\n\r')
            for token in raw.upper().split():
                if token in _MODEL_TO_BYTE:
                    return token
        except OSError:
            continue
    return ''


def _detect_model_byte() -> int:
    """Stage-1 telemetry encoding: 0=unknown, 1=L4, 2=M1, 3=HMI1."""
    return _MODEL_TO_BYTE.get(_detect_model_name(), 0)


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


def _build_mfg_payload() -> bytes:
    """Compact identification blob — fixed 6-byte layout to fit the legacy
    31-byte BLE advertising packet alongside our 128-bit Service UUID.

    Layout:
        byte 0      version       UInt8 — currently 0x01
        byte 1      model         UInt8 — 1=L4, 2=M1, 3=HMI1, 0=unknown
        bytes 2..5  serial_tail   ASCII — last 4 chars of `go-sn r`,
                                   left-padded with 0x00 if shorter

    Why only the tail: BlueZ 5.82 on the Broadcom chip rejects
    "Add Extended Advertising Parameters" with Invalid Parameters (0x0d) the
    moment the AD set exceeds 31 B, which silently kills advertising. Full
    serial fits comfortably in the SystemInfo characteristic post-connect;
    pre-connect we only need enough to disambiguate a fleet on the bench.
    """
    model_byte = _detect_model_byte()
    serial = _run_capture(['go-sn', 'r']).strip()
    serial_bytes = serial.encode('ascii', errors='ignore')
    if len(serial_bytes) >= 4:
        tail = serial_bytes[-4:]
    else:
        tail = b'\x00' * (4 - len(serial_bytes)) + serial_bytes
    payload = bytearray()
    payload.append(MFG_PAYLOAD_VERSION)
    payload.append(model_byte)
    payload.extend(tail)
    return bytes(payload)


def _read_temp_c() -> "float | None":
    """CPU/SoC temperatuur in °C uit het eerste leesbare thermal_zone."""
    try:
        zones = sorted(p for p in os.listdir('/sys/class/thermal')
                       if p.startswith('thermal_zone'))
    except OSError:
        return None
    for zone in zones:
        try:
            with open(f'/sys/class/thermal/{zone}/temp', 'r') as fh:
                milli = int(fh.read().strip())
            if milli > 0:
                return round(milli / 1000.0, 1)
        except (OSError, ValueError):
            continue
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Response characteristic — Pi → iPhone, RPC notify channel.
# Geen periodieke push in fase 1; alle traffic is request-driven.
# ──────────────────────────────────────────────────────────────────────────────
def cb_response_read(options=None):
    """ATT Read voor RESPONSE: leveren een lege payload op. iOS leest dit nooit
    — alle berichten komen via Notify — maar BlueZ vereist een read_callback
    voor characteristics die [read, notify] flags hebben. We accepteren
    `options` zodat bluezero ook een eventuele BLOB-read keurig dispatched."""
    return []


def _read_offset(options) -> int:
    """Extract the `offset` integer from a BlueZ ReadValue options dict.
    bluezero converts D-Bus types to plain Python before invoking us, so the
    dict (when present) is straight `{'offset': int, 'mtu': int, ...}`. Always
    returns a non-negative int; falls back to 0 on missing/invalid input."""
    if not options:
        return 0
    raw = options.get('offset')
    if raw is None:
        return 0
    try:
        v = int(raw)
        return v if v >= 0 else 0
    except (TypeError, ValueError):
        return 0


def cb_response_notify(notifying: bool, characteristic) -> None:
    global _response_char
    _response_char = characteristic
    logger.info('Response notifications %s', 'ON' if notifying else 'OFF')
    if not notifying:
        # Geen subscriber meer — gooi pending tx-frames weg zodat ze niet later
        # de eerste response van een nieuwe sessie corrumperen.
        if _tx_queue:
            logger.info('RPC: notify OFF — dropping %d queued tx frames',
                        len(_tx_queue))
            _tx_queue.clear()
        _reset_rx()


# ──────────────────────────────────────────────────────────────────────────────
# Identity — Pi → iPhone, read-only, 6 bytes raw MAC of the Ethernet interface.
# Used by the iOS app to verify the controller against a QR-scanned MAC at
# pairing time. Plain read (no notify): the MAC never changes during a session,
# so a single ATT Read on connect is sufficient.
# ──────────────────────────────────────────────────────────────────────────────
def _read_identity_mac() -> bytes:
    """Return the 6-byte Ethernet MAC of end0 (or eth0 fallback). All zeros if
    neither interface has a readable address."""
    for iface in ('end0', 'eth0'):
        try:
            with open(f'/sys/class/net/{iface}/address', 'r') as fh:
                mac_str = fh.read().strip()
            parts = mac_str.split(':')
            if len(parts) == 6:
                return bytes(int(p, 16) for p in parts)
        except (OSError, ValueError):
            continue
    return bytes(6)


def cb_identity_read(options=None):
    """6 bytes — passes in one MTU. Honour `options['offset']` for safety
    even though iOS will never need a BLOB read here."""
    mac = _read_identity_mac()
    offset = _read_offset(options)
    chunk = mac[offset:]
    if offset == 0:
        logger.info('Identity read → %s', mac.hex(':'))
    else:
        logger.info('Identity read offset=%d → %d B', offset, len(chunk))
    return list(chunk)


# ──────────────────────────────────────────────────────────────────────────────
# SystemInfo — Pi → iPhone, read-only, JSON. Mirrors the canonical sources
# go-web-ui already exposes over its /api/get_* HTTP endpoints, so the BLE
# client and the local web UI render the same fields from the same files.
#
# Sources:
#   model        device-tree /platform token (M1 / L4 / HMI1)
#   hostname     socket.gethostname()
#   hw_revision  /sys/firmware/devicetree/base/hardware
#   kernel       `uname -rs`
#   rootfs       /etc/image-info — composed display string
#   serial       `go-sn r`
#
# Plain Read (no notify) — these fields are static for the lifetime of the
# session, so a single ATT Read post-discovery is enough. iOS / BlueZ handle
# ATT_READ_BLOB chunking transparently if the JSON exceeds the negotiated MTU.
# ──────────────────────────────────────────────────────────────────────────────
def _read_text_file(path: str) -> str:
    try:
        with open(path, 'r') as fh:
            return fh.read().strip('\x00 \t\n\r')
    except OSError:
        return ''


def _read_image_info() -> dict:
    """Parse /etc/image-info (shell-style KEY="VALUE" lines)."""
    info = {}
    try:
        with open('/etc/image-info', 'r') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, val = line.partition('=')
                info[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return info


def _run_capture(cmd: list, timeout: float = 2.0) -> str:
    """Run a short subprocess and return stripped stdout, or '' on any failure."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
            text=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, OSError):
        return ''


_DEBIAN_CODENAMES = {
    'sid', 'trixie', 'bookworm', 'bullseye', 'buster', 'stretch', 'jessie',
}
_ARCH_DISPLAY = {
    'arm64': 'ARM 64',
    'armhf': 'ARM HF',
    'armel': 'ARM EL',
    'amd64': 'AMD 64',
    'i386':  'i386',
}


def _build_rootfs_summary() -> str:
    """Human-readable rootfs label derived from /etc/image-info IMAGE_ROOTFS.

    Examples:
        'trixie-arm64'   → 'Debian Trixie ARM 64'
        'bookworm-arm64' → 'Debian Bookworm ARM 64'
        'foo-bar'        → 'foo-bar'   (raw fallback for unknown codenames)

    Drops the IMAGE_VARIANT and IMAGE_BUILD_SHA fields the iOS app used to
    show — those weren't useful in the user-facing Overview tab.
    """
    name = _read_image_info().get('IMAGE_ROOTFS', '').strip()
    if not name:
        return ''
    codename, _, arch = name.partition('-')
    if codename.lower() not in _DEBIAN_CODENAMES:
        return name
    arch_disp = _ARCH_DISPLAY.get(arch.lower(), arch.upper())
    return f'Debian {codename.capitalize()} {arch_disp}'.strip()


def _read_system_info_json() -> bytes:
    payload = {
        'model':         _detect_model_name() or 'unknown',
        'hostname':      socket.gethostname(),
        'hw_revision':   _read_text_file('/sys/firmware/devicetree/base/hardware'),
        'kernel':        _run_capture(['uname', '-rs']),
        'rootfs':        _build_rootfs_summary(),
        'serial_number': _run_capture(['go-sn', 'r']),
    }
    return json.dumps(payload).encode('utf-8')


def cb_system_info_read(options=None):
    """Returns the JSON sliced from `options['offset']` so iOS' long-read flow
    (ATT_READ_BLOB) gets correct data. Without slicing, every BLOB request
    re-reads bytes 0..N which corrupts the assembled value on the central."""
    js = _read_system_info_json()
    offset = _read_offset(options)
    chunk = js[offset:]
    if offset == 0:
        logger.info('SystemInfo read → %d B: %s', len(js), js.decode('utf-8', errors='replace'))
    else:
        logger.info('SystemInfo read offset=%d → %d B', offset, len(chunk))
    return list(chunk)


# ──────────────────────────────────────────────────────────────────────────────
# RPC handlers — fase 1 (alleen reads). Elke handler krijgt het params-dict
# (mag {} zijn) en levert het `data`-veld van de respons. Exceptions worden
# opgevangen door de dispatcher en als {ok:false, error:...} doorgestuurd.
# ──────────────────────────────────────────────────────────────────────────────

def _run_capture_argv(argv: list, timeout: float = 3.0) -> str:
    """Compat-wrapper: gebruik bestaande _run_capture maar accepteer argv-list."""
    return _run_capture(argv, timeout=timeout)


# --- modules.info ------------------------------------------------------------

_MODULES_JSON_PATH = '/lib/firmware/gocontroll/modules.json'

def _parse_module_firmware(fw_str: str) -> "dict | None":
    """Parse '20-20-2-6-2-2-0' → dict {type, hw_version, fw_version}.

    Format (per identify v2.2.3):
      tokens[0] = manufacturer prefix (altijd 20)
      tokens[1] = type group (10=input, 20=output, 30=comm, 40=ANLEG)
      tokens[2] = type id within group
      tokens[3] = HW minor (HW major altijd 1)
      tokens[4..6] = SW major.minor.patch

    iOS' BLEManager.moduleName(for:) doet `articleNumber / 100` en zoekt op de
    6-digit base (e.g. 202002). De wire-encoding is daarom de 8-cijferige
    samenvoeging article*100+hw → "20200206" → /100 = 202002 → "6 Channel
    Output Module" in de iOS-lookup.
    """
    if not fw_str:
        return None
    parts = fw_str.split('-')
    if len(parts) < 7:
        return None
    try:
        mfr        = int(parts[0])
        type_group = int(parts[1])
        type_id    = int(parts[2])
        hw_minor   = int(parts[3])
        sw_major   = int(parts[4])
        sw_minor   = int(parts[5])
        sw_patch   = int(parts[6])
    except ValueError:
        return None
    article = mfr * 10000 + type_group * 100 + type_id   # bv. 20*10000+20*100+2 = 202002
    type_field = f'{article * 100 + hw_minor:08d}'        # "20200206"
    return {
        'type': type_field,
        'hw_version': f'v1.{hw_minor}',
        'fw_version': f'{sw_major}.{sw_minor}.{sw_patch}',
    }


def _handler_modules_info(_params: dict) -> dict:
    try:
        with open(_MODULES_JSON_PATH, 'r') as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return {'slots': []}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f'cannot read modules.json: {exc}')

    slots = []
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            slot = entry.get('slot')
            if not isinstance(slot, int) or slot < 1:
                continue
            fw_str = entry.get('firmware', '') or ''
            parsed = _parse_module_firmware(fw_str)
            # Pass-through identification fields straight from modules.json
            # (written by `go-modules scan`). The QR codes are the printed
            # numbers on the module's physical labels — useful for the
            # iOS "tap a slot" detail view to identify a specific
            # physical module without pulling the controller open.
            manufacturer = entry.get('manufacturer')
            qr_front = entry.get('qr_front')
            qr_back = entry.get('qr_back')
            if parsed is None:
                slots.append({'slot': slot, 'empty': True})
            else:
                row = {
                    'slot': slot,
                    'type': parsed['type'],
                    'hw_version': parsed['hw_version'],
                    'fw_version': parsed['fw_version'],
                    'empty': False,
                }
                if isinstance(manufacturer, int):
                    row['manufacturer'] = manufacturer
                if isinstance(qr_front, int) and qr_front > 0:
                    row['qr_front'] = qr_front
                if isinstance(qr_back, int) and qr_back > 0:
                    row['qr_back'] = qr_back
                slots.append(row)
    slots.sort(key=lambda s: s['slot'])
    return {'slots': slots}


# --- system.stats ------------------------------------------------------------

def _handler_system_stats(_params: dict) -> dict:
    return {
        'cpu':       _read_cpu_pct(),
        'temp_c':    _read_temp_c(),
        'mem_pct':   _read_mem_pct(),
        'uptime_s':  _read_uptime_s(),
    }


# --- network.info ------------------------------------------------------------

def _read_iface_ip(iface: str) -> "str | None":
    """Eerste IPv4 op interface, via `ip -j -4 addr show`."""
    out = _run_capture(['ip', '-j', '-4', 'addr', 'show', iface], timeout=2.0)
    if not out:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list) or not data:
        return None
    addrs = data[0].get('addr_info') or []
    for a in addrs:
        if a.get('family') == 'inet' and a.get('local'):
            return a['local']
    return None


def _read_iface_mac(iface: str) -> "str | None":
    try:
        with open(f'/sys/class/net/{iface}/address', 'r') as fh:
            mac = fh.read().strip()
        return mac or None
    except OSError:
        return None


def _read_iface_operstate(iface: str) -> str:
    try:
        with open(f'/sys/class/net/{iface}/operstate', 'r') as fh:
            return fh.read().strip()
    except OSError:
        return 'unknown'


def _ethernet_info() -> dict:
    iface = 'end0' if os.path.exists('/sys/class/net/end0') else 'eth0'
    operstate = _read_iface_operstate(iface)
    info = {
        'iface':       iface,
        'mac':         _read_iface_mac(iface),
        'connected':   operstate == 'up',
        'current_ip':  _read_iface_ip(iface),
        'static_ip':   None,
        'mode':        None,
    }
    # nmcli connection-mode (auto vs static) — best effort
    out = _run_capture(['nmcli', '-t', '-f', 'NAME,DEVICE,STATE',
                        'con', 'show', '--active'], timeout=2.0)
    if out:
        for line in out.splitlines():
            cols = line.split(':')
            if len(cols) >= 2 and (cols[1] == iface or cols[1] == 'eth0'):
                name = cols[0].lower()
                if 'static' in name:
                    info['mode'] = 'static'
                elif 'auto' in name:
                    info['mode'] = 'auto'
                break
    # static IP profielwaarde (alleen tonen wanneer profiel bestaat)
    sout = _run_capture(['nmcli', '-t', '-f', 'ipv4.addresses',
                         'con', 'show', 'Wired connection static'], timeout=2.0)
    if sout:
        for line in sout.splitlines():
            if line.startswith('ipv4.addresses:'):
                val = line.split(':', 1)[1].strip()
                if val:
                    info['static_ip'] = val.split('/')[0]
                break
    return info


def _wifi_info() -> dict:
    info = {
        'enabled':         False,
        'mode':            'off',
        'connected':       False,
        'ip':              None,
        'ap_ssid':         None,
        'connected_ssid':  None,
    }
    out = _run_capture(['rfkill', '-J', '--output-all'], timeout=2.0)
    if out:
        try:
            data = json.loads(out)
            for dev in data.get('rfkilldevices', []):
                if dev.get('type') == 'wlan':
                    info['enabled'] = (dev.get('soft') == 'unblocked'
                                       and dev.get('hard') == 'unblocked')
                    break
        except json.JSONDecodeError:
            pass

    if not info['enabled']:
        return info

    # Actieve wifi-connectie?
    cout = _run_capture(['nmcli', '-t', '-f', 'NAME,DEVICE,TYPE,STATE',
                         'con', 'show', '--active'], timeout=2.0)
    if cout:
        for line in cout.splitlines():
            cols = line.split(':')
            if len(cols) >= 4 and cols[2].endswith('wireless'):
                ssid = cols[0]
                if ssid == 'GOcontroll-AP':
                    info['mode'] = 'ap'
                    info['ap_ssid'] = ssid
                else:
                    info['mode'] = 'client'
                    info['connected'] = True
                    info['connected_ssid'] = ssid
                dev = cols[1]
                if dev:
                    info['ip'] = _read_iface_ip(dev)
                break
    if info['mode'] == 'off':
        # Wifi aan, maar geen connectie — toch het wlan IP melden als er een is
        info['mode'] = 'client'
        for dev in ('wlan0', 'wlp0s1'):
            if os.path.exists(f'/sys/class/net/{dev}'):
                info['ip'] = _read_iface_ip(dev)
                break
    return info


def _wwan_info() -> dict:
    info = {
        'enabled':         False,
        'service_state':   'off',
        'imei':            None,
        'iccid':           None,
        'operator':        None,
        'ip':              None,
        'apn':             None,
        'model':           None,
        'signal_pct':      None,
    }
    # Service-status — als go-wwan inactief is, hoef je mmcli niet te bevragen.
    state = _run_capture(['systemctl', 'is-active', 'go-wwan'], timeout=2.0)
    info['enabled'] = (state == 'active')
    if not info['enabled']:
        return info

    ml = _run_capture(['mmcli', '-J', '--list-modems'], timeout=3.0)
    if not ml:
        info['service_state'] = 'searching'
        return info
    try:
        modems = json.loads(ml).get('modem-list', [])
    except json.JSONDecodeError:
        modems = []
    if not modems:
        info['service_state'] = 'searching'
        return info

    mout = _run_capture(['mmcli', '-J', '--modem=' + modems[0]], timeout=3.0)
    if not mout:
        return info
    try:
        m = json.loads(mout).get('modem', {}) or {}
    except json.JSONDecodeError:
        return info
    gen = m.get('generic', {}) or {}
    three = m.get('3gpp', {}) or {}
    sq = gen.get('signal-quality', {}) or {}

    def _clean(v):
        if v is None:
            return None
        s = str(v).strip()
        return None if s in ('', '--') else s

    info['model']         = _clean(gen.get('model'))
    info['service_state'] = _clean(gen.get('state')) or 'off'
    info['imei']          = _clean(three.get('imei'))
    info['operator']      = _clean(three.get('operator-name'))
    sig = sq.get('value') if isinstance(sq, dict) else sq
    if sig is not None:
        try:
            info['signal_pct'] = int(float(sig))
        except (TypeError, ValueError):
            pass

    # SIM ICCID
    sim_path = _clean(gen.get('sim'))
    if sim_path:
        sout = _run_capture(['mmcli', '-J', '-i', sim_path], timeout=3.0)
        if sout:
            try:
                sprops = json.loads(sout).get('sim', {}).get('properties', {}) or {}
                info['iccid'] = _clean(sprops.get('iccid'))
            except json.JSONDecodeError:
                pass

    # Bearer (APN, IPv4)
    bearers = gen.get('bearers', []) or []
    if bearers:
        bout = _run_capture(['mmcli', '-J', '-b', bearers[0]], timeout=3.0)
        if bout:
            try:
                b = json.loads(bout).get('bearer', {}) or {}
                bprops = b.get('properties', {}) or {}
                info['apn'] = _clean(bprops.get('apn'))
                v4 = b.get('ipv4-config', {}) or {}
                info['ip'] = _clean(v4.get('address'))
            except json.JSONDecodeError:
                pass
    return info


def _handler_network_info(_params: dict) -> dict:
    return {
        'ethernet': _ethernet_info(),
        'wifi':     _wifi_info(),
        'wwan':     _wwan_info(),
    }


# --- can.info ----------------------------------------------------------------

def _list_can_ifaces() -> list:
    try:
        return sorted(
            ifc for ifc in os.listdir('/sys/class/net')
            if ifc.startswith('can') and os.path.isdir(f'/sys/class/net/{ifc}/statistics')
        )
    except OSError:
        return []


def _ip_link_bitrate(ifc: str) -> int:
    out = _run_capture(['ip', '-j', '-d', 'link', 'show', ifc], timeout=2.0)
    if not out:
        return 0
    try:
        data = json.loads(out)
        return int(data[0]['linkinfo']['info_data']['bittiming']['bitrate'])
    except (json.JSONDecodeError, KeyError, IndexError, ValueError, TypeError):
        return 0


def _bitrate_for(ifc: str) -> int:
    now = time.monotonic()
    cached = _can_bitrate_cache.get(ifc)
    if cached and (now - cached[0]) < _CAN_BITRATE_TTL_S:
        return cached[1]
    bitrate = _ip_link_bitrate(ifc)
    _can_bitrate_cache[ifc] = (now, bitrate)
    return bitrate


def _can_counters(ifc: str) -> tuple:
    base = f'/sys/class/net/{ifc}/statistics'
    def _ri(p):
        try:
            with open(p, 'r') as fh:
                return int(fh.read().strip())
        except (OSError, ValueError):
            return 0
    p = _ri(f'{base}/rx_packets') + _ri(f'{base}/tx_packets')
    b = _ri(f'{base}/rx_bytes')   + _ri(f'{base}/tx_bytes')
    return p, b


def _handler_can_info(_params: dict) -> dict:
    ifaces_out = []
    load = {}
    now = time.monotonic()
    for ifc in _list_can_ifaces():
        # Identifier — laatste cijfer(s) van de iface-naam (can0, can1, …)
        m = re.match(r'^can(\d+)$', ifc)
        ident = int(m.group(1)) if m else 0

        operstate = _read_iface_operstate(ifc)
        kbps = _bitrate_for(ifc)
        ifaces_out.append({
            'id':       ident,
            'name':     ifc,
            'present':  True,
            'up':       operstate == 'up',
            'kbps':     int(kbps / 1000) if kbps > 0 else None,
        })

        # Busload — delta sinds vorige call. Eerste call seedt en geeft 0.
        p, b = _can_counters(ifc)
        prev = _can_load_state.get(ifc)
        pct = 0.0
        if prev is not None:
            dt = now - prev['t']
            dp = max(0, p - prev['p'])
            db = max(0, b - prev['b'])
            if dt > 0 and kbps > 0:
                bits = dp * 47 + db * 8   # CAN classic frame overhead approx
                pct = max(0.0, min(100.0, (bits / dt) / kbps * 100.0))
        _can_load_state[ifc] = {'t': now, 'p': p, 'b': b}
        load[ifc] = round(pct, 1)

    return {'interfaces': ifaces_out, 'load': load}


# --- services.list / services.set --------------------------------------------

# Whitelist mirrors go-web-ui's handlers/service.py with one substitution:
# `go-bluetooth` (the legacy RFCOMM server) is replaced by `go-bt` (this
# service). Including go-bt itself is a deliberate choice — disabling it
# from the iPhone obviously kills the RPC channel mid-response, so the
# iPhone times out and recovery requires SSH / webui / physical access.
# Users who toggle this know what they're doing.
_SERVICES_WHITELIST = (
    'ssh',
    'go-simulink',
    'nodered',
    'go-bt',
    'go-upload-server',
    'go-auto-shutdown',
    'gadget-getty@ttyGS0',
    'getty@ttymxc2',
    'go-webui',
)


def _systemctl_is_active(unit: str) -> bool:
    out = _run_capture(['systemctl', 'is-active', unit], timeout=2.0)
    return out == 'active'


def _systemctl_is_enabled(unit: str) -> bool:
    out = _run_capture(['systemctl', 'is-enabled', unit], timeout=2.0)
    return out in ('enabled', 'enabled-runtime', 'static', 'alias')


def _handler_services_list(_params: dict) -> dict:
    services = []
    for unit in _SERVICES_WHITELIST:
        services.append({
            'unit':    unit,
            'active':  _systemctl_is_active(unit),
            'enabled': _systemctl_is_enabled(unit),
        })
    return {'services': services}


def _systemctl_run(verb: str, unit: str) -> tuple:
    """Run `systemctl <verb> <unit>` and return (ok, error_msg).
    `verb` is restricted by the caller to the safe enable/disable/start/stop set."""
    try:
        result = subprocess.run(
            ['systemctl', verb, unit],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, text=True,
        )
    except subprocess.TimeoutExpired:
        return False, f'systemctl {verb} {unit}: timeout'
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip() or f'exit {result.returncode}'
        return False, msg
    return True, ''


def _handler_services_set(params: dict) -> dict:
    _require_auth()
    unit = params.get('unit')
    enable = params.get('enable')
    if not isinstance(unit, str) or unit not in _SERVICES_WHITELIST:
        raise ValueError(f'unit not in whitelist: {unit!r}')
    if not isinstance(enable, bool):
        raise ValueError('`enable` must be true or false')

    if enable:
        ok, err = _systemctl_run('enable', unit)
        if not ok:
            raise RuntimeError(err)
        ok, err = _systemctl_run('start', unit)
        if not ok:
            raise RuntimeError(err)
    else:
        ok, err = _systemctl_run('stop', unit)
        if not ok:
            raise RuntimeError(err)
        ok, err = _systemctl_run('disable', unit)
        if not ok:
            raise RuntimeError(err)

    return {
        'unit':    unit,
        'active':  _systemctl_is_active(unit),
        'enabled': _systemctl_is_enabled(unit),
    }


# --- ethernet.set_mode / ethernet.set_ip -------------------------------------

_ETH_PROFILE_AUTO   = 'Wired connection auto'
_ETH_PROFILE_STATIC = 'Wired connection static'


def _nmcli_run(*args, timeout: float = 10.0) -> tuple:
    """Run `nmcli ...` returning (ok, error_msg).
    Captures stderr properly so up/down failures surface as RPC errors."""
    cmd = ['nmcli'] + list(args)
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True,
        )
    except subprocess.TimeoutExpired:
        return False, f"nmcli {' '.join(args)}: timeout"
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip() or f'exit {result.returncode}'
        return False, msg
    return True, ''


def _handler_ethernet_set_mode(params: dict) -> dict:
    """Switch the wired interface between DHCP ('auto') and a static-IP
    profile ('static'). Mirrors the go-web-ui set_ethernet_mode pattern:
    flip autoconnect on the two NM profiles, then bring the right one up.

    Touching ethernet can drop a connected support tool — the BLE link
    itself is unaffected since it runs on a separate radio."""
    _require_auth()
    mode = params.get('mode')
    if mode not in ('auto', 'static'):
        raise ValueError("mode must be 'auto' or 'static'")

    if mode == 'static':
        keep, drop = _ETH_PROFILE_STATIC, _ETH_PROFILE_AUTO
    else:
        keep, drop = _ETH_PROFILE_AUTO, _ETH_PROFILE_STATIC

    # Flip autoconnect first so a future reboot honours the user's choice.
    _nmcli_run('con', 'mod', drop, 'connection.autoconnect', 'no', timeout=5.0)
    _nmcli_run('con', 'mod', keep, 'connection.autoconnect', 'yes', timeout=5.0)
    # Bring down the unused profile, then bring up the chosen one. NM
    # serialises these on the device so we don't race ourselves.
    _nmcli_run('con', 'down', drop, timeout=10.0)
    ok, err = _nmcli_run('con', 'up', keep, timeout=20.0)
    if not ok:
        raise RuntimeError(f"failed to activate '{keep}': {err}")
    return {'mode': mode}


def _handler_ethernet_set_ip(params: dict) -> dict:
    """Update the static-profile IPv4 address. Uses /16 to match the
    existing go-web-ui contract (controllers ship as DHCP servers on a
    /16 subnet for industrial deployments). The new address is applied
    immediately if the static profile is currently active; otherwise it
    sticks for the next activation."""
    _require_auth()
    ip = params.get('ip')
    if not isinstance(ip, str) or not ip:
        raise ValueError('`ip` is required')
    import ipaddress
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise ValueError(f'invalid IPv4 address: {exc}')

    ok, err = _nmcli_run(
        'con', 'mod', _ETH_PROFILE_STATIC, 'ipv4.addresses', f'{ip}/16',
        timeout=5.0,
    )
    if not ok:
        raise RuntimeError(f"failed to set static IP: {err}")

    state = _run_capture(
        ['nmcli', '-t', '-f', 'GENERAL.STATE', 'con', 'show', _ETH_PROFILE_STATIC],
        timeout=2.0,
    )
    if state and 'activated' in state:
        # Bounce the connection so the new IP takes effect now.
        _nmcli_run('con', 'down', _ETH_PROFILE_STATIC, timeout=5.0)
        ok, err = _nmcli_run('con', 'up', _ETH_PROFILE_STATIC, timeout=10.0)
        if not ok:
            raise RuntimeError(f"failed to re-activate static profile: {err}")
    return {'ip': ip}


# --- wifi.scan / wifi.set_mode / wifi.connect --------------------------------

_WIFI_AP_PROFILE = 'GOcontroll-AP'


def _wifi_scan_active() -> list:
    """Trigger nmcli rescan + return visible SSIDs with signal strength.

    `nmcli -t -f SSID,SIGNAL,SECURITY device wifi list --rescan yes` blocks
    on the rescan (which is what we want — the user pressed Scan and is
    waiting). De-duplicate by SSID, keep the strongest signal."""
    # Best-effort rescan trigger; ignore errors.
    _run_capture(['nmcli', 'device', 'wifi', 'rescan'], timeout=15.0)
    out = _run_capture(['nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY',
                        'device', 'wifi', 'list'], timeout=10.0)
    if not out:
        return []
    by_ssid = {}
    for line in out.splitlines():
        parts = line.split(':')
        if len(parts) < 2:
            continue
        ssid = parts[0]
        if not ssid:
            continue
        try:
            signal = int(parts[1])
        except ValueError:
            signal = 0
        security = parts[2] if len(parts) >= 3 else ''
        existing = by_ssid.get(ssid)
        if existing is None or signal > existing['signal']:
            by_ssid[ssid] = {
                'ssid':     ssid,
                'signal':   signal,
                'secured':  bool(security and security != '--'),
                'security': security,
            }
    return sorted(by_ssid.values(), key=lambda e: -e['signal'])


def _handler_wifi_scan(_params: dict) -> dict:
    return {'networks': _wifi_scan_active()}


def _handler_wifi_set_mode(params: dict) -> dict:
    """Switch between Access Point and Client. Mirrors go-web-ui's
    set_wifi_type — toggles the autoconnect flag on the AP profile vs the
    user's regular wifi connections, then brings the right one up."""
    _require_auth()
    mode = params.get('mode')
    if mode not in ('ap', 'client'):
        raise ValueError("mode must be 'ap' or 'client'")

    # Discover all wireless connections so we can flip their autoconnect.
    out = _run_capture(['nmcli', '-t', 'con'], timeout=3.0)
    wifi_cons = []
    if out:
        for line in out.splitlines():
            cols = line.split(':')
            if len(cols) >= 3 and cols[2].endswith('wireless') and cols[0] != _WIFI_AP_PROFILE:
                wifi_cons.append(cols[0])

    if mode == 'ap':
        for con in wifi_cons:
            _run_capture(['nmcli', 'con', 'mod', con,
                          'connection.autoconnect', 'no'], timeout=3.0)
        _run_capture(['nmcli', 'con', 'mod', _WIFI_AP_PROFILE,
                      'connection.autoconnect', 'yes'], timeout=3.0)
        ok, err = _systemctl_run('start', 'NetworkManager')   # no-op if running
        _run_capture(['nmcli', 'con', 'up', _WIFI_AP_PROFILE], timeout=10.0)
    else:  # client
        for con in wifi_cons:
            _run_capture(['nmcli', 'con', 'mod', con,
                          'connection.autoconnect', 'yes'], timeout=3.0)
        _run_capture(['nmcli', 'con', 'mod', _WIFI_AP_PROFILE,
                      'connection.autoconnect', 'no'], timeout=3.0)
        _run_capture(['nmcli', 'con', 'down', _WIFI_AP_PROFILE], timeout=5.0)

    return {'mode': mode}


def _handler_wifi_connect(params: dict) -> dict:
    """Connect to a WiFi network as a client. Creates / updates the nmcli
    connection profile and brings it up. Returns the resolved IP on success."""
    _require_auth()
    ssid = params.get('ssid')
    password = params.get('password', '')
    if not isinstance(ssid, str) or not ssid:
        raise ValueError('`ssid` is required')
    if not isinstance(password, str):
        raise ValueError('`password` must be a string (use "" for open networks)')

    cmd = ['nmcli', 'device', 'wifi', 'connect', ssid]
    if password:
        cmd += ['password', password]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, text=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'connect {ssid}: timeout')
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip() or f'exit {result.returncode}'
        raise RuntimeError(f'connect {ssid}: {msg}')

    # Probe the wifi info immediately so the iOS-side gets a fresh snapshot
    # in the same response, instead of waiting for the next refresh tick.
    info = _wifi_info()
    return {
        'ssid':       ssid,
        'connected':  bool(info.get('connected')),
        'ip':         info.get('ip'),
    }


# --- can.set_bitrate ---------------------------------------------------------

# Standard classic-CAN bitrates we accept. iOS' picker offers exactly these.
# Higher rates (CAN-FD) need a separate handler with sample-point + dbitrate.
_CAN_VALID_BITRATES = {125_000, 250_000, 500_000, 1_000_000}


def _handler_can_set_bitrate(params: dict) -> dict:
    """Reconfigure a CAN interface's bitrate via `go-can set <ifc> bitrate N`.

    go-can handles the down → reconfigure → up sequence transparently and
    persists the change to /etc/gocontroll/can.d/<ifc>.conf. Returns the
    post-change snapshot from the same code path can.info uses, so the
    sheet UI can update without an extra round-trip."""
    _require_auth()
    iface = params.get('interface')
    bitrate = params.get('bitrate')
    if not isinstance(iface, str) or not re.match(r'^can\d+$', iface):
        raise ValueError(f'invalid interface: {iface!r}')
    if not isinstance(bitrate, int) or bitrate not in _CAN_VALID_BITRATES:
        raise ValueError(
            f'bitrate must be one of {sorted(_CAN_VALID_BITRATES)} bit/s'
        )

    cmd = ['go-can', 'set', iface, 'bitrate', str(bitrate)]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, text=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'go-can set {iface} bitrate: timeout')
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip() or f'exit {result.returncode}'
        raise RuntimeError(f'go-can set {iface} bitrate: {msg}')

    # Update bitrate cache so the next can.info call reflects the change
    # immediately instead of returning the stale TTL'd value.
    _can_bitrate_cache[iface] = (time.monotonic(), bitrate)

    operstate = _read_iface_operstate(iface)
    return {
        'interface': iface,
        'bitrate':   bitrate,
        'kbps':      bitrate // 1000,
        'up':        operstate == 'up',
    }


# --- auth.login (one-shot session authentication) ----------------------------
#
# Lichtgewicht model: client stuurt SHA256(canonical end0 MAC) na connect.
# Server vergelijkt met `pass_hash` uit /etc/go_bluetooth.conf (default =
# zelfde sha256(MAC) als de conf-file ontbreekt). Bij match: sessie
# geauthenticeerd tot disconnect. Geen ongoing handshake per write.
#
# Threat-model: geeft GEEN crypto-bescherming tegen iemand die binnen BLE-
# bereik zit en de MAC kan lezen uit IDENTITY of de adv. Het is een
# explicit-handshake-laag bovenop de bestaande proximity-protection
# (Just-Works pairing + QR-pair flow + adv invisible-buiten-app). Vooral
# nuttig om per ongeluk schrijven door verkeerde apps te voorkomen, en als
# vangrail mocht een toekomstig pass_hash met sterker geheim ingesteld zijn.

_AUTH_REQUIRED_ERROR = 'auth_required: call auth.login before this command'


def _read_pass_hash() -> str:
    """Return de geconfigureerde pass_hash, of het default `sha256(MAC)`.

    Conf-formaat (`/etc/go_bluetooth.conf`):
        pass_hash=<64-char hex sha256 digest>

    Default: sha256 van de canonical lowercase end0 MAC met dubbele punten,
    bv. `sha256("00:0c:c6:94:91:77")`. Hash-input is dus exact wat IDENTITY
    teruggeeft als string-form."""
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH, 'r') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' not in line:
                        continue
                    key, _, val = line.partition('=')
                    if key.strip() == 'pass_hash':
                        h = val.strip().lower()
                        if len(h) == 64 and all(c in '0123456789abcdef' for c in h):
                            return h
        except OSError as exc:
            logger.warning('auth: failed to read %s (%s); falling back to MAC default',
                           CONF_PATH, exc)
    mac = _read_identity_mac()
    canonical = ':'.join(f'{b:02x}' for b in mac)
    return hashlib.sha256(canonical.encode('ascii')).hexdigest()


def _handler_auth_login(params: dict) -> dict:
    """Validate the supplied hash against `pass_hash`. Marks the session as
    authenticated on success; subsequent write-commands within the same
    BLE session are then permitted until disconnect."""
    global _session_authenticated
    import hmac
    supplied = params.get('hash')
    if not isinstance(supplied, str) or len(supplied) != 64:
        raise ValueError('hash must be a 64-char hex sha256 digest')
    expected = _read_pass_hash()
    # Constant-time compare — BLE-link RTT dominates the timing channel
    # anyway, but `hmac.compare_digest` is the right habit for any
    # secret-comparison code path.
    if not hmac.compare_digest(supplied.lower(), expected):
        _session_authenticated = False
        raise PermissionError('invalid credentials')
    _session_authenticated = True
    logger.info('Auth: session authenticated')
    return {'authenticated': True}


def _require_auth() -> None:
    """Raise PermissionError als de huidige RPC-sessie niet geauthenticeerd
    is. Aangeroepen door alle write-handlers vóór ze daadwerkelijk muteren."""
    if not _session_authenticated:
        raise PermissionError(_AUTH_REQUIRED_ERROR)


# --- handler-tabel -----------------------------------------------------------

_HANDLERS = {
    'auth.login':         _handler_auth_login,
    'system.stats':       _handler_system_stats,
    'modules.info':       _handler_modules_info,
    'network.info':       _handler_network_info,
    'can.info':           _handler_can_info,
    'services.list':      _handler_services_list,
    'services.set':       _handler_services_set,
    'ethernet.set_mode':  _handler_ethernet_set_mode,
    'ethernet.set_ip':    _handler_ethernet_set_ip,
    'wifi.scan':          _handler_wifi_scan,
    'wifi.set_mode':      _handler_wifi_set_mode,
    'wifi.connect':       _handler_wifi_connect,
    'can.set_bitrate':    _handler_can_set_bitrate,
}


# ──────────────────────────────────────────────────────────────────────────────
# Connect / disconnect — log only; bluezero handles all the link-layer plumbing
# ──────────────────────────────────────────────────────────────────────────────
def on_connect(device) -> None:
    logger.info('Connected: %s', device)


def on_disconnect(device) -> None:
    global _session_active, _session_authenticated
    _session_active = False
    _session_authenticated = False
    _reset_rx()
    if _tx_queue:
        _tx_queue.clear()
    logger.info('Disconnected: %s', device)
    # Murata 1YN/BlueZ 5.82: the LEAdvertisement1 instance is dropped from
    # the controller after central-disconnect and is NOT auto-resumed.
    # Without re-registering here the device stays invisible to future scans
    # until the service is manually restarted. Defer 500 ms so BlueZ' own
    # post-disconnect bookkeeping settles before we re-register.
    GLib.timeout_add(500, _restart_advertising_once)


def _restart_advertising_once() -> bool:
    """One-shot GLib timeout callback — re-register the advertisement so the
    device becomes scannable again. Returns False so the timeout doesn't
    auto-repeat."""
    if _peripheral is None:
        return False
    advert = _peripheral.advert
    ad_manager = _peripheral.ad_manager
    try:
        ad_manager.unregister_advertisement(advert)
        logger.debug('Advertising: previous instance unregistered')
    except dbus.DBusException as exc:
        # Often "DoesNotExist" — the controller already dropped it. Benign.
        logger.debug('Advertising: unregister skipped (%s)', exc.get_dbus_name())
    except Exception as exc:
        logger.debug('Advertising: unregister error (%s)', exc)
    try:
        ad_manager.register_advertisement(advert, {})
        logger.info('Advertising re-registered after disconnect')
    except Exception as exc:
        logger.warning('Advertising: re-register failed (%s)', exc)
    return False


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
    global _peripheral
    _setup_logging()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    adapters = list(adapter.Adapter.available())
    if not adapters:
        raise RuntimeError('No Bluetooth adapter found')
    dongle_address = adapters[0].address
    logger.info('Adapter: %s', dongle_address)

    _set_kernel_adv_defaults()
    # NOTE: BD_ADDR flash is NOT done here — the BCM4345C0 chip rejects
    # btmgmt power-off in the first ~60 s after boot, which made go-bt's
    # startup hang for a minute on retries. The flash is now handled by
    # `go-bt-bdaddr.service` (oneshot) triggered by `go-bt-bdaddr.timer`
    # `OnBootSec=60s` after multi-user.target — safely past the chip's
    # warm-up window. The script restarts go-bt itself once the flip
    # succeeds so the new address is broadcast immediately.

    ble = peripheral.Peripheral(dongle_address)
    _peripheral = ble
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
        srv_id=1, chr_id=2, uuid=REQUEST_UUID,
        value=[], notifying=False,
        flags=['write', 'write-without-response'],
        write_callback=cb_request_write,
    )

    ble.add_characteristic(
        srv_id=1, chr_id=3, uuid=RESPONSE_UUID,
        value=[], notifying=False,
        flags=['read', 'notify'],
        read_callback=cb_response_read,
        notify_callback=cb_response_notify,
    )

    ble.add_characteristic(
        srv_id=1, chr_id=4, uuid=IDENTITY_UUID,
        value=list(_read_identity_mac()), notifying=False,
        flags=['read'],
        read_callback=cb_identity_read,
    )

    ble.add_characteristic(
        srv_id=1, chr_id=5, uuid=SYSTEM_INFO_UUID,
        value=list(_read_system_info_json()), notifying=False,
        flags=['read'],
        read_callback=cb_system_info_read,
    )

    async_tools.add_timer_ms(HEARTBEAT_INTERVAL_MS, _heartbeat_tick)
    async_tools.add_timer_seconds(1, _watchdog)

    # Add Manufacturer Specific Data so the iOS scan list can render the
    # correct controller type (M1 / L4 / HMI1) and serial number BEFORE the
    # user taps to connect. The payload MUST fit alongside the 128-bit
    # Service UUID in a single legacy 31-byte advertising packet — BlueZ
    # 5.82 on this Broadcom chip rejects "Add Extended Advertising
    # Parameters" with "Invalid Parameters (0x0d)" the moment the combined
    # AD set exceeds 31 B, which leaves the device unadvertised entirely.
    #
    # Budget: 31 B total
    #   3 B  Flags AD (1 len + 1 type + 1 flags)
    #  18 B  128-bit Service UUID AD (1 len + 1 type + 16 UUID)
    #   4 B  Manuf Data framing (1 len + 1 type + 2 company id)
    #   ── ────
    #  25 B  used → 6 B left for our payload
    #
    # _build_mfg_payload() respects this 6-byte ceiling.
    mfg_payload = _build_mfg_payload()
    ble.advert.manufacturer_data(MFG_COMPANY_ID, list(mfg_payload))

    _register_agent()
    _disable_pairing()

    logger.info('go-bt server starting (no LocalName, UUID-only advertising)')
    logger.info('  MfgData company=0x%04X payload=%s (%d B)',
                MFG_COMPANY_ID, mfg_payload.hex(), len(mfg_payload))
    logger.info('  Service:    %s', SERVICE_UUID)
    logger.info('  Heartbeat:  %s  [read, notify] @ %d ms', HEARTBEAT_UUID, HEARTBEAT_INTERVAL_MS)
    logger.info('  Request:    %s  [write, w/o-r]  RPC chunked JSON', REQUEST_UUID)
    logger.info('  Response:   %s  [read, notify]  RPC chunked JSON', RESPONSE_UUID)
    logger.info('  Identity:   %s  [read]  6-byte end0 MAC', IDENTITY_UUID)
    logger.info('  SystemInfo: %s  [read]  JSON (model/hostname/hw/kernel/rootfs/sn)', SYSTEM_INFO_UUID)
    logger.info('  RPC handlers: %s', ', '.join(sorted(_HANDLERS.keys())))
    ble.publish()


if __name__ == '__main__':
    main()
