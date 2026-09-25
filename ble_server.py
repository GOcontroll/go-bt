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

    Read commands (no auth):
        system.stats     → {cpu, temp_c, mem_pct, uptime_s, supply, accel}
        system.software  → {application:{simulink_version}, packages:[...]}
        modules.info     → {slots: [{slot, type, hw_version, fw_version, empty}]}
        network.info     → {ethernet:{...}, wifi:{...}, wwan:{...}}
        can.info         → {interfaces:[{id,present,up,kbps,state}], load:{canX:pct}}
        services.list, wifi.scan, wifi.saved

    Write commands (after auth.login): services.set, ethernet.set_mode,
    ethernet.set_ip, wifi.set_enabled, wifi.set_mode, wifi.set_ap,
    wifi.connect, wifi.connect_saved, wifi.forget, can.set_bitrate

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

# Manufacturer Specific Data — 16-bit company ID, payload broadcast next to
# the 128-bit Service UUID in the primary advertising packet. 0xFFFF is the
# BLE SIG "test/proprietary" range; safe for our use until we register an
# official company ID.
#
# Layout (2 bytes total):
#   payload[0]   version    uint8   currently 0x01
#   payload[1]   model      uint8   1=L4, 2=M1, 3=HMI1, 0=unknown
#
# The serial number is no longer in manuf-data — it ships in the BLE
# LocalName (AD type 0x09) which BlueZ spills into the scan-response
# AD-set when the primary adv is full. iOS' active scan reads both the
# primary adv and the scan-response, so the iPhone app sees the full
# serial pre-connect via `kCBAdvertisementDataLocalNameKey`.
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

# CAN busload differential state (per-iface deltas across can.info calls)
_can_load_state: dict = {}     # ifc -> {"t": monotonic, "p": packets, "b": bytes}

# IIO device directories by kernel name ("mcp3004", "lis2dw12"). Only hits are
# cached: the numbering is fixed per boot, a driver that probes late is retried.
_iio_device_cache: dict = {}

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

# Request params that never go into the log (Wi-Fi passwords, auth hash).
_SECRET_PARAMS = ('password', 'hash')


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

    logged = ({k: ('***' if k in _SECRET_PARAMS else v) for k, v in params.items()}
              if isinstance(params, dict) else params)
    logger.info('RPC ← id=%s cmd=%s params=%s', req_id, cmd, logged)
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
def _read_conf() -> dict:
    """Parse /etc/go_bluetooth.conf (`key=value` lines, `#` comments) into a
    dict with lowercase keys. Empty when the file is missing or unreadable."""
    conf = {}
    try:
        # errors='replace': a stray byte must not crash startup (the model
        # lookup for the advertisement reads this file).
        with open(CONF_PATH, 'r', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, val = line.partition('=')
                # Inline comments are allowed after the value (CLAUDE.md example).
                conf[key.strip().lower()] = val.split('#', 1)[0].strip()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning('conf: failed to read %s (%s)', CONF_PATH, exc)
    return conf


_MODEL_TO_BYTE = {'L4': 1, 'M1': 2, 'HMI1': 3}

# Contact inputs (K15) per model — GOcontroll-Architecture
# controller/static/info.md "Voeding en omgeving". Names follow the
# GOcontroll-CodeBase supply indices (K15-A/B/C on ADC channel 0/1/2).
_MODEL_K15_NAMES = {
    'L4':   ('K15-A', 'K15-B', 'K15-C'),
    'M1':   ('K15-A', 'K15-B', 'K15-C'),
    'HMI1': ('K15',),
}


def _detect_model_name() -> str:
    """Return the canonical short model name (M1 / L4 / HMI1), or an empty
    string if not detected. Order (linux/spec.md §3): `controller_model` in
    /etc/go_bluetooth.conf, then the device-tree platform/model strings, then
    the hardware string for 5.10 kernels without a platform node.

    Token-based matching — substring matching is a trap: "M1" appears inside
    "HMI1", so an `'m1' in raw` check would mis-identify an HMI1 as M1.
    """
    override = _read_conf().get('controller_model', '').upper()
    if override in _MODEL_TO_BYTE:
        return override
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
    # The hardware string names the product family ("Moduline Mini V1.11"),
    # same fallback go-web-ui uses (handlers/modules.py _classify).
    hardware = _read_text_file('/sys/firmware/devicetree/base/hardware').lower()
    if 'mini' in hardware:
        return 'M1'
    if 'display' in hardware or 'hmi' in hardware:
        return 'HMI1'
    if 'moduline iv' in hardware:
        return 'L4'
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
    """Compact identification blob — fixed 2-byte layout that lives next to
    the 128-bit Service UUID in the primary advertising packet.

    Layout:
        byte 0   version  UInt8 — currently 0x01
        byte 1   model    UInt8 — 1=L4, 2=M1, 3=HMI1, 0=unknown

    The full serial number is published separately via the BLE LocalName
    (see _build_local_name) which BlueZ spills into the scan-response
    AD-set. That keeps the manuf-data tiny — version + model only —
    while still surfacing the SN pre-connect on iOS.
    """
    payload = bytearray()
    payload.append(MFG_PAYLOAD_VERSION)
    payload.append(_detect_model_byte())
    return bytes(payload)


def _build_local_name() -> str:
    """Serial number, used as the BLE LocalName so iOS can show it in the
    scan list before the user taps to connect.

    BlueZ 5.82 on the Broadcom chip in M1/L4 fits the 128-bit Service UUID
    + 2-byte manuf-data in the primary AD-set (≤ 25 B). The LocalName
    pushes the total over 31 B, so BlueZ moves the LocalName into the
    scan-response AD-set automatically — that's a separate 31-byte budget,
    delivered to iOS during active scanning. A typical serial like
    "B1AL-B055-B001-A002" (19 chars + 2 framing = 21 B) fits comfortably.

    Falls back to an empty string when `go-sn r` is not available; bluezero
    then omits the LocalName altogether.
    """
    return _run_capture(['go-sn', 'r']).strip()


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
# Supply voltages + accelerometer — IIO sysfs, same sources and scaling as
# GOcontroll-CodeBase code/GO_board.c (ControllerPower / ControllerInfo, Linux).
#
# Supply: MCP3004 ADC, mV = raw × 25.54, channels ch0 = K15-A, ch1 = K15-B,
# ch2 = K15-C, ch3 = K30. Boards with an ADS1015 instead (Moduline IV
# V3.00–V3.05, Mini V1.03) are read by the application over raw I²C with
# unlocked single-shot conversions; go-bt stays off that bus so it cannot
# corrupt the application's readings, and reports `supply: null` there.
#
# Accelerometer: LIS2DW12 (M1 only). A sysfs raw read fails with EBUSY while
# the application streams the sensor through its IIO buffer — `accel: null`.
# Each raw read also powers the sensor up and sleeps boot-time / ODR (st_accel:
# 2 / ODR s); at the driver's 1 Hz default that is 6 s for three axes, which
# would stall the single-threaded server, so below `_ACCEL_MIN_ODR_HZ` go-bt
# reports null too. The ODR is the application's setting — go-bt never writes it.
# ──────────────────────────────────────────────────────────────────────────────
_IIO_DIR = '/sys/bus/iio/devices'
_SUPPLY_MV_PER_LSB = 25.54          # ((3.35 / 1023) / 1.5) × 11700
_SUPPLY_K30_CHANNEL = 3
_STANDARD_GRAVITY = 9.80665
_ACCEL_MIN_ODR_HZ = 25.0


def _find_iio_device(name: str) -> "str | None":
    """Return the sysfs directory of the IIO device whose `name` attribute
    matches (e.g. /sys/bus/iio/devices/iio:device0), or None."""
    cached = _iio_device_cache.get(name)
    if cached:
        return cached
    try:
        entries = sorted(os.listdir(_IIO_DIR))
    except OSError:
        return None
    for entry in entries:
        if not entry.startswith('iio:device'):
            continue
        path = f'{_IIO_DIR}/{entry}'
        if _read_text_file(f'{path}/name') == name:
            _iio_device_cache[name] = path
            return path
    return None


def _read_number_file(path: str) -> "float | None":
    """Read one numeric sysfs attribute; None when missing, busy or garbled."""
    try:
        with open(path, 'r') as fh:
            return float(fh.read().strip())
    except (OSError, ValueError):
        return None


def _read_supply() -> "dict | None":
    """{k30: V, k15: [{name, v}]} with one K15 entry per contact input of the
    detected model (volts, 2 decimals, null per unreadable channel), or None
    when the controller has no MCP3004."""
    dev = _find_iio_device('mcp3004')
    if dev is None:
        return None

    def volts(channel: int) -> "float | None":
        raw = _read_number_file(f'{dev}/in_voltage{channel}_raw')
        if raw is None:
            return None
        return round(raw * _SUPPLY_MV_PER_LSB / 1000.0, 2)

    names = _MODEL_K15_NAMES.get(_detect_model_name(), _MODEL_K15_NAMES['L4'])
    return {
        'k30': volts(_SUPPLY_K30_CHANNEL),
        'k15': [{'name': name, 'v': volts(ch)} for ch, name in enumerate(names)],
    }


def _read_accel() -> "dict | None":
    """{x_mg, y_mg, z_mg} in milli-g from the LIS2DW12, or None when the
    controller has none, the application holds it in buffered mode, or its
    output data rate is too low to read without stalling."""
    dev = _find_iio_device('lis2dw12')
    if dev is None:
        return None
    odr = (_read_number_file(f'{dev}/sampling_frequency')
           or _read_number_file(f'{dev}/in_accel_sampling_frequency'))
    if odr is None or odr < _ACCEL_MIN_ODR_HZ:
        return None
    out = {}
    for axis in ('x', 'y', 'z'):
        raw = _read_number_file(f'{dev}/in_accel_{axis}_raw')
        scale = (_read_number_file(f'{dev}/in_accel_{axis}_scale')
                 or _read_number_file(f'{dev}/in_accel_scale'))
        if raw is None or scale is None:
            return None
        # scale is m/s² per LSB (IIO ABI)
        out[f'{axis}_mg'] = int(round(raw * scale / _STANDARD_GRAVITY * 1000.0))
    return out


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

_MODULES_JSON_PATH     = '/lib/firmware/gocontroll/modules.json'
_MODULES_DEV_JSON_PATH = '/lib/firmware/gocontroll/modules_dev.json'
_SHM_SLOT_DIR_FMT      = '/dev/shm/slot{slot}/{article}'

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


# --- modules.channels.{config,values} ----------------------------------------

def _article_from_firmware(fw_str: str) -> "str | None":
    """Strip the trailing 3-segment SW version from a 7-segment firmware
    identifier so we get the article number used in /dev/shm paths.

    Example: '20-10-1-5-2-0-3' → '20-10-1-5'  (2-0-3 is sw_major-minor-patch).
    Returns None when the firmware string isn't well-formed.
    """
    if not fw_str:
        return None
    parts = fw_str.split('-')
    if len(parts) < 4:
        return None
    return '-'.join(parts[:-3])


def _read_modules_dev_entry(slot: int) -> "dict | None":
    """Locate the per-slot entry in modules_dev.json. Returns None when the
    file is missing, malformed, or doesn't contain this slot."""
    try:
        with open(_MODULES_DEV_JSON_PATH, 'r') as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f'cannot read modules_dev.json: {exc}')
    if not isinstance(raw, list):
        return None
    for entry in raw:
        if isinstance(entry, dict) and entry.get('slot') == slot:
            return entry
    return None


def _handler_modules_channels_config(params: dict) -> dict:
    """Return the per-channel configuration for one slot from modules_dev.json.

    Schema (subset of modules_dev.json[slot]):
        {slot, article, type?, sensor_supply?, channels: [...]}

    Returns `{config: null}` when the slot is empty / unconfigured so the
    iPhone-side can render a "no channel info" placeholder uniformly,
    instead of failing the RPC. Hard errors (unreadable file, malformed
    JSON) propagate as RPC errors via the RuntimeError above.
    """
    slot = params.get('slot')
    if not isinstance(slot, int) or slot < 1:
        raise ValueError('slot must be a positive int')
    entry = _read_modules_dev_entry(slot)
    if entry is None:
        return {'config': None}
    fw_str = entry.get('firmware') or ''
    article = _article_from_firmware(fw_str)
    config = entry.get('config')
    if not isinstance(config, dict) or article is None:
        return {'config': None}
    channels = config.get('channels')
    if not isinstance(channels, list):
        return {'config': None}
    out = {
        'slot': slot,
        'article': article,
        'channels': channels,
    }
    if isinstance(entry.get('type'), str):
        out['type'] = entry['type']
    if isinstance(config.get('sensor_supply'), dict):
        out['sensor_supply'] = config['sensor_supply']
    return {'config': out}


def _read_channel_value(path: str) -> "int | None":
    """Read one /dev/shm/slot.../channelN file. Format is space-padded
    ASCII int + '\\n'; returns the parsed integer, or None when the file
    is missing or unparseable. Missing files are normal (e.g. when a
    channel is configured but no module-side process has populated the
    shm value yet) — surface them as null so the UI can render a dash."""
    try:
        with open(path, 'r') as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _handler_modules_channels_values(params: dict) -> dict:
    """Return the live values for one slot's channels from /dev/shm.

    Builds the channel list from modules_dev.json (so the iPhone-side
    sees a stable channel set) then reads each /dev/shm path. The shm
    entries match the directory layout we observe on M1:
        /dev/shm/slot{N}/{article}/channel{M}
    """
    slot = params.get('slot')
    if not isinstance(slot, int) or slot < 1:
        raise ValueError('slot must be a positive int')
    entry = _read_modules_dev_entry(slot)
    if entry is None:
        return {'values': None}
    fw_str = entry.get('firmware') or ''
    article = _article_from_firmware(fw_str)
    if article is None:
        return {'values': None}
    config = entry.get('config') or {}
    channels = config.get('channels')
    if not isinstance(channels, list) or not channels:
        return {'values': None}
    base_dir = _SHM_SLOT_DIR_FMT.format(slot=slot, article=article)
    values: dict = {}
    for ch in channels:
        if not isinstance(ch, dict):
            continue
        idx = ch.get('channel')
        if not isinstance(idx, int) or idx < 1:
            continue
        path = f'{base_dir}/channel{idx}'
        values[str(idx)] = _read_channel_value(path)
    return {
        'values': {
            'slot': slot,
            'article': article,
            'channels': values,
        }
    }


# --- system.stats ------------------------------------------------------------

def _handler_system_stats(_params: dict) -> dict:
    return {
        'cpu':       _read_cpu_pct(),
        'temp_c':    _read_temp_c(),
        'mem_pct':   _read_mem_pct(),
        'uptime_s':  _read_uptime_s(),
        'supply':    _read_supply(),
        'accel':     _read_accel(),
    }


# --- system.software ---------------------------------------------------------

_SIMULINK_VERSION_DIR = '/usr/mem-sim'


def _read_simulink_version() -> "str | None":
    """Model version the Simulink target writes to /usr/mem-sim/MODEL_{MAJOR,
    FEATURE,FIX} (one gcvt-formatted number per file, e.g. "2" or "2.").
    Same source as go-web-ui /api/get_sim_ver. None until a model has been
    built with a version."""
    parts = []
    for name in ('MODEL_MAJOR', 'MODEL_FEATURE', 'MODEL_FIX'):
        value = _read_number_file(f'{_SIMULINK_VERSION_DIR}/{name}')
        if value is None:
            return None
        parts.append(str(int(value)))
    return '.'.join(parts)


def _installed_gocontroll_packages() -> list:
    """[{name, version}] for every installed `go-*` Debian package."""
    out = _run_capture(['dpkg-query', '-W',
                        '-f=${Package}\t${Version}\t${db:Status-Abbrev}\n',
                        'go-*'], timeout=5.0)
    packages = []
    for line in out.splitlines():
        cols = line.split('\t')
        # Status abbreviation: 2nd char 'i' = installed ("ii", held "hi");
        # patterns also list removed/known packages.
        if len(cols) >= 3 and cols[2][1:2] == 'i':
            packages.append({'name': cols[0], 'version': cols[1]})
    return sorted(packages, key=lambda p: p['name'])


def _handler_system_software(_params: dict) -> dict:
    return {
        'application': {
            'simulink_version': _read_simulink_version(),
        },
        'packages': _installed_gocontroll_packages(),
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


def _nmcli_split(line: str) -> list:
    """Split one `nmcli -t` table line on ':' honouring nmcli's escapes
    (`\\:` = literal colon, `\\\\` = backslash) — SSIDs may contain either."""
    fields, cur, escaped = [], [], False
    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == '\\':
            escaped = True
        elif ch == ':':
            fields.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append(''.join(cur))
    return fields


def _nmcli_connections() -> list:
    """Every NetworkManager profile as {name, type, device, autoconnect, active}.
    `type` is NM's long form, e.g. '802-11-wireless' / '802-3-ethernet'."""
    out = _run_capture(['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE,AUTOCONNECT,ACTIVE',
                        'con', 'show'], timeout=3.0)
    cons = []
    for line in out.splitlines():
        cols = _nmcli_split(line)
        if len(cols) < 5:
            continue
        cons.append({
            'name':        cols[0],
            'type':        cols[1],
            'device':      cols[2],
            'autoconnect': cols[3] == 'yes',
            'active':      cols[4] == 'yes',
        })
    return cons


def _nmcli_profile_fields(name: str, *fields) -> dict:
    """`nmcli con show <name>` restricted to `fields`, as {field: value}.
    Unescaped (`-e no`): one field per line, so the value is everything after
    the first ':'. Empty dict when the profile does not exist."""
    out = _run_capture(['nmcli', '-t', '-e', 'no', '-f', ','.join(fields),
                        'con', 'show', name], timeout=3.0)
    values = {}
    for line in out.splitlines():
        key, sep, val = line.partition(':')
        if sep:
            values[key] = val
    return values


def _ethernet_iface() -> str:
    return 'end0' if os.path.exists('/sys/class/net/end0') else 'eth0'


def _ethernet_info(cons: "list | None" = None) -> dict:
    iface = _ethernet_iface()
    operstate = _read_iface_operstate(iface)
    info = {
        'iface':         iface,
        'mac':           _read_iface_mac(iface),
        'connected':     operstate == 'up',
        'current_ip':    _read_iface_ip(iface),
        'static_ip':     None,
        'static_prefix': None,
        'mode':          None,
    }
    # Mode = the profile active on the port. Without a cable neither profile
    # is active, so fall back to the one that autoconnects — that is what
    # ethernet.set_mode configures and what comes up on the next link.
    by_name = {c['name']: c for c in (cons if cons is not None else _nmcli_connections())}
    auto = by_name.get(_ETH_PROFILE_AUTO)
    static = by_name.get(_ETH_PROFILE_STATIC)
    if static and static['active']:
        info['mode'] = 'static'
    elif auto and auto['active']:
        info['mode'] = 'auto'
    elif static and static['autoconnect']:
        info['mode'] = 'static'
    elif auto and auto['autoconnect']:
        info['mode'] = 'auto'
    if static:
        addresses = _nmcli_profile_fields(_ETH_PROFILE_STATIC, 'ipv4.addresses')
        first = addresses.get('ipv4.addresses', '').split(',')[0].strip()
        if first:
            ip, _, prefix = first.partition('/')
            info['static_ip'] = ip
            info['static_prefix'] = int(prefix) if prefix.isdigit() else None
    return info


def _wifi_iface() -> "str | None":
    """First wireless netdev (it has a `wireless` sysfs directory), e.g. wlan0."""
    try:
        for name in sorted(os.listdir('/sys/class/net')):
            if os.path.isdir(f'/sys/class/net/{name}/wireless'):
                return name
    except OSError:
        pass
    return None


def _wifi_radio() -> tuple:
    """(present, enabled) for the WLAN radio from rfkill. `enabled` = neither
    soft- nor hard-blocked; `nmcli radio wifi off` sets the soft block."""
    out = _run_capture(['rfkill', '-J', '--output-all'], timeout=2.0)
    if out:
        try:
            for dev in json.loads(out).get('rfkilldevices', []):
                if dev.get('type') == 'wlan':
                    return True, (dev.get('soft') == 'unblocked'
                                  and dev.get('hard') == 'unblocked')
        except json.JSONDecodeError:
            pass
    return False, False


def _wifi_info(cons: "list | None" = None) -> dict:
    """Wi-Fi state. `mode` follows go-web-ui's wifi type: 'ap' while the
    GOcontroll-AP profile autoconnects (or is up), otherwise 'client'; 'off'
    with the radio disabled. `ap_ssid` is the SSID the AP profile broadcasts
    (the profile itself is always named GOcontroll-AP)."""
    present, enabled = _wifi_radio()
    iface = _wifi_iface()
    info = {
        'present':         present or iface is not None,
        'enabled':         enabled,
        'mode':            'off',
        'connected':       False,
        'ip':              None,
        'ap_ssid':         None,
        'ap_active':       False,
        'connected_ssid':  None,
        'signal':          None,
    }
    ap = _nmcli_profile_fields(_WIFI_AP_PROFILE,
                               '802-11-wireless.ssid', 'connection.autoconnect')
    info['ap_ssid'] = ap.get('802-11-wireless.ssid') or None
    if not enabled:
        return info

    if cons is None:
        cons = _nmcli_connections()
    ap_con = next((c for c in cons if c['name'] == _WIFI_AP_PROFILE), None)
    info['ap_active'] = bool(ap_con and ap_con['active'])
    ap_autoconnect = ap.get('connection.autoconnect') == 'yes'
    info['mode'] = 'ap' if (ap_autoconnect or info['ap_active']) else 'client'

    client = next((c for c in cons
                   if c['active'] and c['type'].endswith('wireless')
                   and c['name'] != _WIFI_AP_PROFILE), None)
    if client:
        info['connected'] = True
        info['connected_ssid'] = client['name']
        # SSID + signal of the joined network from NM's cached scan list.
        for row in _wifi_scan_rows(rescan=False):
            if row['in_use']:
                info['connected_ssid'] = row['ssid'] or client['name']
                info['signal'] = row['signal']
                break
    if iface:
        info['ip'] = _read_iface_ip(iface)
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
        'access_tech':     None,
        'gps':             None,
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
    access = [str(t).upper() for t in (gen.get('access-technologies') or [])
              if _clean(t) and str(t).lower() != 'unknown']
    info['access_tech']   = ', '.join(access) or None
    info['gps']           = _wwan_gps(modems[0])
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


def _wwan_gps(modem_path: str) -> "dict | None":
    """GNSS state of the 4G module through ModemManager's location API:
    {enabled, fix, latitude, longitude}. None when the modem has no GPS
    capability. `enabled` means a GPS source (gps-nmea / gps-raw) is switched
    on in ModemManager; without that there is no position to report.
    ModemManager only fills latitude/longitude from the gps-raw source; with
    just gps-nmea the position comes from the GGA sentence in the NMEA trace."""
    sout = _run_capture(['mmcli', '-J', '--modem=' + modem_path,
                         '--location-status'], timeout=3.0)
    try:
        loc = (json.loads(sout).get('modem', {}) or {}).get('location', {}) or {}
    except json.JSONDecodeError:
        return None
    capabilities = loc.get('capabilities') or []
    if not any(str(c).startswith('gps') for c in capabilities):
        return None
    enabled = any(str(s) in ('gps-nmea', 'gps-raw') for s in (loc.get('enabled') or []))
    gps = {'enabled': enabled, 'fix': False, 'latitude': None, 'longitude': None}
    if not enabled:
        return gps
    gout = _run_capture(['mmcli', '-J', '--modem=' + modem_path,
                         '--location-get'], timeout=3.0)
    try:
        fix = ((json.loads(gout).get('modem', {}) or {})
               .get('location', {}) or {}).get('gps', {}) or {}
    except json.JSONDecodeError:
        return gps
    try:
        position = (float(fix['latitude']), float(fix['longitude']))
    except (KeyError, TypeError, ValueError):
        position = _parse_gga(fix.get('nmea') or [])   # '--' without gps-raw
    if position is not None:
        gps['latitude'], gps['longitude'] = position
        gps['fix'] = True
    return gps


def _parse_gga(sentences) -> "tuple | None":
    """(latitude, longitude) in decimal degrees from the first GGA sentence
    with a fix (quality > 0), or None. GGA: $xxGGA,time,ddmm.mmmm,N|S,
    dddmm.mmmm,E|W,quality,…"""
    def degrees(value: str, hemisphere: str, negative: str) -> float:
        raw = float(value)
        deg = int(raw // 100)
        result = deg + (raw - deg * 100) / 60.0
        return -result if hemisphere == negative else result

    for sentence in sentences if isinstance(sentences, list) else []:
        fields = str(sentence).split('*')[0].split(',')
        if len(fields) < 7 or not fields[0].endswith('GGA'):
            continue
        if fields[6] in ('', '0') or not fields[2] or not fields[4]:
            continue
        try:
            return (round(degrees(fields[2], fields[3], 'S'), 6),
                    round(degrees(fields[4], fields[5], 'W'), 6))
        except ValueError:
            continue
    return None


def _handler_network_info(_params: dict) -> dict:
    cons = _nmcli_connections()
    return {
        'ethernet': _ethernet_info(cons),
        'wifi':     _wifi_info(cons),
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


def _can_link_details() -> dict:
    """{ifname: (bitrate_bps, state)} for every CAN link from a single
    `ip -j -d link show type can`. `state` is the controller state the kernel
    reports (ERROR-ACTIVE / ERROR-PASSIVE / BUS-OFF / STOPPED) or None."""
    out = _run_capture(['ip', '-j', '-d', 'link', 'show', 'type', 'can'], timeout=2.0)
    try:
        links = json.loads(out) if out else []
    except json.JSONDecodeError:
        return {}
    details = {}
    for link in links if isinstance(links, list) else []:
        info = (link.get('linkinfo') or {}).get('info_data') or {}
        try:
            bitrate = int((info.get('bittiming') or {}).get('bitrate') or 0)
        except (TypeError, ValueError):
            bitrate = 0
        state = info.get('state')
        details[link.get('ifname')] = (bitrate, state if isinstance(state, str) else None)
    return details


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
    details = _can_link_details()
    for ifc in _list_can_ifaces():
        # Identifier — laatste cijfer(s) van de iface-naam (can0, can1, …)
        m = re.match(r'^can(\d+)$', ifc)
        ident = int(m.group(1)) if m else 0

        operstate = _read_iface_operstate(ifc)
        bitrate, state = details.get(ifc, (0, None))
        ifaces_out.append({
            'id':       ident,
            'name':     ifc,
            'present':  True,
            'up':       operstate == 'up',
            'kbps':     int(bitrate / 1000) if bitrate > 0 else None,
            'state':    state,
        })

        # Busload — delta sinds vorige call. Eerste call seedt en geeft 0.
        p, b = _can_counters(ifc)
        prev = _can_load_state.get(ifc)
        pct = 0.0
        if prev is not None:
            dt = now - prev['t']
            dp = max(0, p - prev['p'])
            db = max(0, b - prev['b'])
            if dt > 0 and bitrate > 0:
                bits = dp * 47 + db * 8   # CAN classic frame overhead approx
                pct = max(0.0, min(100.0, (bits / dt) / bitrate * 100.0))
        _can_load_state[ifc] = {'t': now, 'p': p, 'b': b}
        load[ifc] = round(pct, 1)

    return {'interfaces': ifaces_out, 'load': load}


# --- services.list / services.set --------------------------------------------

# Whitelist (unit, label, description) mirrors go-web-ui's handlers/service.py
# + js/services.js with two changes: `go-bluetooth` (the legacy RFCOMM server)
# is replaced by `go-bt` (this service), and `go-wwan` (4G, a page of its own
# in go-web-ui) is added. Units that are not installed are left out of
# services.list. Including go-bt itself is deliberate, like go-web-ui lists
# itself: the app warns before disabling it, and services.set lets the
# response go out before the stop takes the BLE link down.
_SERVICES = (
    ('ssh',                 'SSH',
     'OpenSSH service, to log in over a network'),
    ('go-simulink',         'Simulink',
     'Starts the Simulink model automatically'),
    ('nodered',             'Node-RED',
     'The Node-RED programming interface'),
    ('go-bt',               'Bluetooth server',
     'This Bluetooth connection to the GOcontroll app'),
    ('go-upload-server',    'Simulink upload server',
     'Accepts new Simulink models to be uploaded'),
    ('go-auto-shutdown',    'Auto shutdown',
     'Shuts the controller down when K15 is low and Simulink is not running'),
    ('go-wwan',             '4G / LTE',
     'Mobile data connection through the 4G modem'),
    ('gadget-getty@ttyGS0', 'USB terminal',
     'Log in through the USB interface'),
    ('getty@ttymxc2',       'Serial terminal',
     'Log in through the RS232 interface'),
    ('go-web-ui',           'Web UI',
     'The browser interface on port 5000'),
)
_SERVICES_WHITELIST = tuple(unit for unit, _, _ in _SERVICES)
_SELF_UNIT = 'go-bt'
_SELF_STOP_DELAY_MS = 1500      # lets the services.set response frames go out first
_ENABLED_UNIT_FILE_STATES = ('enabled', 'enabled-runtime', 'static', 'alias')


def _systemctl_states(units) -> dict:
    """{unit: {loaded, active, enabled}} for `units` from one `systemctl show`.
    systemctl prints one property block per unit, separated by a blank line;
    blocks are matched on their Id (`<unit>.service`), falling back to argument
    order. A unit that is not installed has LoadState=not-found."""
    units = list(units)
    out = _run_capture(['systemctl', 'show',
                        '--property=Id,LoadState,ActiveState,UnitFileState']
                       + units, timeout=5.0)
    blocks = [dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
              for block in out.split('\n\n') if block.strip()] if out else []
    by_id = {props.get('Id'): props for props in blocks}
    states = {}
    for idx, unit in enumerate(units):
        props = by_id.get(f'{unit}.service')
        if props is None:
            if idx >= len(blocks):
                continue
            props = blocks[idx]
        states[unit] = {
            'loaded':  props.get('LoadState') not in (None, '', 'not-found'),
            'active':  props.get('ActiveState') == 'active',
            'enabled': props.get('UnitFileState') in _ENABLED_UNIT_FILE_STATES,
        }
    return states


def _service_entry(unit: str, state: dict) -> dict:
    label, description = next((l, d) for u, l, d in _SERVICES if u == unit)
    return {
        'unit':        unit,
        'label':       label,
        'description': description,
        'active':      state['active'],
        'enabled':     state['enabled'],
    }


def _handler_services_list(_params: dict) -> dict:
    states = _systemctl_states(_SERVICES_WHITELIST)
    return {'services': [_service_entry(unit, states[unit])
                         for unit in _SERVICES_WHITELIST
                         if unit in states and states[unit]['loaded']]}


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


def _stop_self_once() -> bool:
    """One-shot GLib timeout: stop go-bt after services.set disabled it."""
    logger.info('services.set: stopping %s as requested over BLE', _SELF_UNIT)
    subprocess.Popen(['systemctl', 'stop', _SELF_UNIT])
    return False


def _handler_services_set(params: dict) -> dict:
    """enable=true → systemctl enable + start; enable=false → disable + stop
    (go-web-ui order: disable first, so a unit that is gone after the stop
    cannot come back at boot). Stopping go-bt itself is deferred until the
    response has been sent."""
    _require_auth()
    unit = params.get('unit')
    enable = params.get('enable')
    if not isinstance(unit, str) or unit not in _SERVICES_WHITELIST:
        raise ValueError(f'unit not in whitelist: {unit!r}')
    if not isinstance(enable, bool):
        raise ValueError('`enable` must be true or false')

    verbs = ('enable', 'start') if enable else ('disable', 'stop')
    for verb in verbs:
        if unit == _SELF_UNIT and verb == 'stop':
            GLib.timeout_add(_SELF_STOP_DELAY_MS, _stop_self_once)
            return _service_entry(unit, {'active': False, 'enabled': False})
        ok, err = _systemctl_run(verb, unit)
        if not ok:
            raise RuntimeError(err)

    state = _systemctl_states([unit]).get(unit, {'active': False, 'enabled': False})
    return _service_entry(unit, state)


# --- ethernet.set_mode / ethernet.set_ip -------------------------------------

_ETH_PROFILE_AUTO   = 'Wired connection auto'
_ETH_PROFILE_STATIC = 'Wired connection static'


def _redacted_args(args) -> str:
    """Command line for error messages with the value after a secret key
    (`wifi-sec.psk`, `password`) masked — messages go to the app and the log."""
    out, hide = [], False
    for arg in args:
        out.append('***' if hide else str(arg))
        hide = arg in ('wifi-sec.psk', 'password')
    return ' '.join(out)


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
        return False, f"nmcli {_redacted_args(args)}: timeout"
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
    if mode == 'static':
        # The address may have been changed while DHCP was selected (the
        # pool is only moved while static is selected) — catch up now.
        static = _ethernet_info().get('static_ip')
        if static:
            _sync_dhcp_pool(static)
    return {'mode': mode}


_DNSMASQ_CONF = '/etc/dnsmasq.conf'
# The rootfs serves DHCP on the wired port in static mode, e.g.
#   dhcp-range=end0,10.100.1.1,10.100.1.250,12h
_DHCP_RANGE_RE = re.compile(
    r'^dhcp-range=(?P<iface>eth0|end0),(?P<start>[0-9.]+),(?P<end>[0-9.]+)(?P<rest>,.*)?$'
)


def _dhcp_pool_for(ip: str) -> tuple:
    """DHCP pool in the /24 of the controller's own static address, on the side
    of that /24 that leaves the most room: .1 – .(own-1) for a high own
    address (the factory 10.100.1.254 keeps its pool), else .(own+1) – .254."""
    octets = ip.split('.')
    base, own = '.'.join(octets[:3]), int(octets[3])
    if own > 128:
        return f'{base}.1', f'{base}.{own - 1}'
    return f'{base}.{own + 1}', f'{base}.254'


def _update_dnsmasq_range(ip: str) -> "str | None":
    """Move the wired DHCP pool into the new static address' subnet — the
    step go-web-ui's set_static_ip intends. Only a plain `dhcp-range=<iface>,
    <start>,<end>[,…]` line for eth0/end0 is rewritten (atomically, through a
    symlink); any other layout is left alone. Returns the new 'start-end'
    range, or None when nothing was changed."""
    path = os.path.realpath(_DNSMASQ_CONF)
    try:
        with open(path, 'r', errors='replace') as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    start, end = _dhcp_pool_for(ip)
    changed = False
    for idx, line in enumerate(lines):
        m = _DHCP_RANGE_RE.match(line.strip())
        if m:
            lines[idx] = f"dhcp-range={m['iface']},{start},{end}{m['rest'] or ''}"
            changed = True
    if not changed:
        return None
    tmp = path + '.go-bt.tmp'
    try:
        with open(tmp, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning('dnsmasq: could not write %s (%s); pool left as it was', path, exc)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return None
    return f'{start}-{end}'


def _static_profile_selected() -> bool:
    """True when the port runs, or will run on the next link, the static
    profile — only then is the controller the DHCP server on it."""
    static = next((c for c in _nmcli_connections() if c['name'] == _ETH_PROFILE_STATIC), None)
    return bool(static and (static['active'] or static['autoconnect']))


def _sync_dhcp_pool(ip: str) -> "str | None":
    """Rewrite the wired pool for `ip` and restart dnsmasq, but only while the
    static profile is selected: in DHCP mode the port sits on someone else's
    LAN, and a pool in that LAN's subnet would make the controller a second
    DHCP server there. Returns the new range or None."""
    if not _static_profile_selected():
        return None
    dhcp_range = _update_dnsmasq_range(ip)
    if dhcp_range:
        # dnsmasq reads its config at start only; no-op when it isn't running.
        _systemctl_run('try-restart', 'dnsmasq')
    return dhcp_range


def _handler_ethernet_set_ip(params: dict) -> dict:
    """Update the static-profile IPv4 address. Uses /16 to match the
    existing go-web-ui contract (controllers ship as DHCP servers on a
    /16 subnet for industrial deployments) and, while static is selected,
    moves the dnsmasq pool of the wired port along. The new address is
    applied immediately if the static profile is currently active; otherwise
    it sticks for the next activation."""
    _require_auth()
    ip = params.get('ip')
    if not isinstance(ip, str) or not ip:
        raise ValueError('`ip` is required')
    import ipaddress
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise ValueError(f'invalid IPv4 address: {exc}')
    if (addr.is_multicast or addr.is_loopback or addr.is_unspecified
            or ip.endswith('.0') or ip.endswith('.255')):
        raise ValueError(f'{ip} cannot be used as a host address')

    ok, err = _nmcli_run(
        'con', 'mod', _ETH_PROFILE_STATIC, 'ipv4.addresses', f'{ip}/16',
        timeout=5.0,
    )
    if not ok:
        raise RuntimeError(f"failed to set static IP: {err}")

    state = _nmcli_profile_fields(_ETH_PROFILE_STATIC, 'GENERAL.STATE')
    if state.get('GENERAL.STATE', '').strip() == 'activated':
        # Bounce the connection so the new IP takes effect now.
        _nmcli_run('con', 'down', _ETH_PROFILE_STATIC, timeout=5.0)
        ok, err = _nmcli_run('con', 'up', _ETH_PROFILE_STATIC, timeout=10.0)
        if not ok:
            raise RuntimeError(f"failed to re-activate static profile: {err}")
    return {'ip': ip, 'dhcp_range': _sync_dhcp_pool(ip)}


# --- wifi.scan / wifi.set_mode / wifi.connect --------------------------------

_WIFI_AP_PROFILE = 'GOcontroll-AP'
_WIFI_CONNECT_WAIT_S = 35       # nmcli --wait; the subprocess gets 5 s more


def _wifi_scan_rows(rescan: bool) -> list:
    """One row per visible BSSID: {ssid, signal, security, in_use}.

    `--rescan yes` blocks until a fresh scan completes (the user pressed Scan
    and is waiting); `--rescan no` returns NetworkManager's cached list. The
    radio cannot scan while it runs the access point — the list is then
    whatever NM saw last, often empty."""
    out = _run_capture(['nmcli', '-t', '-f', 'IN-USE,SSID,SIGNAL,SECURITY',
                        'device', 'wifi', 'list',
                        '--rescan', 'yes' if rescan else 'no'],
                       timeout=25.0 if rescan else 5.0)
    rows = []
    for line in out.splitlines():
        cols = _nmcli_split(line)
        if len(cols) < 4:
            continue
        try:
            signal = int(cols[2])
        except ValueError:
            signal = 0
        rows.append({
            'ssid':     cols[1],
            'signal':   signal,
            'security': '' if cols[3] == '--' else cols[3],
            'in_use':   cols[0].strip() == '*',
        })
    return rows


def _wifi_scan_active() -> list:
    """Rescan and return the visible networks, de-duplicated by SSID (the
    strongest BSSID wins, `in_use` if any BSSID of it is joined), strongest
    first. Hidden networks (empty SSID) are left out."""
    by_ssid = {}
    for row in _wifi_scan_rows(rescan=True):
        ssid = row['ssid']
        if not ssid:
            continue
        existing = by_ssid.get(ssid)
        if existing is None or row['signal'] > existing['signal']:
            by_ssid[ssid] = {
                'ssid':     ssid,
                'signal':   row['signal'],
                'secured':  bool(row['security']),
                'security': row['security'],
                'in_use':   row['in_use'] or bool(existing and existing['in_use']),
            }
        elif row['in_use']:
            existing['in_use'] = True
    return sorted(by_ssid.values(), key=lambda e: -e['signal'])


def _handler_wifi_scan(_params: dict) -> dict:
    return {'networks': _wifi_scan_active()}


def _wifi_client_profiles(cons: "list | None" = None) -> list:
    """Saved Wi-Fi client profiles — every wireless profile but the AP."""
    return [c for c in (cons if cons is not None else _nmcli_connections())
            if c['type'].endswith('wireless') and c['name'] != _WIFI_AP_PROFILE]


def _wifi_set_autoconnect(client: bool) -> None:
    """Make the choice between AP and client survive a reboot, like go-web-ui's
    set_wifi_type: client → every saved network autoconnects and the AP does
    not; AP → the other way round."""
    for con in _wifi_client_profiles():
        # `id`: a profile literally named "id"/"uuid"/"path" would otherwise
        # be read as an nmcli keyword.
        _nmcli_run('con', 'mod', 'id', con['name'], 'connection.autoconnect',
                   'yes' if client else 'no', timeout=5.0)
    _nmcli_run('con', 'mod', _WIFI_AP_PROFILE, 'connection.autoconnect',
               'no' if client else 'yes', timeout=5.0)


def _handler_wifi_set_mode(params: dict) -> dict:
    """Switch between Access Point and Client. Mirrors go-web-ui's
    set_wifi_type — toggles the autoconnect flag on the AP profile vs the
    user's regular wifi connections, then brings the right one up."""
    _require_auth()
    mode = params.get('mode')
    if mode not in ('ap', 'client'):
        raise ValueError("mode must be 'ap' or 'client'")

    _wifi_set_autoconnect(client=(mode == 'client'))
    if mode == 'ap':
        ok, err = _nmcli_run('con', 'up', _WIFI_AP_PROFILE, timeout=20.0)
        if not ok:
            raise RuntimeError(f'failed to start the access point: {err}')
    else:
        # NetworkManager then joins a saved network on its own.
        _nmcli_run('con', 'down', _WIFI_AP_PROFILE, timeout=10.0)
    return {'mode': mode}


def _handler_wifi_set_enabled(params: dict) -> dict:
    """Switch the Wi-Fi radio on or off (`nmcli radio wifi`), like go-web-ui's
    set_wifi. The configured AP/client mode is kept for when it comes back."""
    _require_auth()
    enabled = params.get('enabled')
    if not isinstance(enabled, bool):
        raise ValueError('`enabled` must be true or false')
    ok, err = _nmcli_run('radio', 'wifi', 'on' if enabled else 'off', timeout=10.0)
    if not ok:
        raise RuntimeError(f'failed to switch Wi-Fi {"on" if enabled else "off"}: {err}')
    return {'enabled': enabled}


def _handler_wifi_set_ap(params: dict) -> dict:
    """Change the SSID and/or WPA2 password the GOcontroll-AP profile
    broadcasts (go-web-ui set_ap_ssid / set_ap_pass). A running AP is
    restarted so the change takes effect now. The password is never read
    back."""
    _require_auth()
    ssid = params.get('ssid')
    password = params.get('password')
    changes = []
    if ssid is not None:
        if not isinstance(ssid, str) or not ssid.strip() or len(ssid.encode('utf-8')) > 32:
            raise ValueError('`ssid` must be 1–32 bytes')
        changes += ['802-11-wireless.ssid', ssid]
    if password is not None:
        if (not isinstance(password, str) or not 8 <= len(password) <= 63
                or not all(32 <= ord(ch) < 127 for ch in password)):
            raise ValueError('`password` must be 8–63 printable ASCII characters')
        changes += ['wifi-sec.psk', password]
    if not changes:
        raise ValueError('nothing to change: give `ssid` and/or `password`')

    ok, err = _nmcli_run('con', 'mod', _WIFI_AP_PROFILE, *changes, timeout=5.0)
    if not ok:
        raise RuntimeError(f'failed to update the access point: {err}')
    ap_active = any(c['name'] == _WIFI_AP_PROFILE and c['active']
                    for c in _nmcli_connections())
    if ap_active:
        _nmcli_run('con', 'down', _WIFI_AP_PROFILE, timeout=10.0)
        ok, err = _nmcli_run('con', 'up', _WIFI_AP_PROFILE, timeout=20.0)
        if not ok:
            raise RuntimeError(f'access point updated but failed to restart: {err}')
    ap = _nmcli_profile_fields(_WIFI_AP_PROFILE, '802-11-wireless.ssid')
    return {'ap_ssid': ap.get('802-11-wireless.ssid') or None, 'ap_active': ap_active}


def _wifi_connected_result(name: str) -> dict:
    """Fresh snapshot for a connect response, so the app does not have to wait
    for its next network.info refresh."""
    info = _wifi_info()
    return {
        'ssid':       info.get('connected_ssid') or name,
        'connected':  bool(info.get('connected')),
        'ip':         info.get('ip'),
    }


def _handler_wifi_connect(params: dict) -> dict:
    """Connect to a WiFi network as a client. Creates / updates the nmcli
    connection profile and brings it up, then switches the autoconnect flags
    to client mode so the choice survives a reboot."""
    _require_auth()
    ssid = params.get('ssid')
    password = params.get('password', '')
    if not isinstance(ssid, str) or not ssid:
        raise ValueError('`ssid` is required')
    if not isinstance(password, str):
        raise ValueError('`password` must be a string (use "" for open networks)')

    # --wait below the subprocess timeout: nmcli gives up (and reports why)
    # before we would kill it while NetworkManager keeps activating.
    cmd = ['nmcli', '--wait', str(_WIFI_CONNECT_WAIT_S), 'device', 'wifi', 'connect', ssid]
    if password:
        cmd += ['password', password]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=_WIFI_CONNECT_WAIT_S + 5, text=True,
        )
    except subprocess.TimeoutExpired:
        # `from None`: the chained TimeoutExpired would put the password
        # (it is in the argv) into the log via logger.exception.
        raise RuntimeError(f'connect {ssid}: timeout') from None
    # Some nmcli versions exit 0 but print "Error: …" (noted in go-web-ui).
    failed = result.returncode != 0 or 'Error:' in result.stdout
    if failed:
        msg = (result.stderr or result.stdout).strip() or f'exit {result.returncode}'
        raise RuntimeError(f'connect {ssid}: {msg}')

    _wifi_set_autoconnect(client=True)
    return _wifi_connected_result(ssid)


def _handler_wifi_saved(_params: dict) -> dict:
    """Saved client networks: [{name, active, autoconnect}]. `name` is the
    NetworkManager profile name — the SSID for networks joined via
    wifi.connect."""
    return {'networks': [
        {'name': c['name'], 'active': c['active'], 'autoconnect': c['autoconnect']}
        for c in _wifi_client_profiles()
    ]}


def _saved_wifi_profile(params: dict) -> str:
    name = params.get('name')
    if not isinstance(name, str) or not name:
        raise ValueError('`name` is required')
    if name not in {c['name'] for c in _wifi_client_profiles()}:
        raise ValueError(f'no saved Wi-Fi network named {name!r}')
    return name


def _handler_wifi_connect_saved(params: dict) -> dict:
    """Join a saved network (no password needed) and switch to client mode."""
    _require_auth()
    name = _saved_wifi_profile(params)
    ok, err = _nmcli_run('--wait', str(_WIFI_CONNECT_WAIT_S), 'con', 'up', 'id', name,
                         timeout=_WIFI_CONNECT_WAIT_S + 5)
    if not ok:
        raise RuntimeError(f'connect {name}: {err}')
    _wifi_set_autoconnect(client=True)
    return _wifi_connected_result(name)


def _handler_wifi_forget(params: dict) -> dict:
    """Delete a saved client network profile. The AP profile cannot be
    removed this way."""
    _require_auth()
    name = _saved_wifi_profile(params)
    ok, err = _nmcli_run('con', 'delete', 'id', name, timeout=10.0)
    if not ok:
        raise RuntimeError(f'forget {name}: {err}')
    return {'name': name}


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
    h = _read_conf().get('pass_hash', '').lower()
    if len(h) == 64 and all(c in '0123456789abcdef' for c in h):
        return h
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
    'system.software':    _handler_system_software,
    'modules.info':              _handler_modules_info,
    'modules.channels.config':   _handler_modules_channels_config,
    'modules.channels.values':   _handler_modules_channels_values,
    'network.info':       _handler_network_info,
    'can.info':           _handler_can_info,
    'services.list':      _handler_services_list,
    'services.set':       _handler_services_set,
    'ethernet.set_mode':  _handler_ethernet_set_mode,
    'ethernet.set_ip':    _handler_ethernet_set_ip,
    'wifi.scan':          _handler_wifi_scan,
    'wifi.saved':         _handler_wifi_saved,
    'wifi.set_enabled':   _handler_wifi_set_enabled,
    'wifi.set_mode':      _handler_wifi_set_mode,
    'wifi.set_ap':        _handler_wifi_set_ap,
    'wifi.connect':       _handler_wifi_connect,
    'wifi.connect_saved': _handler_wifi_connect_saved,
    'wifi.forget':        _handler_wifi_forget,
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

    # Add Manufacturer Specific Data + LocalName so the iOS scan list can
    # render the correct controller type (M1 / L4 / HMI1) and the full
    # serial number BEFORE the user taps to connect. Two AD-sets:
    #
    # Primary advertising packet (≤ 31 B):
    #   3 B  Flags AD (1 len + 1 type + 1 flags)
    #  18 B  128-bit Service UUID AD (1 len + 1 type + 16 UUID)
    #   4 B  Manuf Data framing (1 len + 1 type + 2 company id)
    #   2 B  Manuf Data payload  (version + model)
    #   ── ────
    #  27 B  used → 4 B free
    #
    # Scan-response packet (≤ 31 B):
    #   2 B  LocalName framing (1 len + 1 type)
    #   N B  LocalName payload (`go-sn r` output, typically 19 chars)
    #
    # BlueZ decides automatically that the LocalName won't fit in the
    # primary packet alongside the items above, and spills it to the
    # scan-response AD-set. iOS active-scans, reads both AD-sets, and
    # exposes the LocalName via kCBAdvertisementDataLocalNameKey.
    #
    # Why this works while LE Extended Advertising fails: Ext-Adv goes
    # through a different kernel/HCI path on this Broadcom chip and
    # returns Invalid Parameters (0x0d). Legacy adv + scan-response uses
    # the standard LL path which is well-supported.
    mfg_payload = _build_mfg_payload()
    ble.advert.manufacturer_data(MFG_COMPANY_ID, list(mfg_payload))
    local_name = _build_local_name()
    if local_name:
        ble.advert.local_name = local_name

    _register_agent()
    _disable_pairing()

    logger.info('go-bt server starting (LocalName=%r, MfgData + Service UUID adv)',
                local_name or '(omitted)')
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
