#!/usr/bin/env python3
"""
End-to-end BLE test for go-bt — run on a PC with Bluetooth, next to a
controller that runs go-bt.

Talks to the controller the way the iOS app does: scan on the management
service UUID, read the bootstrap characteristics (Heartbeat / Identity /
SystemInfo), then chunked JSON-RPC over Request (write) + Response (notify).
Every check prints PASS / FAIL / SKIP; the full responses go to a JSON report.

Requirements:  pip install bleak      (tested with bleak 2.1 on Windows 11)

    python tools/e2e_ble.py --serial A4CG-B041-A07C-A001
    python tools/e2e_ble.py --serial A4CG-B041-A07C-A001 --no-writes

Pass --serial (the `go-sn r` serial, advertised as LocalName) whenever more
than one controller is in range; without it the first controller found is used.

State the test changes on the controller (skipped with --no-writes):
  - services.set: switches --toggle-service (default go-upload-server) off and
    back on, only if it is active + enabled to begin with;
  - can.set_bitrate: re-applies the current bitrate of --can-iface (default
    can3) — go-can takes the interface down and up;
  - ethernet.set_ip: re-applies the current static address, only while the
    port runs DHCP and the static profile is a /16;
  - wifi.set_enabled true.
All other write commands are only sent with invalid parameters, to check that
the server rejects them before changing anything.

Exit code 0 when every check passed.
"""

import argparse
import asyncio
import hashlib
import json
import re
import sys
import time
from pathlib import Path

from bleak import BleakClient, BleakScanner

SERVICE_UUID     = '4e2c7a1b-f3d5-4890-b6c8-2a9e0f7d3c5b'
HEARTBEAT_UUID   = '4e2c7a30-f3d5-4890-b6c8-2a9e0f7d3c5b'
REQUEST_UUID     = '4e2c7a31-f3d5-4890-b6c8-2a9e0f7d3c5b'
RESPONSE_UUID    = '4e2c7a32-f3d5-4890-b6c8-2a9e0f7d3c5b'
IDENTITY_UUID    = '4e2c7a33-f3d5-4890-b6c8-2a9e0f7d3c5b'
SYSTEM_INFO_UUID = '4e2c7a34-f3d5-4890-b6c8-2a9e0f7d3c5b'

RPC_MAX_PAYLOAD = 180                   # same chunk size as ble_server.py
MFG_COMPANY_ID = 0xFFFF
MODEL_BYTES = {'L4': 1, 'M1': 2, 'HMI1': 3}

RESULTS = []
REPORT = {}


def record(name: str, ok: bool, detail: str = '') -> None:
    RESULTS.append({'test': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''), flush=True)


def skip(name: str, why: str) -> None:
    RESULTS.append({'test': name, 'status': 'SKIP', 'detail': why})
    print(f'[SKIP] {name} — {why}', flush=True)


class Rpc:
    """Client side of the chunked JSON-RPC: frames = [seq, total] + JSON slice."""

    def __init__(self, client: BleakClient):
        self.client = client
        self.next_id = 1
        self.pending = {}
        self.events = []
        self.frames_rx = 0
        self.bad_frames = 0
        self._reset()

    def _reset(self) -> None:
        self.buf, self.total, self.seq = bytearray(), 0, -1

    def on_notify(self, _char, data: bytearray) -> None:
        self.frames_rx += 1
        if len(data) < 2:
            self.bad_frames += 1
            return
        seq, total, payload = data[0], data[1], bytes(data[2:])
        if seq == 0:
            self.buf, self.total, self.seq = bytearray(payload), total, 0
        elif seq == self.seq + 1 and total == self.total:
            self.buf.extend(payload)
            self.seq = seq
        else:
            self.bad_frames += 1
            self._reset()
            return
        if self.seq != self.total - 1:
            return
        raw = bytes(self.buf)
        self._reset()
        try:
            msg = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.bad_frames += 1
            print(f'  !! undecodable response ({len(raw)} B): {exc}', flush=True)
            return
        msg['_bytes'], msg['_chunks'] = len(raw), total
        if 'event' in msg:
            self.events.append(msg)
            return
        fut = self.pending.pop(msg.get('id'), None)
        if fut and not fut.done():
            fut.set_result(msg)

    async def send_raw(self, payload: bytes) -> int:
        chunks = [payload[i:i + RPC_MAX_PAYLOAD]
                  for i in range(0, len(payload), RPC_MAX_PAYLOAD)] or [b'']
        for seq, chunk in enumerate(chunks):
            await self.client.write_gatt_char(
                REQUEST_UUID, bytes([seq, len(chunks)]) + chunk, response=True)
        return len(chunks)

    async def call(self, cmd: str, params=None, timeout: float = 15.0) -> dict:
        req_id = self.next_id
        self.next_id += 1
        req = {'id': req_id, 'cmd': cmd}
        if params is not None:
            req['params'] = params
        fut = asyncio.get_running_loop().create_future()
        self.pending[req_id] = fut
        t0 = time.perf_counter()
        n = await self.send_raw(json.dumps(req, separators=(',', ':')).encode('utf-8'))
        try:
            msg = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self.pending.pop(req_id, None)
            msg = {'ok': False, 'error': f'TIMEOUT after {timeout:.0f} s'}
        msg['_ms'] = round((time.perf_counter() - t0) * 1000)
        msg['_tx_chunks'] = n
        return msg


def meta(msg: dict) -> str:
    return f"{msg.get('_ms')} ms, {msg.get('_bytes')} B in {msg.get('_chunks')} chunk(s)"


def summary(msg: dict) -> str:
    if not msg.get('ok'):
        return msg.get('error') or json.dumps(msg)[:200]
    return f"{meta(msg)} → {json.dumps(msg.get('data'), ensure_ascii=False)}"


async def expect_error(rpc: Rpc, name: str, cmd: str, params, needle: str) -> None:
    r = await rpc.call(cmd, params)
    record(name, r.get('ok') is False and needle in (r.get('error') or ''),
           r.get('error') or json.dumps(r)[:200])


async def scan(args):
    """First controller advertising the management service (and, with
    --serial, that LocalName; LocalName arrives in the scan response)."""
    found = {}

    def match(dev, adv) -> bool:
        if SERVICE_UUID not in [u.lower() for u in adv.service_uuids]:
            return False
        if args.serial and adv.local_name != args.serial:
            return False
        if args.address and dev.address.lower() != args.address.lower():
            return False
        found['adv'] = adv
        return True

    t0 = time.perf_counter()
    dev = await BleakScanner.find_device_by_filter(match, timeout=args.scan_timeout)
    return dev, found.get('adv'), time.perf_counter() - t0


def expected_le_address(mac: bytes) -> str:
    """BD_ADDR go-bt-bdaddr.sh derives from end0: locally administered,
    unicast first octet, rest of the MAC unchanged."""
    first = (mac[0] & 0xFC) | 0x02
    return ':'.join(f'{b:02X}' for b in bytes([first]) + mac[1:])


async def bootstrap(client: BleakClient, dev, adv) -> str:
    svc = client.services.get_service(SERVICE_UUID)
    record('management service discovered', svc is not None)
    want = {
        HEARTBEAT_UUID:   {'read', 'notify'},
        REQUEST_UUID:     {'write', 'write-without-response'},
        RESPONSE_UUID:    {'read', 'notify'},
        IDENTITY_UUID:    {'read'},
        SYSTEM_INFO_UUID: {'read'},
    }
    for uuid, props in want.items():
        ch = svc.get_characteristic(uuid) if svc else None
        have = set(ch.properties) if ch else set()
        record(f'characteristic {uuid[:8]} {"/".join(sorted(props))}',
               ch is not None and props <= have, ','.join(sorted(have)))

    ident = bytes(await client.read_gatt_char(IDENTITY_UUID))
    mac = ':'.join(f'{b:02x}' for b in ident)
    REPORT['identity'] = mac
    record('IDENTITY is a 6-byte MAC', len(ident) == 6 and any(ident), mac)
    if re.fullmatch(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', dev.address) and len(ident) == 6:
        want_addr = expected_le_address(ident)
        record('BD_ADDR derived from end0 MAC (go-bt-bdaddr)',
               dev.address.upper() == want_addr, f'{dev.address}, expected {want_addr}')
    else:
        skip('BD_ADDR derived from end0 MAC (go-bt-bdaddr)', f'platform hides the address ({dev.address})')

    raw = bytes(await client.read_gatt_char(SYSTEM_INFO_UUID))
    try:
        info = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        record('SYSTEM_INFO is JSON (long read)', False, f'{len(raw)} B: {exc}')
        info = {}
    else:
        REPORT['system_info'] = info
        keys = {'model', 'hostname', 'hw_revision', 'kernel', 'rootfs', 'serial_number'}
        record('SYSTEM_INFO is JSON (long read)', keys <= set(info),
               f'{len(raw)} B, missing {sorted(keys - set(info)) or "nothing"}')
    if info.get('serial_number'):
        record('advertised LocalName = SYSTEM_INFO serial', adv.local_name == info['serial_number'],
               f'{adv.local_name!r} vs {info["serial_number"]!r}')
    model_byte = MODEL_BYTES.get(info.get('model'), 0)
    mfg = adv.manufacturer_data.get(MFG_COMPANY_ID)
    record('advertised mfg data = version 1 + model byte',
           mfg is not None and bytes(mfg) == bytes([1, model_byte]),
           f'{bytes(mfg).hex() if mfg else None}, model {info.get("model")!r}')

    beats = []
    await client.start_notify(HEARTBEAT_UUID,
                              lambda _c, d: beats.append((time.perf_counter(), d[0])))
    await asyncio.sleep(4.5)
    await client.stop_notify(HEARTBEAT_UUID)
    steps_ok = all(((b[1] - a[1]) & 0xFF) == 1 for a, b in zip(beats, beats[1:]))
    period = (beats[-1][0] - beats[0][0]) / (len(beats) - 1) if len(beats) > 1 else 0.0
    record('HEARTBEAT notifies +1 at ~1 Hz', len(beats) >= 3 and steps_ok and 0.7 < period < 1.3,
           f'{len(beats)} beats, {period:.2f} s apart, {[b[1] for b in beats]}')
    return mac


async def reads(rpc: Rpc) -> dict:
    out = {}
    for cmd, timeout in (('system.stats', 10), ('system.software', 10), ('modules.info', 10),
                         ('network.info', 20), ('can.info', 10), ('services.list', 10),
                         ('wifi.saved', 10), ('wifi.scan', 40)):
        r = await rpc.call(cmd, timeout=timeout)
        out[cmd] = r
        record(f'RPC {cmd}', r.get('ok') is True and isinstance(r.get('data'), dict),
               meta(r) if r.get('ok') else r.get('error'))

    await asyncio.sleep(2.2)   # cpu % and CAN busload are deltas between calls
    for cmd in ('system.stats', 'can.info'):
        r = await rpc.call(cmd)
        out[f'{cmd}#2'] = r
        record(f'RPC {cmd} (second call, differential values)', r.get('ok') is True, meta(r))

    slots = ((out['modules.info'].get('data') or {}).get('slots')) or []
    occupied = [s['slot'] for s in slots if not s.get('empty')]
    if not occupied:
        skip('RPC modules.channels.*', 'modules.info lists no occupied slot')
    for slot in occupied:
        for verb in ('config', 'values'):
            r = await rpc.call(f'modules.channels.{verb}', {'slot': slot})
            out[f'modules.channels.{verb}#{slot}'] = r
            record(f'RPC modules.channels.{verb} slot {slot}', r.get('ok') is True,
                   meta(r) if r.get('ok') else r.get('error'))

    multi = [k for k, v in out.items() if (v.get('_chunks') or 0) > 1]
    record('multi-chunk responses reassembled', bool(multi) and rpc.bad_frames == 0,
           f'{len(multi)} multi-chunk responses, {rpc.bad_frames} bad frames')
    REPORT['reads'] = {k: v.get('data', v.get('error')) for k, v in out.items()}
    return out


async def robustness(rpc: Rpc) -> None:
    await expect_error(rpc, 'unknown cmd rejected', 'nope.nope', None, 'unknown cmd')
    r = await rpc.call('modules.channels.config', {'slot': 1, 'pad': 'x' * 600})
    record('request split over 4 frames reassembled by the server',
           r.get('ok') is True and r.get('_tx_chunks', 0) >= 4,
           f"{r.get('_tx_chunks')} frames sent, {meta(r)}")
    # A stray continuation frame and a frame with broken JSON must be dropped.
    await rpc.client.write_gatt_char(REQUEST_UUID, bytes([1, 2]) + b'"stray"', response=True)
    await rpc.client.write_gatt_char(REQUEST_UUID, bytes([0, 1]) + b'{not json', response=True)
    r = await rpc.call('system.stats')
    record('server answers again after stray / garbage frames', r.get('ok') is True, meta(r))


async def auth(rpc: Rpc, mac: str) -> None:
    await expect_error(rpc, 'write without auth.login → auth_required', 'services.set',
                       {'unit': 'ssh', 'enable': True}, 'auth_required')
    await expect_error(rpc, 'auth.login with a wrong hash rejected', 'auth.login',
                       {'hash': '0' * 64}, 'invalid credentials')
    await expect_error(rpc, 'auth.login with a malformed hash rejected', 'auth.login',
                       {'hash': 'abc'}, '64-char')
    await expect_error(rpc, 'still unauthenticated after a failed login', 'wifi.set_enabled',
                       {'enabled': True}, 'auth_required')
    r = await rpc.call('auth.login', {'hash': hashlib.sha256(mac.encode('ascii')).hexdigest()})
    record('auth.login with sha256(end0 MAC) accepted',
           r.get('ok') is True and (r.get('data') or {}).get('authenticated') is True, summary(r))


async def write_validation(rpc: Rpc) -> None:
    cases = (
        ('services.set', {'unit': 'dbus', 'enable': False}, 'whitelist'),
        ('services.set', {'unit': 'ssh', 'enable': 'yes'}, 'true or false'),
        ('ethernet.set_mode', {'mode': 'dhcp'}, "'auto' or 'static'"),
        ('ethernet.set_ip', {'ip': '10.100.1.0'}, 'host address'),
        ('ethernet.set_ip', {'ip': '10.100.300.1'}, 'invalid IPv4'),
        ('wifi.set_enabled', {'enabled': 'on'}, 'true or false'),
        ('wifi.set_mode', {'mode': 'mesh'}, "'ap' or 'client'"),
        ('wifi.set_ap', {'ssid': 'x' * 33}, '1–32 bytes'),
        ('wifi.set_ap', {'password': 'short'}, '8–63'),
        ('wifi.set_ap', {}, 'nothing to change'),
        ('wifi.connect', {}, '`ssid` is required'),
        ('wifi.connect_saved', {'name': 'e2e-does-not-exist'}, 'no saved Wi-Fi network'),
        ('wifi.forget', {'name': 'GOcontroll-AP'}, 'no saved Wi-Fi network'),
        ('can.set_bitrate', {'interface': 'can0', 'bitrate': 123}, 'bitrate must be one of'),
        ('can.set_bitrate', {'interface': 'eth0', 'bitrate': 250000}, 'invalid interface'),
    )
    for cmd, params, needle in cases:
        await expect_error(rpc, f'{cmd} {json.dumps(params)} rejected', cmd, params, needle)


async def writes(rpc: Rpc, data: dict, args) -> None:
    r = await rpc.call('wifi.set_enabled', {'enabled': True})
    record('wifi.set_enabled true', r.get('ok') is True, summary(r))

    services = {s['unit']: s for s in (data['services.list'].get('data') or {}).get('services', [])}
    unit = args.toggle_service
    state = services.get(unit)
    if not (state and state['active'] and state['enabled']):
        skip(f'services.set {unit} off / on', f'not active + enabled: {state}')
    else:
        r = await rpc.call('services.set', {'unit': unit, 'enable': False}, timeout=30)
        d = r.get('data') or {}
        record(f'services.set {unit} off', r.get('ok') is True and not d.get('active')
               and not d.get('enabled'), summary(r))
        r = await rpc.call('services.set', {'unit': unit, 'enable': True}, timeout=30)
        d = r.get('data') or {}
        record(f'services.set {unit} on (restored)', r.get('ok') is True and d.get('active') is True
               and d.get('enabled') is True, summary(r))

    can = (data['can.info'].get('data') or {}).get('interfaces') or []
    iface = next((i for i in can if i.get('name') == args.can_iface and i.get('kbps')), None)
    if iface is None:
        skip(f'can.set_bitrate {args.can_iface}', 'interface or its bitrate not in can.info')
    else:
        r = await rpc.call('can.set_bitrate',
                           {'interface': iface['name'], 'bitrate': iface['kbps'] * 1000}, timeout=20)
        record(f"can.set_bitrate {iface['name']} {iface['kbps']} kbit/s (current value)",
               r.get('ok') is True and (r.get('data') or {}).get('kbps') == iface['kbps'], summary(r))

    eth = (data['network.info'].get('data') or {}).get('ethernet') or {}
    if eth.get('mode') == 'auto' and eth.get('static_ip') and eth.get('static_prefix') == 16:
        r = await rpc.call('ethernet.set_ip', {'ip': eth['static_ip']}, timeout=20)
        d = r.get('data') or {}
        record(f"ethernet.set_ip {eth['static_ip']} (current value, DHCP mode)",
               r.get('ok') is True and d.get('ip') == eth['static_ip']
               and d.get('dhcp_range') is None, summary(r))
    else:
        skip('ethernet.set_ip', f"port in {eth.get('mode')!r} mode or static profile not a /16")


async def first_session(dev, adv, args) -> None:
    async with BleakClient(dev, timeout=30, winrt={'use_cached_services': False}) as client:
        record('connect', client.is_connected, f'MTU {client.mtu_size}')
        record('MTU fits a 182-byte notify frame', client.mtu_size >= 185, str(client.mtu_size))
        REPORT['mtu'] = client.mtu_size
        mac = await bootstrap(client, dev, adv)

        rpc = Rpc(client)
        await client.start_notify(RESPONSE_UUID, rpc.on_notify)
        await asyncio.sleep(0.3)
        data = await reads(rpc)
        await robustness(rpc)
        await auth(rpc, mac)
        await write_validation(rpc)
        if args.no_writes:
            skip('state-changing writes', '--no-writes')
        else:
            await writes(rpc, data, args)
        record('no corrupt response frames in the session', rpc.bad_frames == 0,
               f'{rpc.frames_rx} frames received')
        REPORT['events'] = rpc.events


async def second_session(args) -> None:
    """Advertising must come back after a disconnect, and auth must be reset."""
    dev, _adv, took = await scan(args)
    record('advertises again after the disconnect', dev is not None,
           f'found after {took:.1f} s' if dev else f'not found in {args.scan_timeout:.0f} s')
    if dev is None:
        return
    async with BleakClient(dev, timeout=30) as client:
        rpc = Rpc(client)
        await client.start_notify(RESPONSE_UUID, rpc.on_notify)
        await asyncio.sleep(0.3)
        r = await rpc.call('system.stats')
        record('reconnect: RPC works', r.get('ok') is True, meta(r))
        await expect_error(rpc, 'reconnect: authentication was reset', 'wifi.set_enabled',
                           {'enabled': True}, 'auth_required')


async def run(args) -> None:
    dev, adv, took = await scan(args)
    record('scan finds the management service', dev is not None,
           f'{took:.1f} s' if dev else f'nothing in {args.scan_timeout:.0f} s')
    if dev is None:
        return
    REPORT['advertisement'] = {
        'address': dev.address, 'local_name': adv.local_name, 'rssi': adv.rssi,
        'service_uuids': adv.service_uuids,
        'manufacturer_data': {f'0x{k:04X}': v.hex() for k, v in adv.manufacturer_data.items()},
    }
    print(f"  {REPORT['advertisement']}", flush=True)
    try:
        await first_session(dev, adv, args)
    except Exception as exc:  # noqa: BLE001 — report and still try the reconnect
        record('first session completed', False, f'{type(exc).__name__}: {exc}')
    await asyncio.sleep(2.0)
    try:
        await second_session(args)
    except Exception as exc:  # noqa: BLE001
        record('second session completed', False, f'{type(exc).__name__}: {exc}')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--serial', help='controller serial = advertised LocalName (go-sn r)')
    ap.add_argument('--address', help='BD_ADDR to connect to (not on macOS)')
    ap.add_argument('--no-writes', action='store_true', help='skip the state-changing writes')
    ap.add_argument('--toggle-service', default='go-upload-server',
                    help='whitelisted unit to switch off and on again (default: %(default)s)')
    ap.add_argument('--can-iface', default='can3',
                    help='CAN interface whose bitrate is re-applied (default: %(default)s)')
    ap.add_argument('--scan-timeout', type=float, default=20.0)
    ap.add_argument('--out', default='e2e_report.json', help='JSON report (default: %(default)s)')
    args = ap.parse_args()

    asyncio.run(run(args))

    counts = {s: sum(r['status'] == s for r in RESULTS) for s in ('PASS', 'FAIL', 'SKIP')}
    print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped", flush=True)
    Path(args.out).write_text(json.dumps({'results': RESULTS, 'report': REPORT},
                                         indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'report: {args.out}')
    return 0 if counts['FAIL'] == 0 and counts['PASS'] else 1


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')   # Windows consoles default to cp1252
    sys.exit(main())
