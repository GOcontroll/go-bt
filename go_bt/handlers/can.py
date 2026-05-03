import logging
import shutil
import subprocess
import threading

logger = logging.getLogger(__name__)

CAN_CONF = '/etc/network/interfaces.d/can.conf'
NUM_INTERFACES = 4

_load_process = None
_load_lock = threading.Lock()
_load_callback = None


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'can.info':
        return get_state()
    elif cmd == 'can.set_baudrate':
        auth.require()
        return _set_baudrate(int(params['interface']), int(params['kbps']))
    elif cmd == 'can.set_state':
        auth.require()
        return _set_state(int(params['interface']), bool(params['up']))
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    ip_out = subprocess.run(['ip', '-br', 'a'], capture_output=True, text=True).stdout
    interfaces = []
    for i in range(NUM_INTERFACES):
        iface = f'can{i}'
        present = iface in ip_out
        up = False
        if present:
            for line in ip_out.splitlines():
                if line.startswith(iface):
                    up = 'UP' in line
                    break
        kbps = _get_baudrate(i) // 1000 if present else 0
        interfaces.append({'id': i, 'present': present, 'up': up, 'kbps': kbps})
    return {'type': 'can.state', 'interfaces': interfaces}


def get_load() -> dict:
    """Return last known bus load. Updated by background process."""
    return {'type': 'can.load', **_current_load}


def start_load_monitor(send_telemetry_fn):
    """Start canbusload background process. Call once after connect."""
    global _load_callback
    _load_callback = send_telemetry_fn
    threading.Thread(target=_load_monitor_thread, daemon=True).start()


def stop_load_monitor():
    global _load_process
    with _load_lock:
        if _load_process:
            _load_process.terminate()
            _load_process = None


_current_load = {'can0': 0, 'can1': 0, 'can2': 0, 'can3': 0}


def _load_monitor_thread():
    global _load_process
    ip_out = subprocess.run(['ip', '-br', 'a'], capture_output=True, text=True).stdout
    args = []
    for i in range(NUM_INTERFACES):
        iface = f'can{i}'
        if iface in ip_out:
            bps = _get_baudrate(i)
            args.append(f'{iface}@{bps}')
    if not args:
        return
    with _load_lock:
        _load_process = subprocess.Popen(
            ['canbusload'] + args, stdout=subprocess.PIPE, text=True
        )
    proc = _load_process
    for line in proc.stdout:
        if proc.poll() is not None:
            break
        parts = line.strip().split()
        if len(parts) >= 2 and '@' in parts[0]:
            iface = parts[0].split('@')[0]
            try:
                load = int(parts[-1].rstrip('%'))
                if iface in _current_load:
                    _current_load[iface] = load
            except ValueError:
                pass


def _set_baudrate(interface: int, kbps: int) -> dict:
    iface = f'can{interface}'
    bps = kbps * 1000
    _write_baudrate(interface, bps)
    was_up = _is_up(iface)
    if was_up:
        _set_can_iface(iface, False)
        _set_can_iface(iface, True)
    return {}


def _set_state(interface: int, up: bool) -> dict:
    iface = f'can{interface}'
    _set_can_iface(iface, up)
    return {}


def _set_can_iface(iface: str, up: bool):
    if shutil.which('ifup'):
        cmd = ['ifup' if up else 'ifdown', iface]
        subprocess.run(cmd, check=False)
    else:
        if up:
            bps = _get_baudrate(int(iface.replace('can', '')))
            subprocess.run(
                ['ip', 'link', 'set', iface, 'up', 'type', 'can', 'bitrate', str(bps)],
                check=True
            )
        else:
            subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True)


def _get_baudrate(index: int) -> int:
    """Read baudrate from /etc/network/interfaces.d/can.conf. Returns bps."""
    search = f'iface can{index} inet manual'
    line_num = _get_line_num(CAN_CONF, search)
    if line_num is False:
        return 500000
    try:
        with open(CAN_CONF, 'r') as f:
            lines = f.readlines()
        option_line = lines[line_num + 1].split()
        # format: ... bitrate <value> ...
        if 'bitrate' in option_line:
            idx = option_line.index('bitrate')
            return int(option_line[idx + 1])
    except (IndexError, ValueError, FileNotFoundError):
        pass
    return 500000


def _write_baudrate(index: int, bps: int):
    search = f'iface can{index} inet manual'
    line_num = _get_line_num(CAN_CONF, search)
    if line_num is False:
        return
    with open(CAN_CONF, 'r') as f:
        lines = f.readlines()
    option_line = lines[line_num + 1].split()
    if 'bitrate' in option_line:
        idx = option_line.index('bitrate')
        option_line[idx + 1] = str(bps)
        lines[line_num + 1] = ' '.join(option_line) + '\n'
        with open(CAN_CONF, 'w') as f:
            f.writelines(lines)


def _is_up(iface: str) -> bool:
    out = subprocess.run(['ip', '-br', 'a'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith(iface) and 'UP' in line:
            return True
    return False


def _get_line_num(path: str, search: str):
    try:
        with open(path, 'r') as f:
            for i, line in enumerate(f):
                if search in line:
                    return i
    except FileNotFoundError:
        pass
    return False
