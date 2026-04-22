import json
import logging
import subprocess

logger = logging.getLogger(__name__)

CELLULAR_CONN_FILE = '/etc/NetworkManager/system-connections/GO-cellular.nmconnection'


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'wwan.info':
        return _full_info()
    elif cmd == 'wwan.set_enabled':
        auth.require()
        return _set_enabled(params['enabled'])
    elif cmd == 'wwan.set_config':
        auth.require()
        return _set_config(params.get('apn', ''), params.get('pin', ''))
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    """Lightweight state — no mmcli call."""
    result = subprocess.run(
        ['systemctl', 'is-active', 'go-wwan'], capture_output=True, text=True
    )
    service_state = result.stdout.strip()
    enabled = service_state == 'active'
    return {'type': 'wwan.state', 'enabled': enabled, 'service_state': service_state}


def get_signal() -> dict | None:
    """Return signal quality or None if modem unavailable."""
    modem_num = _find_modem()
    if modem_num is None:
        return None
    try:
        mmcli = subprocess.Popen(['mmcli', '-K', f'--modem={modem_num}'], stdout=subprocess.PIPE)
        output = subprocess.check_output(
            ['grep', 'signal-quality.value'], stdin=mmcli.stdout, text=True
        )
        mmcli.wait()
        quality = int(output.split(':')[1].strip())
        return {'type': 'wwan.signal', 'quality': quality}
    except Exception:
        return None


def _full_info() -> dict:
    state = get_state()
    info = {
        'enabled': state['enabled'],
        'service_state': state['service_state'],
        'imei': '', 'iccid': '', 'operator': '',
        'ip': '', 'apn': '', 'pin': '',
        'model': '', 'signal_pct': 0,
    }

    # Read APN and PIN from connection file
    try:
        with open(CELLULAR_CONN_FILE, 'r') as f:
            for line in f:
                if line.startswith('apn='):
                    info['apn'] = line.split('=', 1)[1].strip()
                elif line.startswith('gsm.pin=') or line.startswith('pin='):
                    info['pin'] = line.split('=', 1)[1].strip()
    except FileNotFoundError:
        pass

    if not state['enabled']:
        return info

    modem_num = _find_modem()
    if modem_num is None:
        return info

    # Get modem details
    try:
        mmcli = subprocess.Popen(['mmcli', '-K', f'--modem={modem_num}'], stdout=subprocess.PIPE)
        output = subprocess.check_output(
            ['grep', '-E', 'model|signal-quality\\.value|imei|operator-name'],
            stdin=mmcli.stdout, text=True
        )
        mmcli.wait()
        for line in output.splitlines():
            parts = line.split(':', 1)
            if len(parts) < 2:
                continue
            key = parts[0].strip()
            val = parts[1].strip()
            if 'model' in key:
                info['model'] = val
            elif 'signal-quality.value' in key:
                try:
                    info['signal_pct'] = int(val)
                except ValueError:
                    pass
            elif 'imei' in key:
                info['imei'] = val
            elif 'operator-name' in key:
                info['operator'] = val
    except Exception as e:
        logger.debug(f'mmcli info: {e}')

    # Get ICCID from SIM
    try:
        sim_json = subprocess.run(['mmcli', '-i', '0', '-J'], capture_output=True, text=True).stdout
        if 'error' not in sim_json:
            data = json.loads(sim_json)
            info['iccid'] = data.get('sim', {}).get('properties', {}).get('iccid', '')
    except Exception:
        pass

    return info


def _set_enabled(enabled: bool) -> dict:
    if enabled:
        subprocess.run(['systemctl', 'enable', 'go-wwan'], check=False)
        subprocess.run(['systemctl', 'start', 'go-wwan'], check=False)
    else:
        subprocess.run(['systemctl', 'stop', 'go-wwan'], check=False)
        subprocess.run(['systemctl', 'disable', 'go-wwan'], check=False)
    return {}


def _set_config(apn: str, pin: str) -> dict:
    _ensure_connection()
    args = ['nmcli', 'con', 'mod', 'GO-cellular']
    if apn:
        args += ['gsm.apn', apn]
    if pin:
        args += ['gsm.pin', pin]
    subprocess.run(args, check=True)
    result = subprocess.run(['nmcli', 'con', 'down', 'GO-cellular'], capture_output=True, text=True)
    if 'successfully' in result.stdout:
        subprocess.run(['nmcli', 'con', 'up', 'GO-cellular'], check=False)
    return {}


def _find_modem() -> str | None:
    result = subprocess.run(['mmcli', '--list-modems'], capture_output=True, text=True)
    if '/freedesktop/' not in result.stdout:
        return None
    return result.stdout.split('/')[-1].split()[0]


def _ensure_connection():
    """Create GO-cellular NM connection if it doesn't exist."""
    import os
    if os.path.exists(CELLULAR_CONN_FILE):
        return
    subprocess.run([
        'nmcli', 'con', 'add', 'type', 'gsm', 'ifname', 'cdc-wdm0',
        'con-name', 'GO-cellular', 'apn', 'internet',
        'connection.autoconnect', 'yes', 'gsm.pin', '0000',
    ], check=False)
