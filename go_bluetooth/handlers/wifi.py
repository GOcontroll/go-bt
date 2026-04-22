import logging
import subprocess

logger = logging.getLogger(__name__)

AP_CONN_FILE = '/etc/NetworkManager/system-connections/GOcontroll-AP.nmconnection'


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'wifi.info':
        return get_state()
    elif cmd == 'wifi.scan':
        return _scan()
    elif cmd == 'wifi.ap_clients':
        return _ap_clients()
    elif cmd == 'wifi.set_mode':
        auth.require()
        return _set_mode(params['mode'])
    elif cmd == 'wifi.connect':
        auth.require()
        return _connect(params['ssid'], params.get('psk', ''))
    elif cmd == 'wifi.disconnect':
        auth.require()
        return _disconnect(params['ssid'])
    elif cmd == 'wifi.set_ap':
        auth.require()
        return _set_ap(params.get('ssid', ''), params.get('psk', ''))
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    mode = 'off'
    ip = ''
    ap_ssid = ''
    ap_psk = ''
    connected = False

    try:
        from PyModuline import wifi as pywifi
        wifi_on = pywifi.get_wifi()
        if wifi_on:
            try:
                mode = pywifi.get_wifi_mode()
            except Exception:
                mode = 'client'
        else:
            mode = 'off'
        try:
            ip = pywifi.get_wifi_address() or ''
        except Exception:
            pass
    except ImportError:
        pass

    try:
        with open(AP_CONN_FILE, 'r') as f:
            for line in f:
                if line.startswith('ssid='):
                    ap_ssid = line.split('=', 1)[1].strip()
                elif line.startswith('psk='):
                    ap_psk = line.split('=', 1)[1].strip()
    except FileNotFoundError:
        pass

    return {
        'type': 'wifi.state',
        'mode': mode,
        'ip': ip,
        'ap_ssid': ap_ssid,
        'ap_psk': ap_psk,
        'connected': connected,
    }


def _scan() -> dict:
    result = subprocess.run(
        ['nmcli', '-t', '-f', 'IN-USE,SSID,SIGNAL,SECURITY', 'dev', 'wifi'],
        capture_output=True, text=True, timeout=15
    )
    networks = []
    for line in result.stdout.splitlines():
        parts = line.split(':')
        if len(parts) < 4:
            continue
        in_use = parts[0].strip() == '*'
        ssid   = parts[1].strip()
        if not ssid:
            continue
        try:
            signal_dbm = int(parts[2].strip())
        except ValueError:
            signal_dbm = 0
        security = parts[3].strip() or 'Open'
        networks.append({
            'ssid': ssid,
            'signal_dbm': signal_dbm,
            'security': security,
            'connected': in_use,
        })
    # deduplicate by ssid, keep strongest signal
    seen = {}
    for n in networks:
        key = n['ssid']
        if key not in seen or n['signal_dbm'] > seen[key]['signal_dbm']:
            seen[key] = n
    networks = sorted(seen.values(), key=lambda n: n['signal_dbm'], reverse=True)
    return {'networks': networks}


def _ap_clients() -> dict:
    clients = []
    try:
        result = subprocess.run(
            ['ip', 'n', 'show', 'dev', 'wlan0'], capture_output=True, text=True
        )
        reachable = [
            l.split() for l in result.stdout.splitlines()
            if 'REACHABLE' in l or 'DELAY' in l
        ]
        leases = {}
        try:
            with open('/var/lib/misc/dnsmasq.leases') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        leases[parts[1]] = parts[3]  # mac → hostname
        except FileNotFoundError:
            pass
        for parts in reachable:
            if len(parts) >= 3:
                mac = parts[2]
                clients.append({'mac': mac, 'hostname': leases.get(mac, '')})
    except Exception as e:
        logger.error(f'ap_clients: {e}')
    return {'clients': clients}


def _set_mode(mode: str) -> dict:
    import time
    if mode not in ('off', 'ap', 'client'):
        raise ValueError(f'Invalid wifi mode: {mode!r}')
    try:
        from PyModuline import wifi as pywifi
        if mode == 'off':
            pywifi.set_wifi(False)
        else:
            if not pywifi.get_wifi():
                pywifi.set_wifi(True)
                time.sleep(1)
            if mode == 'ap':
                pywifi.activate_ap()
            else:
                pywifi.deactivate_ap()
    except ImportError:
        logger.warning('PyModuline not available for wifi mode switch')
    return {}


def _connect(ssid: str, psk: str) -> dict:
    args = ['nmcli', 'device', 'wifi', 'connect', ssid]
    if psk:
        args += ['password', psk]
    result = subprocess.run(args, capture_output=True, text=True)
    out = result.stdout
    if 'successfully' in out:
        return {'result': 'success'}
    elif 'Secrets' in out:
        subprocess.run(['nmcli', 'connection', 'delete', 'id', ssid], check=False)
        raise ValueError('wrong_password')
    elif 'SSID' in out:
        subprocess.run(['nmcli', 'connection', 'delete', 'id', ssid], check=False)
        raise ValueError('ssid_not_found')
    else:
        subprocess.run(['nmcli', 'connection', 'delete', 'id', ssid], check=False)
        raise RuntimeError('connect_failed')


def _disconnect(ssid: str) -> dict:
    result = subprocess.run(
        ['nmcli', 'connection', 'delete', 'id', ssid],
        capture_output=True, text=True
    )
    if 'successfully' not in result.stdout:
        raise RuntimeError('disconnect_failed')
    return {}


def _set_ap(ssid: str, psk: str) -> dict:
    if ssid:
        subprocess.run(['nmcli', 'con', 'mod', 'GOcontroll-AP', '802-11-wireless.ssid', ssid], check=True)
    if psk:
        subprocess.run(['nmcli', 'con', 'mod', 'GOcontroll-AP', 'wifi-sec.psk', psk], check=True)
    result = subprocess.run(['nmcli', 'con', 'down', 'GOcontroll-AP'], capture_output=True, text=True)
    if 'successfully' in result.stdout:
        subprocess.run(['nmcli', 'con', 'up', 'GOcontroll-AP'], check=False)
    return {}
