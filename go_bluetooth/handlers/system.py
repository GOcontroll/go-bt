import subprocess
import logging
from gi.repository import GLib

logger = logging.getLogger(__name__)


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'system.info':
        return _info()
    elif cmd == 'system.set_name':
        auth.require()
        return _set_name(params['name'])
    elif cmd == 'system.reboot':
        auth.require()
        GLib.timeout_add(500, lambda: subprocess.run(['reboot']) and False)
        return {}
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    return {'type': 'system.identity', **_info()}


def _info() -> dict:
    hw_revision = ''
    model = 'l4'
    try:
        with open('/sys/firmware/devicetree/base/hardware', 'r') as f:
            hw_raw = f.read().strip().rstrip('\x00')
        hw_revision = hw_raw
        hw_lower = hw_raw.lower()
        for m in ('hmi1', 'm1', 'l4'):
            if m in hw_lower:
                model = m
                break
    except FileNotFoundError:
        pass

    kernel = ''
    try:
        result = subprocess.run(['uname', '-r'], check=True, capture_output=True, text=True)
        kernel = result.stdout.strip()
    except subprocess.CalledProcessError:
        pass

    hostname = ''
    try:
        with open('/etc/machine-info', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_HOSTNAME='):
                    hostname = line.split('=', 1)[1].strip()
                    break
    except FileNotFoundError:
        pass

    return {
        'model': model,
        'hw_revision': hw_revision,
        'kernel': kernel,
        'hostname': hostname,
    }


def _set_name(name: str) -> dict:
    name = name.strip()
    if ':' in name:
        raise ValueError('Name may not contain colon')
    with open('/etc/machine-info', 'w') as f:
        f.write(f'PRETTY_HOSTNAME={name}\n')
    logger.info(f'Hostname set to {name!r}')
    return {}
