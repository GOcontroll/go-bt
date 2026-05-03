import logging
import subprocess

logger = logging.getLogger(__name__)

VALID_ACTIONS = {'start', 'stop', 'enable', 'disable', 'restart'}


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'services.status':
        return _status(params['names'])
    elif cmd == 'services.set':
        auth.require()
        return _set(params['service'], params['action'])
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    return {'type': 'services.state'}


def _status(names: list) -> dict:
    services = []
    for name in names:
        result = subprocess.run(
            ['systemctl', 'is-active', name], capture_output=True, text=True
        )
        services.append({'name': name, 'status': result.stdout.strip()})
    return {'services': services}


def _set(service: str, action: str) -> dict:
    if action not in VALID_ACTIONS:
        raise ValueError(f'Invalid action: {action!r}')
    result = subprocess.run(
        ['systemctl', action, service], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f'systemctl {action} {service} failed')
    return {}
