import logging
import subprocess

logger = logging.getLogger(__name__)


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'ethernet.info':
        return get_state()
    elif cmd == 'ethernet.set_mode':
        auth.require()
        return _set_mode(params['mode'])
    elif cmd == 'ethernet.set_ip':
        auth.require()
        return _set_ip(params['ip'])
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    mode = 'dhcp'
    current_ip = ''
    static_ip = ''
    connected = False

    try:
        from PyModuline import ethernet
        try:
            current_ip = ethernet.get_ethernet_ip() or ''
        except Exception:
            pass
        try:
            static_ip = ethernet.get_ethernet_static_ip() or ''
        except Exception:
            pass
        try:
            is_static = ethernet.get_ethernet_static_status()
            mode = 'static' if is_static else 'dhcp'
        except Exception:
            pass
    except ImportError:
        pass

    try:
        import PyModuline.networking as networking
        connected = bool(networking.connectivity_state())
    except Exception:
        pass

    return {
        'type': 'ethernet.state',
        'mode': mode,
        'current_ip': current_ip,
        'static_ip': static_ip,
        'connected': connected,
    }


def _set_mode(mode: str) -> dict:
    if mode not in ('dhcp', 'static'):
        raise ValueError(f'Invalid mode: {mode!r}')
    try:
        from PyModuline import ethernet
        if mode == 'static':
            ethernet.activate_ethernet_static()
        else:
            ethernet.deactivate_ethernet_static()
    except ImportError:
        con = 'Wired connection static' if mode == 'static' else 'Wired connection auto'
        subprocess.run(['nmcli', 'con', 'up', con], check=False)
    return {}


def _set_ip(ip: str) -> dict:
    try:
        from PyModuline import ethernet
        ethernet.set_static_ethernet_ip(ip)
    except ImportError:
        # fallback: configure via nmcli
        subprocess.run(
            ['nmcli', 'con', 'mod', 'Wired connection static',
             'ipv4.addresses', ip, 'ipv4.method', 'manual'],
            check=True
        )
        subprocess.run(['nmcli', 'con', 'up', 'Wired connection static'], check=False)
    return {}
