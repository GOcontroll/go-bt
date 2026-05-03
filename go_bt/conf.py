import hashlib
import logging

logger = logging.getLogger(__name__)

_conf = None


def parse_boolean(value: str) -> bool:
    if value.lower() in ('y', 'yes', 'true'):
        return True
    if value.lower() in ('n', 'no', 'false'):
        return False
    raise ValueError(f'Not a boolean: {value!r}')


def parse_conf(conf_file) -> dict:
    conf_dict = {}
    for line in conf_file:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, _, val = line.partition('=')
        key = key.strip().lower()
        val = val.strip()
        if not key:
            continue
        try:
            conf_dict[key] = parse_boolean(val)
        except ValueError:
            conf_dict[key] = val
    return conf_dict


def get_conf() -> dict:
    global _conf
    if _conf is not None:
        return _conf
    try:
        with open('/etc/go_bluetooth.conf', 'r') as f:
            _conf = parse_conf(f)
    except FileNotFoundError:
        _conf = _create_default_conf()
    return _conf


def _create_default_conf() -> dict:
    mac = _read_mac()
    default_hash = hashlib.sha256(mac.encode()).hexdigest()
    content = (
        '# GOcontroll BLE server configuration\n'
        '# pass_hash is SHA256 of the passkey; default is SHA256 of the ethernet MAC\n'
        f'pass_hash={default_hash}\n'
        'verify_device=true\n'
    )
    try:
        with open('/etc/go_bluetooth.conf', 'x') as f:
            f.write(content)
    except (FileExistsError, PermissionError) as e:
        logger.warning(f'Could not write default conf: {e}')
    return parse_conf(content.splitlines(keepends=True))


def _read_mac() -> str:
    for iface in ('end0', 'eth0'):
        try:
            with open(f'/sys/class/net/{iface}/address') as f:
                return f.read().strip()
        except FileNotFoundError:
            continue
    return 'de:ad:be:ef:00:01'


def get_controller_model() -> str:
    """Detect controller model: l4 / m1 / hmi1.

    Source priority:
      1. /sys/firmware/devicetree/base/platform — newer DTBs, e.g. "Moduline M1"
      2. /sys/firmware/devicetree/base/model    — fallback for fielded units
         without `platform`, e.g. "GOcontroll Moduline M1"

    /…/hardware (e.g. "Moduline Mini V1.11") holds the board revision and does
    NOT carry the model token — never use it for model detection.
    """
    conf = get_conf()
    if 'controller_model' in conf:
        return str(conf['controller_model']).lower()
    for path in (
        '/sys/firmware/devicetree/base/platform',
        '/sys/firmware/devicetree/base/model',
    ):
        try:
            with open(path) as f:
                tokens = f.read().rstrip('\x00').lower().split()
            for model in ('hmi1', 'm1', 'l4'):
                if model in tokens:
                    return model
        except FileNotFoundError:
            continue
    return 'l4'


def write_conf(conf: dict):
    with open('/etc/go_bluetooth.conf', 'w') as f:
        for key, value in conf.items():
            f.write(f'{key}={value}\n')
