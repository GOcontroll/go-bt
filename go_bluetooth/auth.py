import logging

logger = logging.getLogger(__name__)

TRUSTED_DEVICES_FILE = '/etc/bluetooth/trusted_devices.txt'


class Auth:
    def __init__(self, passkey_hash: str, verify_device: bool = True):
        self._hash = passkey_hash.lower()
        self._verify = verify_device
        self._authenticated = False

    def attempt(self, hash_hex: str) -> bool:
        if hash_hex.lower() == self._hash:
            self._authenticated = True
            logger.info('Authentication successful')
        else:
            logger.warning('Authentication failed — wrong passkey hash')
        return self._authenticated

    def require(self):
        if self._verify and not self._authenticated:
            raise PermissionError('auth_required')

    @property
    def authenticated(self) -> bool:
        return self._authenticated or not self._verify

    def check_trusted(self, ble_mac: str) -> bool:
        try:
            with open(TRUSTED_DEVICES_FILE) as f:
                if ble_mac in f.read():
                    self._authenticated = True
                    logger.info(f'Trusted device {ble_mac!r} — auto-authenticated')
        except FileNotFoundError:
            pass
        return self._authenticated

    def add_trusted(self, ble_mac: str):
        with open(TRUSTED_DEVICES_FILE, 'a') as f:
            f.write(ble_mac + '\n')
        logger.info(f'Added trusted device {ble_mac!r}')
