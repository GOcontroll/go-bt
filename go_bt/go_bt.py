#!/usr/bin/env python3
import logging
import threading
from logging.handlers import RotatingFileHandler

import dbus
import dbus.mainloop.glib
from gi.repository import GLib

from .auth import Auth
from .conf import get_conf, get_controller_model
from .gatt_server import Application, Advertisement
from .ota_service import OtaService
from .mgmt_service import MgmtService
from .telemetry import TelemetryManager
from . import makeAgent as agent
from .handlers import system, ethernet, wifi, wwan, can, modules, services

logger = logging.getLogger(__name__)


def setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s')

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        fh = RotatingFileHandler('/var/log/go_bt.log', maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except PermissionError:
        logger.warning('Cannot open /var/log/go_bt.log — logging to console only')


def main():
    setup_logging()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    logger.info('go-bt (BLE GATT) starting')

    # BlueZ pairing agent in background thread
    threading.Thread(target=agent.create_bt_agent, daemon=True).start()

    conf = get_conf()
    auth = Auth(
        passkey_hash=conf.get('pass_hash', ''),
        verify_device=conf.get('verify_device', True)
    )

    handlers = {
        'system':   system,
        'ethernet': ethernet,
        'wifi':     wifi,
        'wwan':     wwan,
        'can':      can,
        'modules':  modules,
        'services': services,
    }

    bus = dbus.SystemBus()
    app = Application(bus)

    OtaService(app)
    mgmt = MgmtService(app, auth, handlers)
    TelemetryManager(mgmt, handlers)

    app.register()

    model = get_controller_model()
    local_name = conf.get('hostname') or f'GOcontroll-{model.upper()}'
    adv = Advertisement(bus, local_name)
    adv.register()

    logger.info(f'BLE server started as {local_name!r}')
    GLib.MainLoop().run()


if __name__ == '__main__':
    main()
