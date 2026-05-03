import dbus
import dbus.service
import dbus.mainloop.glib
import logging

logger = logging.getLogger(__name__)

BLUEZ_SERVICE             = 'org.bluez'
GATT_MANAGER_IFACE        = 'org.bluez.GattManager1'
ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
GATT_SERVICE_IFACE        = 'org.bluez.GattService1'
GATT_CHRC_IFACE           = 'org.bluez.GattCharacteristic1'
ADVERTISEMENT_IFACE       = 'org.bluez.LEAdvertisement1'
DBUS_OM_IFACE             = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE           = 'org.freedesktop.DBus.Properties'

APP_PATH = '/org/gocontroll/ble'
ADV_PATH = '/org/gocontroll/advertisement'

OTA_SVC_UUID   = '9A3E5F72-8C1D-4B6A-A7E2-3F0D8C5B1E9F'
OTA_DATA_UUID  = '9A3E5F73-8C1D-4B6A-A7E2-3F0D8C5B1E9F'
OTA_CTRL_UUID  = '9A3E5F74-8C1D-4B6A-A7E2-3F0D8C5B1E9F'
OTA_STAT_UUID  = '9A3E5F75-8C1D-4B6A-A7E2-3F0D8C5B1E9F'
OTA_INFO_UUID  = '9A3E5F76-8C1D-4B6A-A7E2-3F0D8C5B1E9F'
MGMT_SVC_UUID  = '4E2C7A1B-F3D5-4890-B6C8-2A9E0F7D3C5B'
MGMT_REQ_UUID  = '4E2C7A1C-F3D5-4890-B6C8-2A9E0F7D3C5B'
MGMT_RESP_UUID = '4E2C7A1D-F3D5-4890-B6C8-2A9E0F7D3C5B'
MGMT_TELE_UUID = '4E2C7A1E-F3D5-4890-B6C8-2A9E0F7D3C5B'


def find_adapter(bus):
    """Return proxy to the first BlueZ adapter that exposes GattManager1."""
    remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE, '/'), DBUS_OM_IFACE)
    objects = remote_om.GetManagedObjects()
    for path, ifaces in objects.items():
        if GATT_MANAGER_IFACE in ifaces:
            return bus.get_object(BLUEZ_SERVICE, path)
    raise RuntimeError(
        'GattManager1 not found — bluetoothd must run with --experimental'
    )


class Application(dbus.service.Object):
    def __init__(self, bus):
        self._bus = bus
        self._services = []
        super().__init__(bus, APP_PATH)

    def add_service(self, service):
        self._services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature='a{oa{sa{sv}}}')
    def GetManagedObjects(self):
        result = {}
        for svc in self._services:
            result[dbus.ObjectPath(svc.path)] = svc.get_properties()
            for chrc in svc.get_characteristics():
                result[dbus.ObjectPath(chrc.path)] = chrc.get_properties()
        return result

    def register(self):
        adapter = find_adapter(self._bus)
        gatt_manager = dbus.Interface(adapter, GATT_MANAGER_IFACE)
        gatt_manager.RegisterApplication(
            APP_PATH, {},
            reply_handler=lambda: logger.info('GATT application registered'),
            error_handler=lambda e: (_ for _ in ()).throw(RuntimeError(str(e)))
        )


class GattService(dbus.service.Object):
    _counter = 0

    def __init__(self, bus, uuid, primary=True):
        GattService._counter += 1
        self.path = f'{APP_PATH}/service{GattService._counter}'
        self.uuid = uuid
        self.primary = primary
        self._characteristics = []
        super().__init__(bus, self.path)

    def get_properties(self):
        return {
            GATT_SERVICE_IFACE: {
                'UUID': dbus.String(self.uuid),
                'Primary': dbus.Boolean(self.primary),
                'Characteristics': dbus.Array(
                    [dbus.ObjectPath(c.path) for c in self._characteristics],
                    signature='o'
                ),
            }
        }

    def add_characteristic(self, chrc):
        self._characteristics.append(chrc)

    def get_characteristics(self):
        return list(self._characteristics)


class GattCharacteristic(dbus.service.Object):
    _counter = 0

    def __init__(self, bus, uuid, flags, service):
        GattCharacteristic._counter += 1
        self.path = f'{service.path}/char{GattCharacteristic._counter}'
        self.uuid = uuid
        self.flags = flags
        self.service = service
        self._value = []
        self._notifying = False
        self.write_callback = None
        self.on_start_notify = None
        self.on_stop_notify = None
        service.add_characteristic(self)
        super().__init__(bus, self.path)

    def get_properties(self):
        return {
            GATT_CHRC_IFACE: {
                'UUID': dbus.String(self.uuid),
                'Service': dbus.ObjectPath(self.service.path),
                'Flags': dbus.Array(self.flags, signature='s'),
                'Value': dbus.Array(self._value, signature='y'),
                'Notifying': dbus.Boolean(self._notifying),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_CHRC_IFACE:
            raise dbus.exceptions.DBusException('org.bluez.Error.InvalidArguments')
        return self.get_properties()[GATT_CHRC_IFACE]

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        return dbus.Array(self._value, signature='y')

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        self._value = list(value)
        if self.write_callback:
            self.write_callback(bytes(value))

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        self._notifying = True
        if self.on_start_notify:
            self.on_start_notify()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        self._notifying = False
        if self.on_stop_notify:
            self.on_stop_notify()

    @dbus.service.signal(DBUS_PROP_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    def send_notification(self, data: bytes):
        self._value = list(data)
        if self._notifying:
            self.PropertiesChanged(
                GATT_CHRC_IFACE,
                {'Value': dbus.Array(self._value, signature='y')},
                dbus.Array([], signature='s')
            )


class Advertisement(dbus.service.Object):
    def __init__(self, bus, local_name: str):
        self._bus = bus
        self._local_name = local_name
        super().__init__(bus, ADV_PATH)

    def get_properties(self):
        return {
            ADVERTISEMENT_IFACE: {
                'Type': dbus.String('peripheral'),
                'ServiceUUIDs': dbus.Array([OTA_SVC_UUID], signature='s'),
                'LocalName': dbus.String(self._local_name),
                'Includes': dbus.Array(['tx-power'], signature='s'),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException('org.bluez.Error.InvalidArguments')
        return self.get_properties()[ADVERTISEMENT_IFACE]

    @dbus.service.method(ADVERTISEMENT_IFACE)
    def Release(self):
        logger.info('Advertisement released by BlueZ')

    def register(self):
        adapter = find_adapter(self._bus)
        ad_manager = dbus.Interface(adapter, ADVERTISING_MANAGER_IFACE)
        ad_manager.RegisterAdvertisement(
            ADV_PATH, {},
            reply_handler=lambda: logger.info(f'Advertising as {self._local_name!r}'),
            error_handler=lambda e: logger.error(f'RegisterAdvertisement failed: {e}')
        )
