import hashlib
import logging
import subprocess
import threading

from .gatt_server import (
    GattService, GattCharacteristic,
    OTA_SVC_UUID, OTA_DATA_UUID, OTA_CTRL_UUID, OTA_STAT_UUID, OTA_INFO_UUID,
)

logger = logging.getLogger(__name__)

OTA_STATUS_IDLE     = 0x00
OTA_STATUS_READY    = 0x01
OTA_STATUS_COMPLETE = 0x03
OTA_STATUS_ERROR    = 0xFF

OTA_CTRL_START      = 0x01
OTA_CTRL_END        = 0x02
OTA_CTRL_ABORT      = 0x03
OTA_CTRL_TIME_SYNC  = 0x04

INFO_TLV_FLASH_PROGRESS = 0x17

FLASH_PHASE_IDLE      = 0
FLASH_PHASE_RECEIVE   = 1
FLASH_PHASE_VALIDATE  = 2
FLASH_PHASE_INSTALL   = 3
FLASH_PHASE_DONE      = 4
FLASH_PHASE_ERROR     = 5

OTA_BIN_PATH = '/tmp/go_bluetooth_ota.bin'


class OtaService:
    def __init__(self, app):
        bus = app._bus
        svc = GattService(bus, OTA_SVC_UUID)
        app.add_service(svc)

        self._data_char   = GattCharacteristic(bus, OTA_DATA_UUID,  ['write', 'write-without-response'], svc)
        self._ctrl_char   = GattCharacteristic(bus, OTA_CTRL_UUID,  ['write'], svc)
        self._status_char = GattCharacteristic(bus, OTA_STAT_UUID,  ['read', 'notify'], svc)
        self._info_char   = GattCharacteristic(bus, OTA_INFO_UUID,  ['read', 'notify'], svc)

        self._buffer = bytearray()
        self._status_char._value = [OTA_STATUS_IDLE]

        self._data_char.write_callback = self._on_data
        self._ctrl_char.write_callback = self._on_control

    def _on_data(self, data: bytes):
        self._buffer.extend(data)

    def _on_control(self, data: bytes):
        if not data:
            return
        cmd = data[0]
        if cmd == OTA_CTRL_START:
            self._buffer.clear()
            self._set_status(OTA_STATUS_READY)
            self._send_tlv(INFO_TLV_FLASH_PROGRESS, bytes([FLASH_PHASE_RECEIVE, 0]))
            logger.info('OTA START received')
        elif cmd == OTA_CTRL_END:
            logger.info(f'OTA END received, {len(self._buffer)} bytes')
            self._send_tlv(INFO_TLV_FLASH_PROGRESS, bytes([FLASH_PHASE_VALIDATE, 0]))
            threading.Thread(target=self._validate_and_install, daemon=True).start()
        elif cmd == OTA_CTRL_ABORT:
            self._buffer.clear()
            self._set_status(OTA_STATUS_IDLE)
            logger.info('OTA ABORT received')
        elif cmd == OTA_CTRL_TIME_SYNC:
            self._handle_time_sync(data[1:])
        else:
            logger.warning(f'OTA unknown control byte: 0x{cmd:02X}')

    def _handle_time_sync(self, payload: bytes):
        if len(payload) < 7:
            return
        year  = payload[0] | (payload[1] << 8)
        month = payload[2]
        day   = payload[3]
        hour  = payload[4]
        minute = payload[5]
        sec   = payload[6]
        time_str = f'{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}'
        try:
            subprocess.run(['date', '-s', time_str], check=True, capture_output=True)
            logger.info(f'Time synced to {time_str}')
        except subprocess.CalledProcessError as e:
            logger.error(f'Time sync failed: {e}')

    def _validate_and_install(self):
        try:
            # Phase 2: validate
            sha1 = hashlib.sha1(self._buffer).hexdigest()
            logger.info(f'OTA SHA1: {sha1}')
            self._send_tlv(INFO_TLV_FLASH_PROGRESS, bytes([FLASH_PHASE_VALIDATE, 50]))

            # Phase 3: install
            self._send_tlv(INFO_TLV_FLASH_PROGRESS, bytes([FLASH_PHASE_INSTALL, 0]))
            with open(OTA_BIN_PATH, 'wb') as f:
                f.write(self._buffer)
            logger.info(f'OTA binary written to {OTA_BIN_PATH}')

            # TODO: invoke platform-specific install script here
            # subprocess.run(['/usr/lib/go_bluetooth/ota_install.sh', OTA_BIN_PATH], check=True)

            self._send_tlv(INFO_TLV_FLASH_PROGRESS, bytes([FLASH_PHASE_DONE, 100]))
            self._set_status(OTA_STATUS_COMPLETE)
            logger.info('OTA complete')
        except Exception as e:
            logger.error(f'OTA install failed: {e}')
            self._send_tlv(INFO_TLV_FLASH_PROGRESS, bytes([FLASH_PHASE_ERROR, 0]))
            self._set_status(OTA_STATUS_ERROR)

    def _set_status(self, status_byte: int):
        self._status_char.send_notification(bytes([status_byte]))

    def _send_tlv(self, tlv_type: int, data: bytes):
        payload = bytes([tlv_type, len(data)]) + data
        self._info_char.send_notification(payload)
