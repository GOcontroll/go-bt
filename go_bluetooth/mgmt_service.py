import json
import logging

from .gatt_server import (
    GattService, GattCharacteristic,
    MGMT_SVC_UUID, MGMT_REQ_UUID, MGMT_RESP_UUID, MGMT_TELE_UUID,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE = 8


class MgmtService:
    def __init__(self, app, auth, handlers: dict):
        bus = app._bus
        svc = GattService(bus, MGMT_SVC_UUID)
        app.add_service(svc)

        self._request_char  = GattCharacteristic(bus, MGMT_REQ_UUID,  ['write'], svc)
        self.response_char  = GattCharacteristic(bus, MGMT_RESP_UUID,  ['notify'], svc)
        self.telemetry_char = GattCharacteristic(bus, MGMT_TELE_UUID,  ['read', 'notify'], svc)

        self._auth = auth
        self._handlers = handlers
        self._request_char.write_callback = self._on_request

    def _on_request(self, value: bytes):
        try:
            msg = json.loads(value.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f'Invalid REQUEST payload: {e}')
            return

        req_id = msg.get('id')
        cmd = msg.get('cmd', '')

        try:
            result = self._dispatch(cmd, msg)
            self._send_response(req_id, True, result)
        except PermissionError as e:
            self._send_response(req_id, False, {}, error=str(e))
        except Exception as e:
            logger.error(f'Handler error for {cmd!r}: {e}')
            self._send_response(req_id, False, {}, error=str(e))

    def _dispatch(self, cmd: str, params: dict) -> dict:
        if cmd == 'auth.attempt':
            ok = self._auth.attempt(params.get('hash', ''))
            return {'authenticated': ok}
        if cmd == 'auth.status':
            return {'authenticated': self._auth.authenticated}

        namespace = cmd.split('.')[0] if '.' in cmd else ''
        handler = self._handlers.get(namespace)
        if handler is None:
            raise ValueError(f'Unknown namespace: {namespace!r}')
        return handler.handle(cmd, params, self._auth)

    def _send_response(self, req_id, ok: bool, result: dict, error: str = None):
        base = {'id': req_id, 'ok': ok}
        if error:
            base['error'] = error
            payload = json.dumps({**base}).encode()
            self.response_char.send_notification(payload)
            return

        # Detect chunking: any list field with > CHUNK_SIZE items
        chunk_key = next(
            (k for k, v in result.items() if isinstance(v, list) and len(v) > CHUNK_SIZE),
            None
        )
        if chunk_key is None:
            payload = json.dumps({**base, **result}).encode()
            self.response_char.send_notification(payload)
            return

        items = result[chunk_key]
        rest = {k: v for k, v in result.items() if k != chunk_key}
        chunks = [items[i:i + CHUNK_SIZE] for i in range(0, len(items), CHUNK_SIZE)]
        total = len(chunks)
        for seq, chunk in enumerate(chunks):
            pkt = {**base, 'seq': seq, 'total': total, chunk_key: chunk, **rest}
            self.response_char.send_notification(json.dumps(pkt).encode())

    def send_telemetry(self, msg: dict):
        self.telemetry_char.send_notification(json.dumps(msg).encode())
