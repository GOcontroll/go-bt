import logging
from gi.repository import GLib

logger = logging.getLogger(__name__)


class TelemetryManager:
    def __init__(self, mgmt_service, handlers: dict):
        self._send = mgmt_service.send_telemetry
        self._handlers = handlers
        self._timer_ids = []

        mgmt_service.telemetry_char.on_start_notify = self._on_subscribe
        mgmt_service.telemetry_char.on_stop_notify  = self._on_unsubscribe

    def _on_subscribe(self):
        logger.info('Telemetry subscribed — sending initial dump')
        self._send_initial_dump()
        self._start_periodic()

    def _on_unsubscribe(self):
        logger.info('Telemetry unsubscribed')
        self._stop_periodic()

    def _send_initial_dump(self):
        from . import handlers as h_pkg
        order = ['system', 'ethernet', 'wifi', 'wwan', 'can', 'modules']
        for ns in order:
            handler = self._handlers.get(ns)
            if handler is None:
                continue
            try:
                state = handler.get_state()
                self._send(state)
            except Exception as e:
                logger.error(f'Initial dump {ns}: {e}')

        # connectivity as final item
        self._send_connectivity()

    def _start_periodic(self):
        self._timer_ids.append(GLib.timeout_add(2000,  self._tick_can_load))
        self._timer_ids.append(GLib.timeout_add(10000, self._tick_system_stats))
        self._timer_ids.append(GLib.timeout_add(30000, self._tick_connectivity))
        self._timer_ids.append(GLib.timeout_add(30000, self._tick_wwan_signal))

    def _stop_periodic(self):
        for tid in self._timer_ids:
            GLib.source_remove(tid)
        self._timer_ids.clear()

    def _tick_can_load(self) -> bool:
        handler = self._handlers.get('can')
        if handler:
            try:
                self._send(handler.get_load())
            except Exception as e:
                logger.debug(f'can.load: {e}')
        return True  # repeat

    def _tick_system_stats(self) -> bool:
        try:
            self._send(_read_system_stats())
        except Exception as e:
            logger.debug(f'system.stats: {e}')
        return True

    def _tick_connectivity(self) -> bool:
        self._send_connectivity()
        return True

    def _tick_wwan_signal(self) -> bool:
        handler = self._handlers.get('wwan')
        if handler:
            try:
                sig = handler.get_signal()
                if sig is not None:
                    self._send(sig)
            except Exception as e:
                logger.debug(f'wwan.signal: {e}')
        return True

    def _send_connectivity(self):
        handler = self._handlers.get('ethernet')
        wwan_handler = self._handlers.get('wwan')
        wifi_handler = self._handlers.get('wifi')
        eth = False
        wifi = False
        wwan = False
        try:
            import subprocess
            result = subprocess.run(
                ['nmcli', 'networking', 'connectivity'],
                capture_output=True, text=True, timeout=5
            )
            full = 'full' in result.stdout.lower()
            eth = full
        except Exception:
            pass
        self._send({'type': 'connectivity', 'ethernet': eth, 'wifi': wifi, 'wwan': wwan})


def _read_system_stats() -> dict:
    cpu = _read_cpu_percent()
    temp = _read_temp()
    uptime = _read_uptime()
    return {'type': 'system.stats', 'cpu': cpu, 'temp_c': temp, 'uptime_s': uptime}


def _read_cpu_percent() -> int:
    try:
        # Two reads 200 ms apart for accurate idle %
        import time
        def read_stat():
            with open('/proc/stat') as f:
                parts = f.readline().split()
            vals = list(map(int, parts[1:]))
            total = sum(vals)
            idle = vals[3]
            return total, idle
        t1, i1 = read_stat()
        time.sleep(0.2)
        t2, i2 = read_stat()
        diff_total = t2 - t1
        diff_idle  = i2 - i1
        if diff_total == 0:
            return 0
        return round(100 * (1 - diff_idle / diff_total))
    except Exception:
        return 0


def _read_temp() -> float:
    try:
        with open('/sys/class/thermal/thermal_zone0/temp') as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        return 0.0


def _read_uptime() -> int:
    try:
        with open('/proc/uptime') as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return 0
