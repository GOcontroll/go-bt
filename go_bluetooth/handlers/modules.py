import glob
import logging
import subprocess
from multiprocessing import Pool

logger = logging.getLogger(__name__)

MODULES_FILE     = '/lib/gocontroll/modules'
FIRMWARE_GLOB    = '/lib/firmware/gocontroll/{type_prefix}*.srec'


def handle(cmd: str, params: dict, auth) -> dict:
    if cmd == 'modules.info':
        return get_state()
    elif cmd == 'modules.scan':
        auth.require()
        return _scan()
    elif cmd == 'modules.firmwares':
        return _firmwares(params['module_type'])
    elif cmd == 'modules.update':
        auth.require()
        return _update(int(params['slot']), params['firmware_id'])
    raise ValueError(f'Unknown command: {cmd}')


def get_state() -> dict:
    return {'type': 'modules.state', 'slots': _read_slots()}


def _read_slots() -> list:
    try:
        with open(MODULES_FILE, 'r') as f:
            line = f.readline().strip()
    except FileNotFoundError:
        return [{'slot': i + 1, 'empty': True} for i in range(8)]

    raw = line.split(':')
    slots = []
    for i, entry in enumerate(raw):
        slot = i + 1
        if not entry or entry == '-':
            slots.append({'slot': slot, 'empty': True})
            continue
        parts = entry.split('-')
        if len(parts) < 5:
            slots.append({'slot': slot, 'empty': True})
            continue
        # format: type-hwver-swmaj-swmin-swpatch
        slots.append({
            'slot': slot,
            'type': '-'.join(parts[:2]),
            'hw_version': parts[2] if len(parts) > 2 else '',
            'fw_version': f'{parts[-3]}.{parts[-2]}.{parts[-1]}',
        })
    return slots


def _scan() -> dict:
    subprocess.run(['go-modules', 'scan'], check=False)
    return get_state()


def _firmwares(module_type: str) -> dict:
    pattern = FIRMWARE_GLOB.format(type_prefix=module_type)
    paths = glob.glob(pattern)
    versions = []
    for p in paths:
        # Extract version from filename: ...<type>-<hwver>-<maj>-<min>-<patch>.srec
        name = p.rsplit('/', 1)[-1].rstrip('.srec').rstrip('c').rstrip('er').rstrip('sr').rstrip('.')
        name = p.split('/')[-1].replace('.srec', '')
        parts = name.split('-')
        if len(parts) >= 3:
            ver = '.'.join(parts[-3:])
            if ver not in versions:
                versions.append(ver)
    return {'versions': versions}


def _update(slot: int, firmware_id: str) -> dict:
    slots = _read_slots()
    targets = []
    for s in slots:
        if s.get('empty'):
            continue
        module_hw = f"{s['type']}-{s['hw_version']}"
        fw_hw = '-'.join(firmware_id.split('-')[:3])
        if module_hw in fw_hw or fw_hw in module_hw:
            fw_ver = '-'.join(firmware_id.split('-')[-3:]).split('.')[0]
            if fw_ver not in s.get('fw_version', ''):
                targets.append([s['slot'], firmware_id])

    # If specific slot requested, restrict to that slot
    target_slot = next((t for t in targets if t[0] == slot), None)
    if target_slot:
        targets = [target_slot]

    if not targets:
        return {'updated': 0, 'message': 'already_up_to_date'}

    with Pool() as p:
        results = p.map(_upload_firmware, targets)

    errors = [f"{r[0]}: {r[1]}" for r in results if 'error' in str(r[1]).lower()]
    if errors:
        raise RuntimeError('; '.join(errors))

    subprocess.run(['go-modules', 'scan'], check=False)
    return {'updated': len(results)}


def _upload_firmware(args):
    slot, firmware = args
    result = subprocess.run(
        ['go-modules', 'overwrite', str(slot), firmware],
        capture_output=True, text=True
    )
    return [slot, result.stdout]
