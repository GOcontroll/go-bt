# go-bt — CLAUDE.md

## Project context

Dit is de BLE server die draait op GOcontroll Linux controllers (Moduline L4, M1, HMI1). De server maakt het mogelijk voor een iOS/Android app om de controller te monitoren en te configureren via Bluetooth Low Energy.

De huidige code (verwijderd) was een **verouderde RFCOMM implementatie** (Classic Bluetooth, niet BLE) gebouwd op de `bluedot` library. Die implementatie wordt volledig vervangen. De code mag als referentie dienen voor de bestaande functionaliteit, maar de architectuur en het protocol worden niet overgenomen.

De actieve branch voor de nieuwe implementatie is `feature/ble-gatt-rewrite`.

---

## Architectuurdocumenten (lees deze eerst)

Alle architectuurbeslissingen zijn al genomen en gedocumenteerd. Lees beide documenten grondig voordat je implementeert:

- **GATT profile** (service UUIDs, karakteristiekenstructuur):
  https://github.com/GOcontroll/GOcontroll-Architecture/blob/master/ble/gatt-profile.md

- **Linux server spec** (volledig protocol, alle JSON-commando's, telemetrie, authenticatie, OTA):
  https://github.com/GOcontroll/GOcontroll-Architecture/blob/master/ble/linux/spec.md

GitHub token voor toegang: `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`

---

## Wat er gebouwd moet worden

Een nieuwe Python BLE GATT server met **twee GATT services**:

### Service 1 — OTA (`F0001000-1234-5678-9ABC-DEF012345678`)
Identiek aan de ESP32/Moduline S1 implementatie. Vier karakteristieken: DATA (Write/WNR), CONTROL (Write), STATUS (Read/Notify), INFO (Read/Notify). Verwerkt firmware-uploads en stuurt OTA flash progress TLV notificaties.

### Service 2 — Management (`F0002000-1234-5678-9ABC-DEF012345678`)
Drie karakteristieken:
- `REQUEST` (`F0002001`, Write) — app stuurt JSON-commando's met `id` en `cmd`
- `RESPONSE` (`F0002002`, Notify) — controller stuurt JSON-antwoorden met matchend `id`
- `TELEMETRY` (`F0002003`, Read+Notify) — controller stuurt periodieke JSON-telemetrie

Het volledige commando-protocol (namespaces, JSON-schema's, telemetrie-typen, chunking, authenticatie) staat in de spec.

---

## Technologie

- **Python 3.11+**
- **BlueZ via D-Bus** — `dbus-python` + `PyGObject` (GLib mainloop). Geen externe BLE-libraries.
- **Geen** `bluedot`, **geen** `netifaces` — die dependencies worden verwijderd uit `pyproject.toml`
- `PyModuline` is optioneel; als het niet beschikbaar is, vallen handlers terug op directe `subprocess`-aanroepen

Systeemtools die handlers aanroepen: `nmcli`, `ip`, `systemctl`, `ifup`/`ifdown`, `canbusload`, `mmcli`, `go-modules`

---

## Bronstructuur (target)

```
go_bt/
├── go_bt.py                # entry point: BlueZ GATT registratie, advertising, main loop
├── gatt_server.py          # D-Bus scaffolding: GattService1, GattCharacteristic1
├── ota_service.py          # OTA service: DATA ontvangst, CONTROL parsing, STATUS updates
├── mgmt_service.py         # Management service: REQUEST dispatch, RESPONSE/TELEMETRY notificaties
├── telemetry.py            # periodieke telemetrie loop + initiële dump bij verbinding
├── conf.py                 # /etc/go_bluetooth.conf parsing (behoud bestaande structuur)
├── auth.py                 # passkey authenticatie, trusted devices
├── makeAgent.py            # BlueZ pairing agent (ongewijzigd hergebruiken)
└── handlers/
    ├── system.py           # system.info, system.set_name, system.reboot
    ├── ethernet.py         # ethernet.*
    ├── wifi.py             # wifi.*
    ├── wwan.py             # wwan.*
    ├── can.py              # can.*, canbusload achtergrondproces
    ├── modules.py          # modules.*
    └── services.py         # services.*
```

---

## Wat behouden blijft

| Bestand | Status |
|---------|--------|
| `conf.py` | Behouden — bestaand formaat, voeg `controller_model` key toe |
| `auth.py` | Herbouwen — SHA256 passkey logica behouden, RFCOMM-specifieke code weg |
| `makeAgent.py` | Ongewijzigd hergebruiken |
| `/etc/go_bluetooth.conf` | Formaat behouden voor backwards-compat |

## Wat verwijderd wordt

| Bestand/dependency | Reden |
|--------------------|-------|
| `server.py` | RFCOMM-specifiek |
| `rfcommServerConstants.py` | Vervangen door JSON protocol |
| `go_bt.py` (huidig) | Volledig herschreven |
| `bluedot` dependency | Vervangen door BlueZ D-Bus GATT |
| `netifaces` dependency | Vervangen door subprocess/nmcli |

---

## Configuratiebestand

`/etc/go_bluetooth.conf` — behoud bestaand formaat:

```ini
pass_hash=<sha256 hex van passkey, standaard sha256 van ethernet MAC van end0>
verify_device=true
controller_model=l4   # optioneel, overschrijft DT-detectie
```

---

## Commit- en branchconventies

- Branch: `feature/ble-gatt-rewrite`
- **Elke commit** als `Rick-GO <rickgijsberts@gocontroll.com>` — author én committer, geen co-auteur
- Gebruik altijd: `git -c user.name="Rick-GO" -c user.email="rickgijsberts@gocontroll.com" commit -m "..."`
- Nooit een `Co-Authored-By` trailer toevoegen
- Commit bericht formaat: `type(scope): beschrijving`
