# Helio Strap ESPHome Bridge

ESP32 bridge that connects to an Amazfit Helio Strap (Zepp OS 2021+) over
BLE every 15 minutes, runs the full Huami auth handshake, pulls the last
15 minutes of sensor data, and publishes the values as Home Assistant
sensors via the ESPHome native API.

Port of `amazfit/zepp_proto.py` + `amazfit/zepp_temp_legacy.py` +
`amazfit/huami_ecdh.py` to an ESPHome external component.

## Status

**Scaffold.** Protocol logic is ported and cross-checked against
Gadgetbridge source, but the firmware has not been flashed to hardware
yet. Known gaps are listed at the bottom — fix those before expecting a
successful boot.

## Layout

```
esphome/
├── helio.yaml                           device config
├── secrets.yaml                         (you create — wifi/api/ota)
└── components/zepp_helio/
    ├── __init__.py                      ESPHome codegen
    ├── sensor.py                        per-metric sensor schemas
    ├── ecdh_b163.{h,cpp}                sect163k1 ECDH (port of huami_ecdh.py)
    └── zepp_helio.{h,cpp}               auth + chunked framing + fetch SM
```

## Hardware

- Any ESP32 with BLE (tested target: generic `esp32dev`).
- Helio Strap paired once with the Zepp app so it has a stored auth key.

## Setup

1. **Extract the auth key** from your Zepp install - see https://codeberg.org/argrento/huami-token

2. **Create `esphome/secrets.yaml`:**

   ```yaml
   wifi_ssid: your-ssid
   wifi_password: your-wifi-password
   api_key: <32-byte base64 key>        # openssl rand -base64 32
   ota_password: your-ota-password
   ```

3. **Set the Helio MAC + auth key in `helio.yaml`:**

   ```yaml
   ble_client:
     - mac_address: # <- your device MAC

   zepp_helio:
     auth_key: # <- your 16-byte key
   ```

4. **Compile and flash:**

   ```bash
   cd amazfit/esphome
   esphome run helio.yaml
   ```

## Metrics

Every 15 minutes the component connects, authenticates, and iterates the
fetch-type list inside one session. For each type the latest non-sentinel
value in the window is published as an HA sensor. All 8 data types are
confirmed working on Helio via the legacy control path (see
`amazfit/zepp_all_legacy.py`); Gadgetbridge byte layouts cross-checked.

### Numeric sensors (`sensor:`)

| Sensor               | Huami code | Record size | Source                                         |
|----------------------|-----------:|------------:|------------------------------------------------|
| `temperature`        |      0x2E  |        8 B  | `FetchTemperatureOperation` (int16 @ offset 2) |
| `heart_rate`         |      0x01  |      **8 B**| `FetchActivityOperation.createExtendedSample`  |
| `steps`              |      0x01  |        8 B  | same activity sample, byte 2                   |
| `stress`             |      0x13  |        1 B  | `FetchStressAutoOperation` (0xFF = skip)       |
| `spo2`               |      0x25  | 1 + 65 B    | `FetchSpo2NormalOperation` (v=2 header)        |
| `resting_heart_rate` |      0x3A  |        6 B  | `FetchHeartRateRestingOperation`               |
| `max_heart_rate`     |      0x3D  |        6 B  | `FetchHeartRateMaxOperation`                   |
| `respiratory_rate`   |      0x38  |        8 B  | `FetchSleepRespiratoryRateOperation`           |
| `hrv`                |      0x49  |        6 B  | `FetchHrvOperation`                            |
| `sample_count`       |         —  |          —  | total samples parsed across all types          |

HR and steps are **gated on wear state**: if the latest activity record
has `kind` == `NOT_WORN` / `CHARGING` / `UNSET`, those cache slots are
not updated — last-known-valid value is retained instead of being
overwritten with an off-wrist `0xFF`.

### Binary sensors (`binary_sensor:`)

| Sensor | Source                              | True when                                        |
|--------|-------------------------------------|--------------------------------------------------|
| `worn` | activity `kind` byte (0x01 @ off 0) | `kind ∉ {115 NOT_WORN, 118 CHARGING, 0xFF UNSET}` |

`device_class: occupancy`, so Home Assistant renders it as
occupied / not occupied and it drops into presence automations
naturally.

### Text sensors (`text_sensor:`)

| Sensor          | Values                                                              |
|-----------------|---------------------------------------------------------------------|
| `sleep_stage`   | `light` / `deep` / `rem` / `awake` / `none`                         |
| `activity_kind` | `running` / `not_worn` / `charging` / `sleep_light` / `sleep_deep` / `sleep_rem` / `sleep_awake` / `awake` / `unset` |

`sleep_stage` is a narrow view of `activity_kind` that only reports
the four sleep stages and returns `none` when the band is awake-worn
or off-wrist. Drop-in for sleep graphs and template sensors without
having to map the full kind enum.

### The Huami extended `kind` enum

Source of truth: `HuamiExtendedSampleProvider.java`. Mirrored in
`zepp_helio.h` as `enum HuamiExtKind` plus inline helpers
`huami_kind_is_worn`, `huami_kind_is_sleep`, `huami_kind_to_string`,
and `huami_kind_to_sleep_stage`.

| Code | Name                  | Meaning                               |
|-----:|-----------------------|---------------------------------------|
|  64  | `HEK_OUTDOOR_RUNNING` | running workout in progress           |
| 115  | `HEK_NOT_WORN`        | band off wrist                        |
| 118  | `HEK_CHARGING`        | on the charger (treated as off-wrist) |
| 120  | `HEK_SLEEP_LIGHT`     | light sleep                           |
| 121  | `HEK_SLEEP_DEEP`      | deep sleep                            |
| 122  | `HEK_SLEEP_REM`       | REM sleep                             |
| 123  | `HEK_SLEEP_AWAKE`     | awake during a sleep session          |
| 0xFF | `HEK_UNSET`           | nothing recorded for this minute      |

Anything else (no explicit enum entry) is reported as `awake` —
worn with no sleep-session or workout flag.

### Adding more metrics

Fetch type list lives in `zepp_helio.h` as `fetch_types_`. Add or
remove codes there — any extra codes from `HuamiFetchDataType.java`
work as long as you add a matching parser branch in
`parse_buffer_for_type_()` and wire a sensor setter in `sensor.py` /
`binary_sensor.py` / `text_sensor.py`.

## Protocol layers (in order)

1. **Connect + MTU negotiation** (ESP32 default request; higher is better).
2. **Chunked-2021 auth handshake** on chars `0x0016` / `0x0017`:
   - Send `CMD_PUB_KEY (0x04)` with our ECDH public key.
   - Receive device random (16 B) + remote public key (48 B).
   - Derive session key = `shared[8..24] XOR auth_key`.
   - Send `CMD_SESSION_KEY (0x05)` with AES-ECB(auth_key, random) and
     AES-ECB(session_key, random) concatenated.
3. **Legacy activity fetch** on chars `0x0004` / `0x0005`:
   - `CMD_START_DATE (0x01)` + 1-byte type + 8-byte time → device replies
     with expected packet count + actual round start timestamp.
   - `CMD_FETCH_DATA (0x02)` → device streams counter-prefixed chunks on
     the data characteristic, terminated by a `0x10 0x02 0x01 <crc32>`
     control reply.
   - `CMD_ACK (0x03 0x09)` → advance to next fetch type.
4. Disconnect, wait 15 min, repeat.

Step 3 is unencrypted even though the auth session is established — the
Helio still honors the Mi Band 4 / Amazfit Bip U legacy path for these
data types. See `amazfit/zepp_temp_legacy.py` comments for why.

## Outstanding risks (hardware verification)

- **ECDH KAT.** Self-test is self-consistency only. A bit flip in the
  port could still produce symmetric but wrong output. Cheap
  insurance: embed one priv/pub vector from Python and memcmp.

- **ESPHome ble_client API drift.** `parent()->get_remote_bda()` and
  `parent()->get_characteristic(svc, chr)` depend on the ble_client
  version in your ESPHome install. If either fails to compile, store
  `param->open.remote_bda` in `OPEN_EVT` and walk
  `parent()->services_` manually.

- **Data counter gap handling.** Current code logs a warning but
  continues. Gadgetbridge's `AbstractFetchOperation` actually retries
  on counter mismatch. If you see frequent gap warnings, port the
  retry logic.

## Debugging

- `logger: level: DEBUG` is already set. First boot logs should show:
  - BLE connect + MTU
  - Service discovery completion
  - Auth handshake: pub key sent, session key sent, `auth success`
  - Per type: `fetching type 0x??` → `type 0x?? parsed N samples`
  - Final `fetch ok, total N samples across types`

- Sample count staying at 0 → handles not resolved or subscribe failed.
- `wrong auth key` → `auth_key` in YAML doesn't match the paired key.
- Control notify arrives but data notify never does → check
  `register_for_notify` is called on **both** chars `0x04` **and**
  `0x05`, and the CCCD descriptor write actually went through.

