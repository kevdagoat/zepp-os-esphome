# Helio Strap ESPHome Bridge

ESP32 bridge that connects to an Amazfit Helio Strap (Zepp OS 2021+) over
BLE every 15 minutes, runs the full Huami auth handshake, pulls the last
15 minutes of sensor data, and publishes the values as Home Assistant
sensors via the ESPHome native API.

Port of `amazfit/zepp_proto.py` + `amazfit/zepp_temp_legacy.py` +
`amazfit/huami_ecdh.py` to an ESPHome external component.

Ported by Claude Code 

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
| `battery_level`      |   0x0029 † |      21 B   | `ZeppOsBatteryService` / `HuamiBatteryInfo`    |
| `sample_count`       |         —  |          —  | total samples parsed across all types          |

† Battery is not a fetch-queue type — it's a one-shot request on the
chunked-2021 encrypted pipe at endpoint `0x0029`. Fired right after
auth success; the reply lands in `handle_battery_reply_()` and
publishes immediately without waiting for the legacy activity fetch.

HR and steps are **gated on wear state**: if the latest activity record
has `kind` == `NOT_WORN` / `CHARGING` / `UNSET`, those cache slots are
not updated — last-known-valid value is retained instead of being
overwritten with an off-wrist `0xFF`.

### Incremental fetch (per-type `last_seen` state)

The firmware keeps an in-RAM `last_seen[type]` timestamp and uses
`max(last_seen + 1s, now - max_lookback)` as the `since` for each
fetch. Steady-state behavior:

- **First cycle after boot** pulls one `max_lookback` window per type
  (default 24 h). On Helio this is ~7.5 kB for activity + temperature
  combined, a few hundred bytes for everything else.
- **Every subsequent cycle** pulls only the records that are newer
  than the last one we saw — typically seconds of wall-clock data,
  not the full 15 min poll interval. Wire traffic drops to near zero
  for sparse types (HRV, resting HR, max HR) that haven't updated.
- **`latest_` cache is NOT cleared between cycles**, so if a type
  returns zero records this cycle, the sensor stays at its last
  published value instead of disappearing.

`max_lookback` is a YAML knob (default `24h`) — it's a safety cap
that only matters on a cold boot or if the ESP32 has been offline
long enough that the device has rolled old data off its internal
ring buffer. In normal operation each type's actual window is
driven by `last_seen`, not this value.

### Historical backfill → HA `recorder.import_statistics`

On first flash the firmware can backfill Home Assistant's historical
charts via 5-minute-bucketed external statistics. Config:

```yaml
zepp_helio:
  first_run_lookback: 24h    # how far back to pull on a fresh flash
  on_statistic_ready:
    - homeassistant.service:
        service: recorder.import_statistics
        data:
          statistic_id: !lambda 'return std::string("esphome:helio_") + type;'
          source: esphome
          name: !lambda 'return std::string("Helio ") + type;'
          has_mean: "true"
          has_sum: "false"
        data_template:
          stats: !lambda |-
            char buf[256];
            snprintf(buf, sizeof(buf),
              "{{ [{'start':'%s','mean':%.3f,'min':%.3f,'max':%.3f}] }}",
              start.c_str(), mean_value, min_value, max_value);
            return std::string(buf);
```

**How it works:**

1. **Per-type `last_import_ts`** is persisted to ESP32 NVS. Zero means
   "never imported" → next fetch uses `first_run_lookback`. Non-zero
   means steady-state delta → `since = last_import_ts + 1s`.
2. **During parse**, each numeric record lands in a 5-minute bucket
   accumulator (`active_buckets_` map keyed on `ts / 300 * 300`).
   Activity contributes `hr` (the chart-worthy field).
3. **At end of each type**, buckets are flattened into `pending_stats_`
   with `{type, start_iso, mean, min, max, count, type_idx}`.
4. **`loop()` pumps** one `PendingStat` through all registered triggers
   per 100 ms — keeps HA's API queue from backing up on a first-run
   dump (24h × 60/5 × 2 per-minute types ≈ 576 calls ≈ ~1 min pump).
5. **After the pending queue drains**, `last_import_ts_[i]` for every
   type that contributed buckets this cycle is committed to NVS via
   `ESPPreferenceObject::save` + `global_preferences->sync()`.
6. **On the HA side**, `stats` is sent as a `data_template` value
   wrapped in `{{ … }}` so HA's Jinja2 renderer evaluates the string
   into a real `list[dict]` before `recorder.import_statistics`
   receives it.

**Statistics IDs land as `esphome:helio_<type>`** in HA's external
statistics store (visible in Developer Tools → Statistics and the
Long-term Statistics card on dashboards). They are **not attached to
the `sensor.helio_*` entities** — HA treats external statistics as a
separate namespace. That's a limitation of `import_statistics` with
`source: esphome`, not something the component can fix.

**What gets bucketed:**

| Type | Statistic ID | Bucketed value |
|------|-------------|----------------|
| `heart_rate` (0x01) | `esphome:helio_heart_rate` | HR from activity record (worn + non-sentinel only) |
| `stress` (0x13) | `esphome:helio_stress` | stress byte (0xFF skipped) |
| `spo2` (0x25) | `esphome:helio_spo2` | parsed SpO2 % |
| `temperature` (0x2E) | `esphome:helio_temperature` | skin temp in °C |
| `respiratory_rate` (0x38) | `esphome:helio_respiratory_rate` | rate byte |
| `resting_heart_rate` (0x3A) | `esphome:helio_resting_heart_rate` | HR byte |
| `max_heart_rate` (0x3D) | `esphome:helio_max_heart_rate` | HR byte |
| `hrv` (0x49) | `esphome:helio_hrv` | HRV byte |

Text/binary sensors (sleep_stage, worn, activity_kind, charging) are
not bucketed — `import_statistics` only accepts numeric mean/min/max.
Those continue to publish as regular `latest_` cache values only.

### Binary sensors (`binary_sensor:`)

| Sensor     | Source                              | True when                                        |
|------------|-------------------------------------|--------------------------------------------------|
| `worn`     | activity `kind` byte (0x01 @ off 0) | `kind ∉ {115 NOT_WORN, 118 CHARGING, 0xFF UNSET}` |
| `charging` | battery reply byte 3 (0x0029)       | `state == 1` (DEVICE_BATTERY_CHARGING)           |

`worn` gets `device_class: occupancy` so Home Assistant renders it as
occupied / not occupied and it drops into presence automations
naturally. `charging` gets `device_class: battery_charging`.

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

