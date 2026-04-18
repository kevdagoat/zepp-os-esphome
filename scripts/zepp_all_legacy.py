"""Legacy-path multi-type probe for Helio Strap.

Iterates every Huami fetch type we know about, sends the unencrypted
CMD_START_DATE on char 0x0004 (the pre-Zepp-OS activity-control char),
and writes one CSV per type under ./legacy_samples/.

Use this to discover which types the device actually honors via the
legacy backdoor — types that refuse (status != 0x01) get skipped and
reported in the summary.

Auth still required — chunked-2021 session is what makes the device
trust us for any non-public char. Protocol helpers come from zepp_proto.
"""

from __future__ import annotations

import asyncio
import csv
import datetime as dt
import struct
from pathlib import Path

import zepp_proto


CSV_DIR = Path("legacy_samples")

MAC = "<MAC>"
AUTH_KEY = bytes.fromhex("<auth key>")

CHAR_ACTIVITY_CONTROL = "00000004-0000-3512-2118-0009af100700"
CHAR_ACTIVITY_DATA    = "00000005-0000-3512-2118-0009af100700"

CMD_START_DATE = 0x01
CMD_FETCH_DATA = 0x02
CMD_ACK        = 0x03

RESPONSE = 0x10
SUCCESS  = 0x01


# Huami fetch type code → friendly name.
# Matches HuamiFetchDataType.java.
FETCH_TYPES: dict[int, str] = {
    0x01: "activity",
    0x13: "stress_auto",
    0x25: "spo2_normal",
    0x2E: "temperature",
    0x38: "sleep_respiratory_rate",
    0x3A: "resting_hr",
    0x3D: "max_hr",
    0x49: "hrv",
}

LOOKBACK = dt.timedelta(days=7)
MAX_ROUNDS = 20


# --- control/time helpers ------------------------------------------------

def make_time_bytes(when: dt.datetime) -> bytes:
    if when.tzinfo is None:
        when = when.astimezone()
    off = when.utcoffset() or dt.timedelta(0)
    tz_units = int(off.total_seconds() // 60 // 15)
    return struct.pack(
        "<HBBBBBB",
        when.year, when.month, when.day,
        when.hour, when.minute, 0,
        tz_units & 0xFF,
    )


def parse_start_date(value: bytes) -> tuple[int, dt.datetime]:
    if value[0] != RESPONSE or value[1] != CMD_START_DATE:
        raise RuntimeError(f"not a start-date reply: {value.hex()}")
    if value[2] != SUCCESS:
        raise RuntimeError(f"start date status 0x{value[2]:02x}")
    expected = struct.unpack_from("<I", value, 3)[0]
    if expected == 0:
        return 0, dt.datetime.now().astimezone()
    year = struct.unpack_from("<H", value, 7)[0]
    month = value[9]; day = value[10]
    hour = value[11]; minute = value[12]
    second = value[13] if len(value) > 13 else 0
    tz = dt.datetime.now().astimezone().tzinfo
    return expected, dt.datetime(year, month, day, hour, minute, second, tzinfo=tz)


def _ts_from_secs(secs: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(secs).astimezone()


# --- per-type parsers ----------------------------------------------------
# Each returns list[(timestamp, dict_of_fields)]. Byte layouts come from
# Gadgetbridge Fetch*Operation.java.

def parse_temperature(buf: bytes, round_start: dt.datetime):
    samples = []
    ts = round_start
    for i in range(0, len(buf) - len(buf) % 8, 8):
        unk1, raw, unk3, unk4 = struct.unpack_from("<hhhh", buf, i)
        samples.append((ts, {"temperature_c": f"{raw / 100:.2f}",
                             "unk1": unk1, "unk3": unk3, "unk4": unk4}))
        ts += dt.timedelta(minutes=1)
    return samples


def parse_activity(buf: bytes, round_start: dt.datetime):
    # FetchActivityOperation.createSample: 4 bytes (kind, intensity, steps, hr).
    # Extended 8-byte variant exists (+ unk, sleep, deep, rem) — we try 4 first
    # and fall back to 8 if length says so. Helio's sample_size is device-
    # dependent; activity may refuse on legacy path altogether.
    samples = []
    ts = round_start
    size = 4 if len(buf) % 4 == 0 and len(buf) % 8 != 0 else (
        8 if len(buf) % 8 == 0 else 4)
    for i in range(0, len(buf) - len(buf) % size, size):
        kind, intensity, steps, hr = buf[i], buf[i + 1], buf[i + 2], buf[i + 3]
        fields = {"kind": kind, "intensity": intensity, "steps": steps, "hr": hr}
        if size == 8:
            fields.update({
                "unk": buf[i + 4],
                "sleep": buf[i + 5],
                "deep_sleep": buf[i + 6],
                "rem_sleep": buf[i + 7],
            })
        samples.append((ts, fields))
        ts += dt.timedelta(minutes=1)
    return samples


def parse_stress_auto(buf: bytes, round_start: dt.datetime):
    # FetchStressAutoOperation: 1B/min, 0xFF = skip.
    samples = []
    ts = round_start
    for b in buf:
        if b != 0xFF:
            samples.append((ts, {"stress": b}))
        ts += dt.timedelta(minutes=1)
    return samples


def parse_spo2_normal(buf: bytes, round_start: dt.datetime):
    # FetchSpo2NormalOperation: 1B hdr (v=2) + 65B records.
    # Record: ts32, spo2raw(signed byte, <0 = auto flag), 60B unknown tail.
    if len(buf) < 1 or buf[0] != 2:
        return []
    samples = []
    i = 1
    while i + 65 <= len(buf):
        ts_s = struct.unpack_from("<I", buf, i)[0]
        raw = struct.unpack_from("<b", buf, i + 4)[0]
        auto = raw < 0
        spo2 = raw + 128 if auto else raw
        samples.append((_ts_from_secs(ts_s),
                        {"spo2": spo2, "auto": int(auto)}))
        i += 65
    return samples


def _parse_hr_6b(buf: bytes, key: str):
    # Shared layout: ts32, tz_quarter_hours(byte), hr(byte).
    samples = []
    for i in range(0, len(buf) - len(buf) % 6, 6):
        ts_s = struct.unpack_from("<I", buf, i)[0]
        tz = struct.unpack_from("<b", buf, i + 4)[0]
        hr = buf[i + 5]
        samples.append((_ts_from_secs(ts_s),
                        {key: hr, "tz_qhours": tz}))
    return samples


def parse_resting_hr(buf: bytes, round_start: dt.datetime):
    return _parse_hr_6b(buf, "resting_hr")


def parse_max_hr(buf: bytes, round_start: dt.datetime):
    return _parse_hr_6b(buf, "max_hr")


def parse_sleep_resp_rate(buf: bytes, round_start: dt.datetime):
    # FetchSleepRespiratoryRateOperation: ts32, tz8, rate8, unk8, unk8.
    samples = []
    for i in range(0, len(buf) - len(buf) % 8, 8):
        ts_s = struct.unpack_from("<I", buf, i)[0]
        tz = struct.unpack_from("<b", buf, i + 4)[0]
        rate = buf[i + 5]
        unk1 = buf[i + 6]
        unk2 = buf[i + 7]
        samples.append((_ts_from_secs(ts_s),
                        {"respiratory_rate": rate, "tz_qhours": tz,
                         "unk1": unk1, "unk2": unk2}))
    return samples


def parse_hrv(buf: bytes, round_start: dt.datetime):
    # FetchHrvOperation: ts32, unk8, hrv8.
    samples = []
    for i in range(0, len(buf) - len(buf) % 6, 6):
        ts_s = struct.unpack_from("<I", buf, i)[0]
        unk1 = buf[i + 4]
        hrv = buf[i + 5]
        samples.append((_ts_from_secs(ts_s),
                        {"hrv": hrv, "unk1": unk1}))
    return samples


PARSERS = {
    0x01: parse_activity,
    0x13: parse_stress_auto,
    0x25: parse_spo2_normal,
    0x2E: parse_temperature,
    0x38: parse_sleep_resp_rate,
    0x3A: parse_resting_hr,
    0x3D: parse_max_hr,
    0x49: parse_hrv,
}


# --- fetch loop ----------------------------------------------------------

class FetchFailure(RuntimeError):
    """Raised when the device rejects a type — caller moves on."""


async def _drain_control(control_queue: asyncio.Queue, settle: float = 0.5):
    """Let any straggler control replies arrive, then empty the queue."""
    await asyncio.sleep(settle)
    while not control_queue.empty():
        v = control_queue.get_nowait()
        print(f"  [drain] {v.hex()}")


async def _send_ack_and_wait(client, control_queue: asyncio.Queue):
    """Send CMD_ACK + wait briefly for its reply so it can't leak to next type."""
    await client.write_gatt_char(
        CHAR_ACTIVITY_CONTROL, bytes([CMD_ACK, 0x09]), response=False)
    try:
        reply = await asyncio.wait_for(control_queue.get(), timeout=2)
        if not (reply[0] == RESPONSE and reply[1] == CMD_ACK):
            print(f"  post-ack unexpected: {reply.hex()}")
    except asyncio.TimeoutError:
        pass


async def fetch_one_type(client, code: int, name: str,
                         control_queue: asyncio.Queue, data_state: dict):
    print(f"\n=== {name} (0x{code:02X}) ===")
    # Settle + drain before we start so stragglers from the previous
    # type can't be mistaken for this type's first reply.
    await _drain_control(control_queue)

    all_samples: list[tuple[dt.datetime, dict]] = []
    since = dt.datetime.now().astimezone() - LOOKBACK
    since = since.replace(second=0, microsecond=0)
    now_ts = dt.datetime.now().astimezone()

    for round_num in range(1, MAX_ROUNDS + 1):
        data_state["buf"].clear()
        data_state["last_counter"] = -1
        while not control_queue.empty():
            control_queue.get_nowait()

        start_cmd = bytes([CMD_START_DATE, code]) + make_time_bytes(since)
        try:
            await client.write_gatt_char(CHAR_ACTIVITY_CONTROL, start_cmd,
                                         response=False)
        except Exception as exc:
            print(f"  write error: {exc}")
            return all_samples, f"write error: {exc}"

        try:
            reply = await asyncio.wait_for(control_queue.get(), timeout=15)
        except asyncio.TimeoutError:
            return all_samples, "timeout waiting for start-date reply"

        try:
            expected_pkts, actual_start = parse_start_date(reply)
        except RuntimeError as exc:
            return all_samples, str(exc)

        print(f"  round {round_num}: expected={expected_pkts} "
              f"start={actual_start.strftime('%Y-%m-%d %H:%M:%S')}")

        if expected_pkts == 0:
            await _send_ack_and_wait(client, control_queue)
            return all_samples, "ok (no data in window)"

        await client.write_gatt_char(
            CHAR_ACTIVITY_CONTROL, bytes([CMD_FETCH_DATA]), response=False)

        while True:
            try:
                reply = await asyncio.wait_for(control_queue.get(), timeout=60)
            except asyncio.TimeoutError:
                return all_samples, "timeout waiting for fetch-data reply"
            if reply[0] == RESPONSE and reply[1] == CMD_FETCH_DATA:
                if reply[2] != SUCCESS:
                    return all_samples, f"fetch failed 0x{reply[2]:02x}"
                break
            if reply[0] == RESPONSE and reply[1] == CMD_ACK:
                break
            if reply[0] == RESPONSE and reply[1] == CMD_START_DATE:
                # Saw a second start-date reply with a non-success status
                # mid-fetch (e.g. spo2 on legacy: device NAKs the type).
                return all_samples, (
                    f"start-date rejected mid-fetch 0x{reply[2]:02x}"
                )

        await _send_ack_and_wait(client, control_queue)

        parser = PARSERS.get(code)
        raw = bytes(data_state["buf"])
        print(f"  raw {len(raw)}B")
        if parser is None:
            return all_samples, "no parser"

        round_samples = parser(raw, actual_start)
        print(f"  parsed {len(round_samples)} samples")
        all_samples.extend(round_samples)

        if not round_samples:
            return all_samples, "ok (empty parse)"

        last_ts = round_samples[-1][0]
        next_since = last_ts + dt.timedelta(minutes=1)
        if next_since >= now_ts:
            return all_samples, "ok"
        if next_since <= since:
            return all_samples, "ok (no forward progress)"
        since = next_since

    return all_samples, f"ok ({MAX_ROUNDS} rounds hit)"


def write_csv(name: str, samples):
    if not samples:
        return
    CSV_DIR.mkdir(exist_ok=True)
    keys = sorted({k for _, fields in samples for k in fields.keys()})
    path = CSV_DIR / f"{name}.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp"] + keys)
        for ts, fields in samples:
            w.writerow([ts.strftime("%Y-%m-%d %H:%M:%S")] +
                       [fields.get(k, "") for k in keys])
    print(f"  wrote {len(samples)} rows → {path}")


# --- main ----------------------------------------------------------------

async def main():
    print("connecting + authenticating...")
    client, session, _ = await zepp_proto.connect_and_auth(MAC, AUTH_KEY)
    try:
        print(f"auth ok, mtu={session.mtu}")

        control_queue: asyncio.Queue[bytes] = asyncio.Queue()
        data_state: dict = {"buf": bytearray(), "last_counter": -1}

        def on_control(_sender, value: bytearray):
            v = bytes(value)
            print(f"  [ctrl {len(v):3}B] {v.hex()}")
            control_queue.put_nowait(v)

        def on_data(_sender, value: bytearray):
            v = bytes(value)
            if not v:
                return
            counter = v[0]
            expected = (data_state["last_counter"] + 1) & 0xFF
            if data_state["last_counter"] >= 0 and counter != expected:
                print(f"  !! counter gap got={counter} exp={expected}")
            data_state["last_counter"] = counter
            data_state["buf"].extend(v[1:])

        await client.start_notify(CHAR_ACTIVITY_CONTROL, on_control)
        await client.start_notify(CHAR_ACTIVITY_DATA, on_data)

        results: dict[str, tuple[list, str]] = {}
        for code, name in FETCH_TYPES.items():
            try:
                samples, status = await fetch_one_type(
                    client, code, name, control_queue, data_state)
            except Exception as exc:
                samples, status = [], f"exception: {exc}"
            results[name] = (samples, status)
            write_csv(name, samples)

        print("\n=== summary ===")
        for name, (samples, status) in results.items():
            print(f"  {name:<24} {len(samples):>6} samples  [{status}]")

        await client.stop_notify(CHAR_ACTIVITY_CONTROL)
        await client.stop_notify(CHAR_ACTIVITY_DATA)
    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
