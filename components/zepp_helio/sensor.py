import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import sensor
from esphome.const import (
    DEVICE_CLASS_TEMPERATURE,
    DEVICE_CLASS_POWER_FACTOR,
    STATE_CLASS_MEASUREMENT,
    UNIT_CELSIUS,
    UNIT_BEATS_PER_MINUTE,
    UNIT_PERCENT,
    UNIT_EMPTY,
)
from . import ZeppHelio, zepp_helio_ns

DEPENDENCIES = ["zepp_helio"]

CONF_ZEPP_HELIO_ID = "zepp_helio_id"

# metric → (key, unit, device_class_or_None, decimals)
METRICS = {
    "temperature":        (UNIT_CELSIUS,          DEVICE_CLASS_TEMPERATURE, 2),
    "heart_rate":         (UNIT_BEATS_PER_MINUTE, None,                     0),
    "resting_heart_rate": (UNIT_BEATS_PER_MINUTE, None,                     0),
    "max_heart_rate":     (UNIT_BEATS_PER_MINUTE, None,                     0),
    "steps":              (UNIT_EMPTY,            None,                     0),
    "stress":             (UNIT_EMPTY,            None,                     0),
    "spo2":               (UNIT_PERCENT,          None,                     0),
    "respiratory_rate":   ("br/min",              None,                     0),
    "hrv":                ("ms",                  None,                     0),
    "sample_count":       (UNIT_EMPTY,            None,                     0),
}

def _metric_schema(key):
    unit, dc, dec = METRICS[key]
    kwargs = dict(
        unit_of_measurement=unit,
        accuracy_decimals=dec,
        state_class=STATE_CLASS_MEASUREMENT,
    )
    if dc is not None:
        kwargs["device_class"] = dc
    return sensor.sensor_schema(**kwargs)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_ZEPP_HELIO_ID): cv.use_id(ZeppHelio),
        **{cv.Optional(k): _metric_schema(k) for k in METRICS},
    }
)

SETTER = {
    "temperature":        "set_temperature_sensor",
    "heart_rate":         "set_heart_rate_sensor",
    "resting_heart_rate": "set_resting_hr_sensor",
    "max_heart_rate":     "set_max_hr_sensor",
    "steps":              "set_steps_sensor",
    "stress":             "set_stress_sensor",
    "spo2":               "set_spo2_sensor",
    "respiratory_rate":   "set_resp_rate_sensor",
    "hrv":                "set_hrv_sensor",
    "sample_count":       "set_count_sensor",
}


async def to_code(config):
    parent = await cg.get_variable(config[CONF_ZEPP_HELIO_ID])
    for key, setter in SETTER.items():
        if key in config:
            s = await sensor.new_sensor(config[key])
            cg.add(getattr(parent, setter)(s))
