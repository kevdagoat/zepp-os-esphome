import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import text_sensor
from . import ZeppHelio

DEPENDENCIES = ["zepp_helio"]

CONF_ZEPP_HELIO_ID = "zepp_helio_id"
CONF_SLEEP_STAGE = "sleep_stage"
CONF_ACTIVITY_KIND = "activity_kind"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_ZEPP_HELIO_ID): cv.use_id(ZeppHelio),
        cv.Optional(CONF_SLEEP_STAGE): text_sensor.text_sensor_schema(),
        cv.Optional(CONF_ACTIVITY_KIND): text_sensor.text_sensor_schema(),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_ZEPP_HELIO_ID])
    if CONF_SLEEP_STAGE in config:
        ts = await text_sensor.new_text_sensor(config[CONF_SLEEP_STAGE])
        cg.add(parent.set_sleep_stage_sensor(ts))
    if CONF_ACTIVITY_KIND in config:
        ts = await text_sensor.new_text_sensor(config[CONF_ACTIVITY_KIND])
        cg.add(parent.set_activity_kind_sensor(ts))
