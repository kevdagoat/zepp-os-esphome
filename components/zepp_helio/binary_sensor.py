import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor
from esphome.const import DEVICE_CLASS_OCCUPANCY, DEVICE_CLASS_BATTERY_CHARGING
from . import ZeppHelio

DEPENDENCIES = ["zepp_helio"]

CONF_ZEPP_HELIO_ID = "zepp_helio_id"
CONF_WORN = "worn"
CONF_CHARGING = "charging"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_ZEPP_HELIO_ID): cv.use_id(ZeppHelio),
        cv.Optional(CONF_WORN): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_OCCUPANCY,
        ),
        cv.Optional(CONF_CHARGING): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_BATTERY_CHARGING,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_ZEPP_HELIO_ID])
    if CONF_WORN in config:
        bs = await binary_sensor.new_binary_sensor(config[CONF_WORN])
        cg.add(parent.set_worn_sensor(bs))
    if CONF_CHARGING in config:
        bs = await binary_sensor.new_binary_sensor(config[CONF_CHARGING])
        cg.add(parent.set_charging_sensor(bs))
