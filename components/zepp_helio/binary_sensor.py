import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor
from esphome.const import DEVICE_CLASS_OCCUPANCY
from . import ZeppHelio

DEPENDENCIES = ["zepp_helio"]

CONF_ZEPP_HELIO_ID = "zepp_helio_id"
CONF_WORN = "worn"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_ZEPP_HELIO_ID): cv.use_id(ZeppHelio),
        cv.Optional(CONF_WORN): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_OCCUPANCY,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_ZEPP_HELIO_ID])
    if CONF_WORN in config:
        bs = await binary_sensor.new_binary_sensor(config[CONF_WORN])
        cg.add(parent.set_worn_sensor(bs))
