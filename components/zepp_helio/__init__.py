import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client, time as time_
from esphome.const import CONF_ID, CONF_TIME_ID

CODEOWNERS = ["@local"]
DEPENDENCIES = ["ble_client", "time"]
AUTO_LOAD = ["sensor", "binary_sensor", "text_sensor"]
MULTI_CONF = True

zepp_helio_ns = cg.esphome_ns.namespace("zepp_helio")
ZeppHelio = zepp_helio_ns.class_(
    "ZeppHelio", cg.Component, ble_client.BLEClientNode
)

CONF_AUTH_KEY = "auth_key"
CONF_CONTROL_PATH = "control_path"

CONTROL_PATH_OPTIONS = ("zeppos", "legacy")

def _validate_hex16(value):
    value = cv.string_strict(value).replace(":", "").replace(" ", "")
    if len(value) != 32:
        raise cv.Invalid("auth_key must be 16 bytes hex (32 chars)")
    try:
        int(value, 16)
    except ValueError:
        raise cv.Invalid("auth_key must be hex")
    return value

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(ZeppHelio),
        cv.Required(CONF_AUTH_KEY): _validate_hex16,
        cv.Required(CONF_TIME_ID): cv.use_id(time_.RealTimeClock),
        cv.Optional(CONF_CONTROL_PATH, default="zeppos"): cv.one_of(
            *CONTROL_PATH_OPTIONS, lower=True
        ),
    }
).extend(cv.COMPONENT_SCHEMA).extend(ble_client.BLE_CLIENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)

    key_hex = config[CONF_AUTH_KEY]
    key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]
    cg.add(var.set_auth_key(key_bytes))

    rtc = await cg.get_variable(config[CONF_TIME_ID])
    cg.add(var.set_time(rtc))

    cg.add(var.set_use_zeppos_control(config[CONF_CONTROL_PATH] == "zeppos"))
