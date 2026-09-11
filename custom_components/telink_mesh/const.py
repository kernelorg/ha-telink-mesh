"""Constants for the Telink mesh integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "telink_mesh"

CONF_MESH_NAME: Final = "mesh_name"
CONF_MESH_PASSWORD: Final = "mesh_password"
CONF_PROFILE: Final = "profile"
CONF_COLOR_MODE: Final = "color_mode"
CONF_WRITE_WITH_RESPONSE: Final = "write_with_response"
CONF_POLL_INTERVAL: Final = "poll_interval"
CONF_ADDRESS: Final = "address"

PROFILE_LIVARNO: Final = "livarno"
PROFILE_GENERIC: Final = "generic"
PROFILES: Final = [PROFILE_LIVARNO, PROFILE_GENERIC]
DEFAULT_PROFILE: Final = PROFILE_LIVARNO

# Vendor credential presets. Each preset auto-fills the mesh name, password and a
# sensible command profile / colour mode for a known product line. "manual" lets
# the user type everything by hand. Keep "manual" last.
PRESET_MANUAL: Final = "manual"
CREDENTIAL_PRESETS: Final = {
    "mesh_lamp": {
        CONF_MESH_NAME: "Fulife",
        CONF_MESH_PASSWORD: "2846",
        CONF_PROFILE: PROFILE_LIVARNO,
        CONF_COLOR_MODE: "rgb_ct",
    },
}
PRESETS: Final = [*CREDENTIAL_PRESETS, PRESET_MANUAL]
DEFAULT_PRESET: Final = next(iter(CREDENTIAL_PRESETS))

COLOR_MODE_RGB_CT: Final = "rgb_ct"
COLOR_MODE_RGB: Final = "rgb"
COLOR_MODE_CT: Final = "ct"
COLOR_MODE_BRIGHTNESS: Final = "brightness"
COLOR_MODE_ONOFF: Final = "onoff"
COLOR_MODES: Final = [
    COLOR_MODE_RGB_CT,
    COLOR_MODE_RGB,
    COLOR_MODE_CT,
    COLOR_MODE_BRIGHTNESS,
    COLOR_MODE_ONOFF,
]
DEFAULT_COLOR_MODE: Final = COLOR_MODE_RGB_CT

DEFAULT_WRITE_WITH_RESPONSE: Final = False
DEFAULT_POLL_INTERVAL: Final = 60
MIN_POLL_INTERVAL: Final = 10
MAX_POLL_INTERVAL: Final = 600

DEFAULT_MESH_NAME: Final = "telink_mesh1"
DEFAULT_MESH_PASSWORD: Final = "123"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = f"{DOMAIN}.nodes"

SIGNAL_NEW_NODE: Final = f"{DOMAIN}_new_node"
SIGNAL_UPDATE: Final = f"{DOMAIN}_update"

# Seconds without any report after which a node is shown as unavailable.
NODE_STALE_SECONDS: Final = 600

# Reconnect back-off (seconds).
RECONNECT_DELAYS: Final = (2, 5, 10, 20, 30, 60)

MANUFACTURER: Final = "Telink"
