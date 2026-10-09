"""Actions (services) of the Telink mesh integration."""

from __future__ import annotations

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv, entity_registry as er
from homeassistant.helpers.service import async_extract_entity_ids

from .const import DOMAIN
from .coordinator import TelinkMeshCoordinator, lamp_mac
from .protocol import DEFAULT_LTK, validate_credentials

SERVICE_SET_MESH_CREDENTIALS = "set_mesh_credentials"
ATTR_MESH_NAME = "mesh_name"
ATTR_MESH_PASSWORD = "mesh_password"
ATTR_LONG_TERM_KEY = "long_term_key"


def _ltk(value: str) -> bytes:
    try:
        key = bytes.fromhex(value.replace(":", "").replace(" ", ""))
    except ValueError as err:
        raise vol.Invalid("long_term_key must be hex") from err
    if len(key) != 16:
        raise vol.Invalid("long_term_key must be 16 bytes (32 hex characters)")
    return key


SET_MESH_CREDENTIALS_SCHEMA = vol.Schema(
    {
        **cv.ENTITY_SERVICE_FIELDS,
        vol.Required(ATTR_MESH_NAME): cv.string,
        vol.Required(ATTR_MESH_PASSWORD): cv.string,
        vol.Optional(ATTR_LONG_TERM_KEY): vol.All(cv.string, _ltk),
    }
)


def _lamps_for_call(
    hass: HomeAssistant, entity_ids: set[str]
) -> list[tuple[TelinkMeshCoordinator, str]]:
    """Map targeted light entities to (coordinator, lamp MAC)."""
    registry = er.async_get(hass)
    lamps: list[tuple[TelinkMeshCoordinator, str]] = []
    for entity_id in sorted(entity_ids):
        entry = registry.async_get(entity_id)
        if entry is None or entry.platform != DOMAIN or entry.config_entry_id is None:
            raise ServiceValidationError(f"{entity_id} is not a Telink mesh lamp")
        config_entry = hass.config_entries.async_get_entry(entry.config_entry_id)
        if config_entry is None or config_entry.state is not ConfigEntryState.LOADED:
            raise ServiceValidationError(f"{entity_id}: its mesh is not loaded")
        mac = lamp_mac(config_entry.entry_id, entry.unique_id)
        if mac is None:
            raise ServiceValidationError(
                f"{entity_id}: pick individual lamps, not the 'All lights' entity"
            )
        lamps.append((config_entry.runtime_data, mac))
    return lamps


async def _async_set_mesh_credentials(call: ServiceCall) -> None:
    hass = call.hass
    name: str = call.data[ATTR_MESH_NAME]
    password: str = call.data[ATTR_MESH_PASSWORD]
    ltk: bytes = call.data.get(ATTR_LONG_TERM_KEY, DEFAULT_LTK)
    try:
        validate_credentials(name, password)
    except ValueError as err:
        raise ServiceValidationError(str(err)) from err

    try:
        entity_ids = await async_extract_entity_ids(call)
    except TypeError:  # Home Assistant before 2026.2 also wants hass
        entity_ids = await async_extract_entity_ids(hass, call)
    if not entity_ids:
        raise ServiceValidationError("select at least one Telink mesh lamp")
    # Move lamps one by one: each change goes over that lamp's own connection.
    for coordinator, mac in _lamps_for_call(hass, entity_ids):
        if coordinator.mesh_name == name and coordinator.password == password:
            continue
        await coordinator.async_set_lamp_credentials(mac, name, password, ltk)


def async_setup_services(hass: HomeAssistant) -> None:
    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_MESH_CREDENTIALS,
        _async_set_mesh_credentials,
        schema=SET_MESH_CREDENTIALS_SCHEMA,
    )
