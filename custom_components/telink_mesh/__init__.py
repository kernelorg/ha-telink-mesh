"""Telink BLE mesh lights via Home Assistant Bluetooth (incl. ESPHome proxies)."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN, MANUFACTURER
from .coordinator import TelinkMeshCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LIGHT]

TelinkMeshConfigEntry = ConfigEntry[TelinkMeshCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: TelinkMeshConfigEntry) -> bool:
    coordinator = TelinkMeshCoordinator(hass, entry)
    await coordinator.async_setup()
    entry.runtime_data = coordinator

    dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.entry_id)},
        name=f"Telink mesh {coordinator.mesh_name}",
        manufacturer=MANUFACTURER,
        model="BLE mesh",
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: TelinkMeshConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    await entry.runtime_data.async_shutdown()
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: TelinkMeshConfigEntry) -> None:
    hass.config_entries.async_schedule_reload(entry.entry_id)
