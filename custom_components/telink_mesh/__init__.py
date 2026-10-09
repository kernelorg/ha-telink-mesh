"""Telink BLE mesh lights via Home Assistant Bluetooth (incl. ESPHome proxies)."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN, MANUFACTURER
from .coordinator import TelinkMeshCoordinator, lamp_mac
from .services import async_setup_services

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LIGHT]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

TelinkMeshConfigEntry = ConfigEntry[TelinkMeshCoordinator]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    async_setup_services(hass)
    return True


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
    _async_remove_stale_devices(hass, entry, coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: TelinkMeshConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    await entry.runtime_data.async_shutdown()
    return unload_ok


def _device_lamp_mac(entry: TelinkMeshConfigEntry, device: dr.DeviceEntry) -> str | None:
    """MAC of the lamp a device stands for, or None for the mesh device itself."""
    for domain, identifier in device.identifiers:
        if domain == DOMAIN and (mac := lamp_mac(entry.entry_id, identifier)):
            return mac
    return None


def _async_remove_stale_devices(
    hass: HomeAssistant, entry: TelinkMeshConfigEntry, coordinator: TelinkMeshCoordinator
) -> None:
    """Delete lamp devices the coordinator no longer knows.

    Older versions adopted corrupted advertisements as lamps; dropping them from
    storage alone left their devices (and entities) behind in the registry.
    """
    registry = dr.async_get(hass)
    stale = [
        device
        for device in dr.async_entries_for_config_entry(registry, entry.entry_id)
        if (mac := _device_lamp_mac(entry, device)) is not None and mac not in coordinator.nodes
    ]
    if stale:
        _LOGGER.info(
            "Mesh %s: removing %d stale lamp devices", coordinator.mesh_name, len(stale)
        )
    for device in stale:
        registry.async_update_device(device.id, remove_config_entry_id=entry.entry_id)


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: TelinkMeshConfigEntry, device: dr.DeviceEntry
) -> bool:
    """Let the user delete a lamp device; the mesh device itself stays."""
    mac = _device_lamp_mac(entry, device)
    if mac is None:
        return False
    await entry.runtime_data.async_forget_lamp(mac)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: TelinkMeshConfigEntry) -> None:
    hass.config_entries.async_schedule_reload(entry.entry_id)
