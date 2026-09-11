"""Light entities for Telink mesh nodes."""

from __future__ import annotations

from typing import Any

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_RGB_COLOR,
    ColorMode,
    LightEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    COLOR_MODE_BRIGHTNESS,
    COLOR_MODE_CT,
    COLOR_MODE_ONOFF,
    COLOR_MODE_RGB,
    COLOR_MODE_RGB_CT,
    DOMAIN,
    MANUFACTURER,
    SIGNAL_NEW_NODE,
)
from .coordinator import TelinkMeshCoordinator, TelinkNode
from .protocol import ADDR_ALL, MAX_KELVIN, MIN_KELVIN

_SUPPORTED: dict[str, set[ColorMode]] = {
    COLOR_MODE_RGB_CT: {ColorMode.RGB, ColorMode.COLOR_TEMP},
    COLOR_MODE_RGB: {ColorMode.RGB},
    COLOR_MODE_CT: {ColorMode.COLOR_TEMP},
    COLOR_MODE_BRIGHTNESS: {ColorMode.BRIGHTNESS},
    COLOR_MODE_ONOFF: {ColorMode.ONOFF},
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TelinkMeshCoordinator = entry.runtime_data
    known: set[int] = set()

    @callback
    def _add_node(node: TelinkNode) -> None:
        if node.mesh_id in known:
            return
        known.add(node.mesh_id)
        async_add_entities([TelinkNodeLight(coordinator, node)])

    entities: list[LightEntity] = [TelinkMeshAllLight(coordinator)]
    for node in list(coordinator.nodes.values()):
        known.add(node.mesh_id)
        entities.append(TelinkNodeLight(coordinator, node))
    async_add_entities(entities)

    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_NEW_NODE}_{entry.entry_id}", _add_node)
    )


def _to_ha_brightness(level: int) -> int:
    return max(0, min(255, round(level * 255 / 100)))


def _to_mesh_brightness(value: int) -> int:
    return max(1, min(100, round(value * 100 / 255)))


class _TelinkLightBase(LightEntity):
    """Shared behaviour of node and group lights."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_min_color_temp_kelvin = MIN_KELVIN
    _attr_max_color_temp_kelvin = MAX_KELVIN

    def __init__(self, coordinator: TelinkMeshCoordinator) -> None:
        self.coordinator = coordinator
        self._attr_supported_color_modes = _SUPPORTED.get(
            coordinator.color_mode, _SUPPORTED[COLOR_MODE_RGB_CT]
        )

    @property
    def target(self) -> int:
        raise NotImplementedError

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self.async_write_ha_state))

    def _resolve_color_mode(self, rgb: tuple[int, int, int] | None, kelvin: int | None) -> ColorMode:
        modes = self._attr_supported_color_modes or set()
        if ColorMode.RGB in modes and rgb is not None and kelvin is None:
            return ColorMode.RGB
        if ColorMode.COLOR_TEMP in modes:
            return ColorMode.COLOR_TEMP
        if ColorMode.RGB in modes:
            return ColorMode.RGB
        if ColorMode.BRIGHTNESS in modes:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    async def async_turn_on(self, **kwargs: Any) -> None:
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        rgb = kwargs.get(ATTR_RGB_COLOR)
        kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        await self.coordinator.async_turn_on(
            self.target,
            brightness=_to_mesh_brightness(brightness) if brightness is not None else None,
            rgb=tuple(rgb) if rgb is not None else None,
            color_temp_kelvin=int(kelvin) if kelvin is not None else None,
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_turn_off(self.target)


class TelinkNodeLight(_TelinkLightBase):
    """One lamp of the mesh."""

    def __init__(self, coordinator: TelinkMeshCoordinator, node: TelinkNode) -> None:
        super().__init__(coordinator)
        self._node = node
        entry_id = coordinator.entry.entry_id
        self._attr_unique_id = f"{entry_id}_{node.mesh_id}"
        self._attr_name = None
        connections = {(CONNECTION_BLUETOOTH, node.mac)} if node.mac else set()
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry_id}_{node.mesh_id}")},
            connections=connections,
            name=node.name or f"{coordinator.mesh_name} {node.mesh_id}",
            manufacturer=MANUFACTURER,
            model=f"Mesh node 0x{node.mesh_id:02X}",
            via_device=(DOMAIN, entry_id),
        )

    @property
    def target(self) -> int:
        return self._node.mesh_id

    @property
    def available(self) -> bool:
        if not self.coordinator.connected:
            return False
        # Without status notifications we cannot know per-node online state, so
        # follow the mesh connection instead of leaving the light unavailable.
        return self.coordinator.optimistic or self._node.online

    @property
    def is_on(self) -> bool:
        return self._node.is_on

    @property
    def brightness(self) -> int | None:
        return _to_ha_brightness(self._node.brightness) if self._node.brightness else None

    @property
    def rgb_color(self) -> tuple[int, int, int] | None:
        return self._node.rgb

    @property
    def color_temp_kelvin(self) -> int | None:
        return self._node.color_temp_kelvin

    @property
    def color_mode(self) -> ColorMode:
        return self._resolve_color_mode(self._node.rgb, self._node.color_temp_kelvin)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "mesh_id": self._node.mesh_id,
            "mac": self._node.mac,
            "rssi": self._node.rssi,
            "connected_via": self.coordinator.connected_address,
        }


class TelinkMeshAllLight(_TelinkLightBase):
    """Broadcast light controlling every node of the mesh at once."""

    _attr_translation_key = "all_lights"

    def __init__(self, coordinator: TelinkMeshCoordinator) -> None:
        super().__init__(coordinator)
        entry_id = coordinator.entry.entry_id
        self._attr_unique_id = f"{entry_id}_all"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    @property
    def target(self) -> int:
        return ADDR_ALL

    @property
    def available(self) -> bool:
        return self.coordinator.connected

    def _online_nodes(self) -> list[TelinkNode]:
        return [n for n in self.coordinator.nodes.values() if n.online]

    @property
    def is_on(self) -> bool:
        return any(n.is_on for n in self._online_nodes())

    @property
    def brightness(self) -> int | None:
        levels = [n.brightness for n in self._online_nodes() if n.is_on and n.brightness]
        return _to_ha_brightness(max(levels)) if levels else None

    @property
    def rgb_color(self) -> tuple[int, int, int] | None:
        for node in self._online_nodes():
            if node.is_on and node.rgb:
                return node.rgb
        return None

    @property
    def color_temp_kelvin(self) -> int | None:
        for node in self._online_nodes():
            if node.is_on and node.color_temp_kelvin:
                return node.color_temp_kelvin
        return None

    @property
    def color_mode(self) -> ColorMode:
        return self._resolve_color_mode(self.rgb_color, self.color_temp_kelvin)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "connected_via": self.coordinator.connected_address,
            "nodes_online": len(self._online_nodes()),
            "nodes_total": len(self.coordinator.nodes),
        }
