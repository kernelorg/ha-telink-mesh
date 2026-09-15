"""Mesh coordinator: one direct BLE connection per lamp.

Lamps of one Telink mesh share a mesh name and password but do not always relay
for each other (they may be in different rooms). So instead of connecting to a
single node and relying on mesh relay, this coordinator keeps a direct
connection to every lamp it discovers and writes each command straight to that
lamp's own GATT link (broadcast address over a dedicated connection). The
"All lights" entity fans a command out to every connection.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import time
from typing import Any

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
import homeassistant.util.dt as dt_util

from .const import (
    CONF_COLOR_MODE,
    CONF_COLOR_TEMP_MAX,
    CONF_COLOR_TEMP_MIN,
    CONF_MESH_NAME,
    CONF_MESH_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_PROFILE,
    CONF_WRITE_WITH_RESPONSE,
    DEFAULT_COLOR_MODE,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_PROFILE,
    DEFAULT_WRITE_WITH_RESPONSE,
    RECONNECT_DELAYS,
    SIGNAL_NEW_NODE,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from .mesh import TelinkAuthError, TelinkConnectionError, TelinkMeshConnection
from .protocol import (
    ADDR_ALL,
    ADV_SERVICE_UUID,
    OP_ONLINE_STATUS,
    OP_STATUS_REPORT,
    OP_TIME_SET,
    TELINK_MANUFACTURER_ID,
    Notification,
    TelinkProtocolError,
    get_profile,
    parse_online_status,
    parse_status_report,
    time_set_params,
    yw_to_kelvin,
)

_LOGGER = logging.getLogger(__name__)

COMMAND_GAP = 0.05
REFRESH_AFTER_COMMAND = 2.0
SAVE_DELAY = 10
AVAILABLE_GRACE = 180.0
COMMAND_CONNECT_WAIT = 15.0


@dataclass
class TelinkNode:
    """State of one lamp."""

    mac: str
    mesh_id: int
    name: str | None = None
    is_on: bool = False
    brightness: int = 0  # 0..100
    rgb: tuple[int, int, int] | None = None
    color_temp_kelvin: int | None = None
    online: bool = False
    last_seen: float = 0.0
    rssi: int | None = None

    def to_storage(self) -> dict[str, Any]:
        return {"mac": self.mac, "mesh_id": self.mesh_id, "name": self.name}

    @classmethod
    def from_storage(cls, data: dict[str, Any]) -> TelinkNode | None:
        mac = data.get("mac")
        if not mac or mac.upper() == "00:00:00:00:00:00":
            return None
        return cls(mac=mac.upper(), mesh_id=int(data.get("mesh_id", mesh_id_from_mac(mac))), name=data.get("name"))


def mesh_id_from_mac(mac: str) -> int:
    """Telink lamps use the last MAC octet as their mesh id."""
    return int(mac.split(":")[-1], 16)


def is_telink_advertisement(service_info: BluetoothServiceInfoBleak) -> bool:
    """Return True when the advertisement comes from a Telink mesh device."""
    return (
        TELINK_MANUFACTURER_ID in service_info.manufacturer_data
        or ADV_SERVICE_UUID in service_info.service_uuids
    )


def advertised_mesh_name(service_info: BluetoothServiceInfoBleak) -> str | None:
    """Return the mesh name carried in the scan response, if any."""
    name = service_info.name
    if not name or name.replace(":", "").replace("-", "").upper() == service_info.address.replace(":", "").upper():
        return None
    return name


class LampLink:
    """Owns the BLE connection to one lamp and drives it directly."""

    def __init__(self, coordinator: TelinkMeshCoordinator, node: TelinkNode) -> None:
        self.coordinator = coordinator
        self.node = node
        self._conn = TelinkMeshConnection(
            coordinator.mesh_name,
            coordinator.password,
            notification_callback=self._on_notification,
            disconnected_callback=self._on_disconnect,
            write_with_response=coordinator.write_with_response,
        )
        self._wake = asyncio.Event()
        self._connected_event = asyncio.Event()
        self._last_connected = 0.0
        self._stopping = False
        self._command_lock = asyncio.Lock()
        self._refresh_handle: asyncio.TimerHandle | None = None

    def start(self) -> None:
        self.coordinator.entry.async_create_background_task(
            self.coordinator.hass,
            self._loop(),
            name=f"telink_mesh {self.coordinator.mesh_name} {self.node.mac}",
        )

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._refresh_handle:
            self._refresh_handle.cancel()
            self._refresh_handle = None
        await self._conn.disconnect()

    @property
    def connected(self) -> bool:
        return self._conn.connected

    @property
    def notifications_enabled(self) -> bool:
        return self._conn.notifications_enabled

    @property
    def address(self) -> str | None:
        return self._conn.address

    @property
    def available(self) -> bool:
        if self._conn.connected:
            return True
        if self._stopping or not self._last_connected:
            return False
        return (time.monotonic() - self._last_connected) < AVAILABLE_GRACE

    def poke(self, rssi: int | None) -> None:
        if rssi is not None:
            self.node.rssi = rssi
        if not self._conn.connected:
            self._wake.set()

    async def _loop(self) -> None:
        attempt = 0
        while not self._stopping:
            if self._conn.connected:
                self._wake.clear()
                await self._wake.wait()
                continue

            device = bluetooth.async_ble_device_from_address(
                self.coordinator.hass, self.node.mac, connectable=True
            )
            if device is not None:
                try:
                    await self._conn.connect(device)
                except TelinkAuthError:
                    _LOGGER.error(
                        "Mesh %s: lamp %s rejected the mesh name/password",
                        self.coordinator.mesh_name,
                        self.node.mac,
                    )
                    self.coordinator.auth_failed = True
                    self.coordinator.entry.async_start_reauth(self.coordinator.hass)
                    return
                except TelinkConnectionError as err:
                    _LOGGER.log(
                        logging.WARNING if attempt == 0 else logging.DEBUG,
                        "Mesh %s: could not connect to lamp %s: %s",
                        self.coordinator.mesh_name,
                        self.node.mac,
                        err,
                    )
                else:
                    attempt = 0
                    now = time.monotonic()
                    self._last_connected = now
                    self._connected_event.set()
                    self.node.online = True
                    self.node.last_seen = now
                    _LOGGER.info(
                        "Mesh %s: connected to lamp %s (0x%02X)%s",
                        self.coordinator.mesh_name,
                        self.node.mac,
                        self.node.mesh_id,
                        "" if self._conn.notifications_enabled else " (optimistic)",
                    )
                    self.coordinator.notify_listeners()
                    await self._post_connect()
                    continue

            delay = RECONNECT_DELAYS[min(attempt, len(RECONNECT_DELAYS) - 1)]
            attempt += 1
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), delay)
            except asyncio.TimeoutError:
                pass

    async def _post_connect(self) -> None:
        now = dt_util.now()
        await self._try(
            self.node.mesh_id,
            OP_TIME_SET,
            time_set_params(now.year, now.month, now.day, now.hour, now.minute, now.second),
        )
        await asyncio.sleep(COMMAND_GAP)
        await self._try(self.node.mesh_id, *self.coordinator.profile.status_query())

    async def _try(self, target: int, opcode: int, params: bytes) -> bool:
        try:
            await self._conn.send(target, opcode, params)
        except TelinkConnectionError as err:
            _LOGGER.debug("Mesh %s: lamp %s send failed: %s", self.coordinator.mesh_name, self.node.mac, err)
            return False
        return True

    async def async_send(self, target: int, opcode: int, params: bytes) -> None:
        if not self._conn.connected:
            self._wake.set()
            try:
                await asyncio.wait_for(self._connected_event.wait(), COMMAND_CONNECT_WAIT)
            except asyncio.TimeoutError:
                raise HomeAssistantError(
                    f"Telink lamp {self.node.mac} is not connected"
                ) from None
        try:
            await self._conn.send(target, opcode, params)
        except TelinkConnectionError as err:
            self._wake.set()
            raise HomeAssistantError(f"Telink lamp {self.node.mac}: {err}") from err

    def schedule_refresh(self) -> None:
        if self._refresh_handle:
            self._refresh_handle.cancel()

        def _fire() -> None:
            self._refresh_handle = None
            if self._conn.connected:
                self.coordinator.hass.async_create_task(
                    self._try(self.node.mesh_id, *self.coordinator.profile.status_query())
                )

        self._refresh_handle = self.coordinator.hass.loop.call_later(
            REFRESH_AFTER_COMMAND, _fire
        )

    async def poll(self) -> None:
        if self._conn.connected:
            self._last_connected = time.monotonic()
            await self._try(self.node.mesh_id, *self.coordinator.profile.status_query())

    @callback
    def _on_disconnect(self) -> None:
        self._connected_event.clear()
        self.coordinator.notify_listeners()
        self._wake.set()

    @callback
    def _on_notification(self, note: Notification) -> None:
        self.coordinator.handle_notification(self.node, note)


class TelinkMeshCoordinator:
    """Manages a pool of per-lamp connections for one mesh."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        options = {**entry.data, **entry.options}
        self.mesh_name: str = entry.data[CONF_MESH_NAME]
        self.password: str = entry.data[CONF_MESH_PASSWORD]
        self.profile = get_profile(options.get(CONF_PROFILE, DEFAULT_PROFILE))
        self.color_mode: str = options.get(CONF_COLOR_MODE, DEFAULT_COLOR_MODE)
        self.color_temp_min = int(options.get(CONF_COLOR_TEMP_MIN) or self.profile.min_kelvin)
        self.color_temp_max = int(options.get(CONF_COLOR_TEMP_MAX) or self.profile.max_kelvin)
        if self.color_temp_max <= self.color_temp_min:
            self.color_temp_min = self.profile.min_kelvin
            self.color_temp_max = self.profile.max_kelvin
        self.write_with_response = bool(
            options.get(CONF_WRITE_WITH_RESPONSE, DEFAULT_WRITE_WITH_RESPONSE)
        )
        self._poll_interval = int(options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL))
        self.auth_failed = False
        self.nodes: dict[str, TelinkNode] = {}  # keyed by MAC
        self.links: dict[str, LampLink] = {}  # keyed by MAC
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{STORAGE_KEY}.{entry.entry_id}"
        )
        self._listeners: set[Callable[[], None]] = set()
        self._unsub_bt: Callable[[], None] | None = None
        self._unsub_poll: Callable[[], None] | None = None

    # -- lifecycle ------------------------------------------------------------------

    async def async_setup(self) -> None:
        data = await self._store.async_load()
        for item in ((data or {}).get("nodes") or {}).values():
            node = TelinkNode.from_storage(item)
            if node is not None:
                self._add_lamp(node)

        unsubs = [
            bluetooth.async_register_callback(
                self.hass, self._bluetooth_callback, matcher, BluetoothScanningMode.ACTIVE
            )
            for matcher in (
                BluetoothCallbackMatcher(
                    manufacturer_id=TELINK_MANUFACTURER_ID, connectable=True
                ),
                BluetoothCallbackMatcher(service_uuid=ADV_SERVICE_UUID, connectable=True),
            )
        ]

        def _unsub_all() -> None:
            for unsub in unsubs:
                unsub()

        self._unsub_bt = _unsub_all
        for service_info in bluetooth.async_discovered_service_info(
            self.hass, connectable=True
        ):
            self._bluetooth_callback(service_info, BluetoothChange.ADVERTISEMENT)

        self._unsub_poll = async_track_time_interval(
            self.hass, self._async_poll, timedelta(seconds=self._poll_interval)
        )
        for link in self.links.values():
            link.start()

    async def async_shutdown(self) -> None:
        if self._unsub_bt:
            self._unsub_bt()
            self._unsub_bt = None
        if self._unsub_poll:
            self._unsub_poll()
            self._unsub_poll = None
        await asyncio.gather(*(link.stop() for link in self.links.values()))
        await self._store.async_save(self._storage_data())

    # -- listeners ------------------------------------------------------------------

    @callback
    def async_add_listener(self, update_callback: Callable[[], None]) -> Callable[[], None]:
        self._listeners.add(update_callback)

        @callback
        def _remove() -> None:
            self._listeners.discard(update_callback)

        return _remove

    @callback
    def notify_listeners(self) -> None:
        for update_callback in list(self._listeners):
            update_callback()

    @property
    def any_available(self) -> bool:
        return any(link.available for link in self.links.values())

    def node_available(self, mac: str) -> bool:
        link = self.links.get(mac)
        return bool(link and link.available)

    def connected_address(self, mac: str) -> str | None:
        link = self.links.get(mac)
        return link.address if link and link.connected else None

    # -- discovery ------------------------------------------------------------------

    def _storage_data(self) -> dict[str, Any]:
        return {"nodes": {n.mac: n.to_storage() for n in self.nodes.values()}}

    def _schedule_save(self) -> None:
        self._store.async_delay_save(self._storage_data, SAVE_DELAY)

    def _add_lamp(self, node: TelinkNode) -> LampLink:
        self.nodes[node.mac] = node
        link = LampLink(self, node)
        self.links[node.mac] = link
        return link

    def _is_member(self, service_info: BluetoothServiceInfoBleak) -> bool:
        if service_info.address.upper() in self.nodes:
            return True
        if not is_telink_advertisement(service_info):
            return False
        return advertised_mesh_name(service_info) == self.mesh_name

    @callback
    def _bluetooth_callback(
        self, service_info: BluetoothServiceInfoBleak, change: BluetoothChange
    ) -> None:
        if not self._is_member(service_info):
            return
        mac = service_info.address.upper()
        link = self.links.get(mac)
        if link is None:
            node = TelinkNode(mac=mac, mesh_id=mesh_id_from_mac(mac))
            _LOGGER.info("Mesh %s: discovered lamp %s (0x%02X)", self.mesh_name, mac, node.mesh_id)
            link = self._add_lamp(node)
            self._schedule_save()
            link.start()
            async_dispatcher_send(
                self.hass, f"{SIGNAL_NEW_NODE}_{self.entry.entry_id}", node
            )
        link.poke(service_info.rssi)

    # -- notifications --------------------------------------------------------------

    @callback
    def handle_notification(self, node: TelinkNode, note: Notification) -> None:
        now = time.monotonic()
        try:
            if note.opcode == OP_ONLINE_STATUS:
                for entry in parse_online_status(note.params):
                    if entry.mesh_id != node.mesh_id:
                        continue
                    node.online = True
                    node.is_on = entry.is_on
                    if entry.brightness:
                        node.brightness = entry.brightness
                    node.last_seen = now
            elif note.opcode == OP_STATUS_REPORT:
                if not self.profile.trust_status_report:
                    return
                report = parse_status_report(note.params)
                node.online = True
                node.last_seen = now
                if report.brightness:
                    node.brightness = report.brightness
                if report.is_rgb:
                    node.rgb = (report.red, report.green, report.blue)
                    node.color_temp_kelvin = None
                elif report.is_white:
                    node.color_temp_kelvin = yw_to_kelvin(report.y, report.w)
                    node.rgb = None
            else:
                return
        except TelinkProtocolError as err:
            _LOGGER.debug("Mesh %s: %s", self.mesh_name, err)
            return
        self.notify_listeners()

    async def _async_poll(self, _now: datetime) -> None:
        await asyncio.gather(*(link.poll() for link in self.links.values()))

    # -- commands -------------------------------------------------------------------

    def _target_links(self, mac: str | None) -> list[LampLink]:
        if mac is None:
            return list(self.links.values())
        link = self.links.get(mac)
        return [link] if link else []

    async def async_turn_on(
        self,
        mac: str | None,
        *,
        brightness: int | None = None,
        rgb: tuple[int, int, int] | None = None,
        color_temp_kelvin: int | None = None,
    ) -> None:
        links = self._target_links(mac)
        if not links:
            raise HomeAssistantError(f"Telink mesh '{self.mesh_name}': no such lamp")
        errors: list[Exception] = []
        for link in links:
            node = link.node
            # A specific lamp is addressed by its own mesh id so relaying lamps
            # do not all react; "All lights" (mac is None) uses the broadcast
            # address on every connection.
            target = ADDR_ALL if mac is None else node.mesh_id
            level = brightness if brightness is not None else (node.brightness or 100)
            commands: list[tuple[int, bytes]] = []
            if not node.is_on or not node.online:
                commands.append(self.profile.power(True))
            if rgb is not None:
                commands.append(self.profile.rgb(*rgb, level))
            elif color_temp_kelvin is not None:
                commands.append(
                    self.profile.color_temp(
                        color_temp_kelvin, level, self.color_temp_min, self.color_temp_max
                    )
                )
            elif brightness is not None:
                commands.append(self.profile.brightness(level))
            try:
                async with link._command_lock:
                    for index, (opcode, params) in enumerate(commands):
                        if index:
                            await asyncio.sleep(COMMAND_GAP)
                        await link.async_send(target, opcode, params)
            except HomeAssistantError as err:
                errors.append(err)
                continue
            node.is_on = True
            if brightness is not None or rgb is not None or color_temp_kelvin is not None:
                node.brightness = level
            if rgb is not None:
                node.rgb = rgb
                node.color_temp_kelvin = None
            elif color_temp_kelvin is not None:
                node.color_temp_kelvin = color_temp_kelvin
                node.rgb = None
            link.schedule_refresh()
        self.notify_listeners()
        if errors and len(errors) == len(links):
            raise errors[0]

    async def async_turn_off(self, mac: str | None) -> None:
        links = self._target_links(mac)
        if not links:
            raise HomeAssistantError(f"Telink mesh '{self.mesh_name}': no such lamp")
        errors: list[Exception] = []
        for link in links:
            target = ADDR_ALL if mac is None else link.node.mesh_id
            try:
                async with link._command_lock:
                    await link.async_send(target, *self.profile.power(False))
            except HomeAssistantError as err:
                errors.append(err)
                continue
            link.node.is_on = False
            link.schedule_refresh()
        self.notify_listeners()
        if errors and len(errors) == len(links):
            raise errors[0]

    def diagnostics(self) -> dict[str, Any]:
        return {
            "mesh_name": self.mesh_name,
            "profile": self.profile.key,
            "color_mode": self.color_mode,
            "color_temp_min": self.color_temp_min,
            "color_temp_max": self.color_temp_max,
            "auth_failed": self.auth_failed,
            "lamps": [
                {
                    "mac": n.mac,
                    "mesh_id": n.mesh_id,
                    "connected": self.links[n.mac].connected,
                    "available": self.links[n.mac].available,
                    "notifications": self.links[n.mac].notifications_enabled,
                    "is_on": n.is_on,
                    "brightness": n.brightness,
                    "rgb": n.rgb,
                    "color_temp_kelvin": n.color_temp_kelvin,
                    "rssi": n.rssi,
                }
                for n in sorted(self.nodes.values(), key=lambda n: n.mesh_id)
            ],
        }
