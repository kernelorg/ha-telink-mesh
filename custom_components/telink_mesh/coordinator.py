"""Mesh coordinator: keeps one BLE connection to the mesh and tracks nodes."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import time
from typing import Any

from bleak.backends.device import BLEDevice

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
    CONF_MESH_NAME,
    CONF_MESH_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_PROFILE,
    CONF_WRITE_WITH_RESPONSE,
    DEFAULT_COLOR_MODE,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_PROFILE,
    DEFAULT_WRITE_WITH_RESPONSE,
    NODE_STALE_SECONDS,
    RECONNECT_DELAYS,
    SIGNAL_NEW_NODE,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from .mesh import TelinkAuthError, TelinkConnectionError, TelinkMeshConnection
from .protocol import (
    ADDR_ALL,
    ADDR_CONNECTED,
    ADDR_GROUP_BASE,
    ADV_SERVICE_UUID,
    OP_ADDRESS_EDIT,
    OP_ADDRESS_REPORT,
    OP_ONLINE_STATUS,
    OP_STATUS_REPORT,
    OP_TIME_SET,
    TELINK_MANUFACTURER_ID,
    Notification,
    TelinkProtocolError,
    get_profile,
    parse_address_report,
    parse_manufacturer_data,
    parse_online_status,
    parse_status_report,
    time_set_params,
    yw_to_kelvin,
)

_LOGGER = logging.getLogger(__name__)

MAX_CONNECT_CANDIDATES = 4
COMMAND_GAP = 0.05
REFRESH_AFTER_COMMAND = 2.0
SAVE_DELAY = 10


@dataclass
class TelinkNode:
    """State of one mesh node (a lamp)."""

    mesh_id: int
    mac: str | None = None
    name: str | None = None
    is_on: bool = False
    brightness: int = 0  # 0..100
    rgb: tuple[int, int, int] | None = None
    color_temp_kelvin: int | None = None
    online: bool = False
    last_seen: float = 0.0
    rssi: int | None = None
    advertised_product: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_storage(self) -> dict[str, Any]:
        return {"mac": self.mac, "name": self.name, "product": self.advertised_product}

    @classmethod
    def from_storage(cls, mesh_id: int, data: dict[str, Any]) -> TelinkNode:
        return cls(
            mesh_id=mesh_id,
            mac=data.get("mac"),
            name=data.get("name"),
            advertised_product=data.get("product"),
        )


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


class TelinkMeshCoordinator:
    """Owns the connection to a mesh and the list of its nodes."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        options = {**entry.data, **entry.options}
        self.mesh_name: str = entry.data[CONF_MESH_NAME]
        self._password: str = entry.data[CONF_MESH_PASSWORD]
        self.profile = get_profile(options.get(CONF_PROFILE, DEFAULT_PROFILE))
        self.color_mode: str = options.get(CONF_COLOR_MODE, DEFAULT_COLOR_MODE)
        self._poll_interval = int(options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL))
        self._connection = TelinkMeshConnection(
            self.mesh_name,
            self._password,
            notification_callback=self._handle_notification,
            disconnected_callback=self._handle_disconnect,
            write_with_response=bool(
                options.get(CONF_WRITE_WITH_RESPONSE, DEFAULT_WRITE_WITH_RESPONSE)
            ),
        )
        self.nodes: dict[int, TelinkNode] = {}
        self.connected_mesh_id: int | None = None
        self.auth_failed = False
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{STORAGE_KEY}.{entry.entry_id}"
        )
        self._candidates: dict[str, float] = {}
        self._known_macs: set[str] = set()
        self._listeners: set[Callable[[], None]] = set()
        self._wake = asyncio.Event()
        self._stopping = False
        self._unsub_bt: Callable[[], None] | None = None
        self._unsub_poll: Callable[[], None] | None = None
        self._refresh_handle: asyncio.TimerHandle | None = None
        self._command_lock = asyncio.Lock()

    # -- lifecycle ------------------------------------------------------------------

    async def async_setup(self) -> None:
        data = await self._store.async_load()
        for mesh_id_str, item in ((data or {}).get("nodes") or {}).items():
            node = TelinkNode.from_storage(int(mesh_id_str), item)
            self.nodes[node.mesh_id] = node
            if node.mac:
                self._known_macs.add(node.mac)

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
        self.entry.async_create_background_task(
            self.hass, self._connection_loop(), name=f"telink_mesh {self.mesh_name}"
        )

    async def async_shutdown(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._unsub_bt:
            self._unsub_bt()
            self._unsub_bt = None
        if self._unsub_poll:
            self._unsub_poll()
            self._unsub_poll = None
        if self._refresh_handle:
            self._refresh_handle.cancel()
            self._refresh_handle = None
        await self._connection.disconnect()
        await self._store.async_save(self._storage_data())

    # -- listeners -----------------------------------------------------------------------

    @callback
    def async_add_listener(self, update_callback: Callable[[], None]) -> Callable[[], None]:
        self._listeners.add(update_callback)

        @callback
        def _remove() -> None:
            self._listeners.discard(update_callback)

        return _remove

    @callback
    def _notify_listeners(self) -> None:
        for update_callback in list(self._listeners):
            update_callback()

    @property
    def connected(self) -> bool:
        return self._connection.connected

    @property
    def connected_address(self) -> str | None:
        return self._connection.address if self._connection.connected else None

    @property
    def candidate_addresses(self) -> list[str]:
        return list(self._candidates)

    # -- node registry ---------------------------------------------------------------------

    def _get_or_create_node(self, mesh_id: int) -> TelinkNode:
        node = self.nodes.get(mesh_id)
        if node is None:
            node = TelinkNode(mesh_id=mesh_id)
            self.nodes[mesh_id] = node
            _LOGGER.info("Mesh %s: discovered node 0x%02x", self.mesh_name, mesh_id)
            self._schedule_save()
            async_dispatcher_send(self.hass, f"{SIGNAL_NEW_NODE}_{self.entry.entry_id}", node)
        return node

    @staticmethod
    def _is_node_address(mesh_id: int) -> bool:
        return 0 < mesh_id < ADDR_GROUP_BASE

    def _storage_data(self) -> dict[str, Any]:
        return {"nodes": {str(n.mesh_id): n.to_storage() for n in self.nodes.values()}}

    def _schedule_save(self) -> None:
        self._store.async_delay_save(self._storage_data, SAVE_DELAY)

    # -- discovery ----------------------------------------------------------------------------

    def _is_member(self, service_info: BluetoothServiceInfoBleak) -> bool:
        if service_info.address in self._known_macs:
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
        address = service_info.address
        first_time = address not in self._candidates
        self._candidates[address] = time.monotonic()

        payload = service_info.manufacturer_data.get(TELINK_MANUFACTURER_ID)
        adv = parse_manufacturer_data(payload) if payload else None
        if adv and adv.mesh_id is not None and self._is_node_address(adv.mesh_id):
            node = self._get_or_create_node(adv.mesh_id)
            node.rssi = service_info.rssi
            node.advertised_product = adv.product_uuid
            if node.mac != address:
                node.mac = address
                self._known_macs.add(address)
                self._schedule_save()
                self._notify_listeners()

        if first_time:
            _LOGGER.debug("Mesh %s: candidate %s (rssi %s)", self.mesh_name, address, service_info.rssi)
        if not self._connection.connected:
            self._wake.set()

    def _sorted_candidates(self) -> list[BLEDevice]:
        scored: list[tuple[int, BLEDevice]] = []
        for address in list(self._candidates):
            device = bluetooth.async_ble_device_from_address(self.hass, address, connectable=True)
            if device is None:
                continue
            info = bluetooth.async_last_service_info(self.hass, address, connectable=True)
            scored.append((info.rssi if info and info.rssi is not None else -127, device))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [device for _, device in scored]

    # -- connection management -------------------------------------------------------

    async def _connection_loop(self) -> None:
        attempt = 0
        while not self._stopping:
            if self._connection.connected:
                self._wake.clear()
                await self._wake.wait()
                continue

            connected = False
            for device in self._sorted_candidates()[:MAX_CONNECT_CANDIDATES]:
                if self._stopping:
                    return
                try:
                    await self._connection.connect(device)
                except TelinkAuthError:
                    _LOGGER.error(
                        "Mesh %s: %s rejected the mesh name/password", self.mesh_name, device.address
                    )
                    self.auth_failed = True
                    self._notify_listeners()
                    self.entry.async_start_reauth(self.hass)
                    return
                except TelinkConnectionError as err:
                    _LOGGER.debug("Mesh %s: %s: %s", self.mesh_name, device.address, err)
                    continue
                connected = True
                break

            if connected:
                attempt = 0
                _LOGGER.info(
                    "Mesh %s: connected through %s", self.mesh_name, self._connection.address
                )
                self._notify_listeners()
                await self._post_connect()
                continue

            delay = RECONNECT_DELAYS[min(attempt, len(RECONNECT_DELAYS) - 1)]
            attempt += 1
            if not self._candidates:
                _LOGGER.debug("Mesh %s: no devices advertising yet", self.mesh_name)
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), delay)
            except asyncio.TimeoutError:
                pass

    @callback
    def _handle_disconnect(self) -> None:
        self.connected_mesh_id = None
        self._notify_listeners()
        self._wake.set()

    async def _post_connect(self) -> None:
        now: datetime = dt_util.now()
        await self._try_send(
            ADDR_ALL,
            OP_TIME_SET,
            time_set_params(now.year, now.month, now.day, now.hour, now.minute, now.second),
        )
        await asyncio.sleep(COMMAND_GAP)
        await self._try_send(ADDR_CONNECTED, OP_ADDRESS_EDIT, b"\xff\xff")
        await asyncio.sleep(COMMAND_GAP)
        await self._try_send(ADDR_ALL, *self.profile.status_query())

    async def _try_send(self, target: int, opcode: int, params: bytes) -> bool:
        try:
            await self._connection.send(target, opcode, params)
        except TelinkConnectionError as err:
            _LOGGER.debug("Mesh %s: send failed: %s", self.mesh_name, err)
            return False
        return True

    async def _async_poll(self, _now: datetime) -> None:
        stale_before = time.monotonic() - NODE_STALE_SECONDS
        changed = False
        for node in self.nodes.values():
            if node.online and node.last_seen and node.last_seen < stale_before:
                node.online = False
                changed = True
        if changed:
            self._notify_listeners()
        if self._connection.connected:
            await self._try_send(ADDR_ALL, *self.profile.status_query())

    def _schedule_refresh(self, target: int) -> None:
        if self._refresh_handle:
            self._refresh_handle.cancel()

        def _fire() -> None:
            self._refresh_handle = None
            if self._connection.connected:
                self.hass.async_create_task(
                    self._try_send(target, *self.profile.status_query())
                )

        self._refresh_handle = self.hass.loop.call_later(REFRESH_AFTER_COMMAND, _fire)

    # -- notifications ------------------------------------------------------------------------

    @callback
    def _handle_notification(self, note: Notification) -> None:
        now = time.monotonic()
        try:
            if note.opcode == OP_ONLINE_STATUS:
                for entry in parse_online_status(note.params):
                    if not self._is_node_address(entry.mesh_id):
                        continue
                    node = self._get_or_create_node(entry.mesh_id)
                    node.online = entry.online
                    node.is_on = entry.is_on
                    if entry.brightness:
                        node.brightness = entry.brightness
                    node.last_seen = now
            elif note.opcode == OP_STATUS_REPORT:
                if not self._is_node_address(note.source):
                    return
                report = parse_status_report(note.params)
                node = self._get_or_create_node(note.source)
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
            elif note.opcode == OP_ADDRESS_REPORT:
                report = parse_address_report(note.params)
                if not self._is_node_address(report.mesh_id):
                    return
                node = self._get_or_create_node(report.mesh_id)
                node.online = True
                node.last_seen = now
                mac = self._match_known_mac(report.mac, report.mac_reversed)
                if mac and node.mac != mac:
                    node.mac = mac
                    self._known_macs.add(mac)
                    self._schedule_save()
                if mac and mac == self._connection.address:
                    self.connected_mesh_id = report.mesh_id
            else:
                return
        except TelinkProtocolError as err:
            _LOGGER.debug("Mesh %s: %s", self.mesh_name, err)
            return
        self._notify_listeners()

    def _match_known_mac(self, *variants: str) -> str | None:
        known = {a.upper() for a in self._candidates} | {a.upper() for a in self._known_macs}
        if self._connection.address:
            known.add(self._connection.address.upper())
        for variant in variants:
            if variant.upper() in known:
                return variant.upper()
        # Telink sends the MAC little-endian, so the first variant is the best guess.
        return variants[0].upper() if variants else None

    # -- commands -----------------------------------------------------------------------------------

    async def async_send(self, target: int, opcode: int, params: bytes) -> None:
        if not self._connection.connected:
            self._wake.set()
            raise HomeAssistantError(
                f"Telink mesh '{self.mesh_name}' is not connected to any node"
            )
        try:
            await self._connection.send(target, opcode, params)
        except TelinkConnectionError as err:
            self._wake.set()
            raise HomeAssistantError(f"Telink mesh '{self.mesh_name}': {err}") from err

    def _targets(self, target: int) -> list[TelinkNode]:
        if target == ADDR_ALL:
            return list(self.nodes.values())
        node = self.nodes.get(target)
        return [node] if node else []

    async def async_turn_on(
        self,
        target: int,
        *,
        brightness: int | None = None,
        rgb: tuple[int, int, int] | None = None,
        color_temp_kelvin: int | None = None,
    ) -> None:
        """Turn a node (or every node with ADDR_ALL) on and apply attributes."""
        nodes = self._targets(target)
        current = nodes[0] if len(nodes) == 1 else None
        level = brightness if brightness is not None else (
            current.brightness if current and current.brightness else 100
        )
        commands: list[tuple[int, bytes]] = []
        if current is None or not current.is_on or not current.online:
            commands.append(self.profile.power(True))
        if rgb is not None:
            commands.append(self.profile.rgb(*rgb, level))
        elif color_temp_kelvin is not None:
            commands.append(self.profile.color_temp(color_temp_kelvin, level))
        elif brightness is not None:
            commands.append(self.profile.brightness(level))

        async with self._command_lock:
            for index, (opcode, params) in enumerate(commands):
                if index:
                    await asyncio.sleep(COMMAND_GAP)
                await self.async_send(target, opcode, params)

        for node in nodes:
            node.is_on = True
            if brightness is not None or rgb is not None or color_temp_kelvin is not None:
                node.brightness = level
            if rgb is not None:
                node.rgb = rgb
                node.color_temp_kelvin = None
            elif color_temp_kelvin is not None:
                node.color_temp_kelvin = color_temp_kelvin
                node.rgb = None
        self._notify_listeners()
        self._schedule_refresh(target)

    async def async_turn_off(self, target: int) -> None:
        async with self._command_lock:
            await self.async_send(target, *self.profile.power(False))
        for node in self._targets(target):
            node.is_on = False
        self._notify_listeners()
        self._schedule_refresh(target)

    async def async_request_refresh(self, target: int = ADDR_ALL) -> None:
        if self._connection.connected:
            await self._try_send(target, *self.profile.status_query())

    def diagnostics(self) -> dict[str, Any]:
        return {
            "mesh_name": self.mesh_name,
            "profile": self.profile.key,
            "color_mode": self.color_mode,
            "connected": self.connected,
            "connected_address": self.connected_address,
            "connected_mesh_id": self.connected_mesh_id,
            "auth_failed": self.auth_failed,
            "candidates": sorted(self._candidates),
            "nodes": [
                {
                    "mesh_id": n.mesh_id,
                    "mac": n.mac,
                    "online": n.online,
                    "is_on": n.is_on,
                    "brightness": n.brightness,
                    "rgb": n.rgb,
                    "color_temp_kelvin": n.color_temp_kelvin,
                    "rssi": n.rssi,
                    "product": n.advertised_product,
                    "seen_seconds_ago": round(time.monotonic() - n.last_seen) if n.last_seen else None,
                }
                for n in sorted(self.nodes.values(), key=lambda n: n.mesh_id)
            ],
        }
