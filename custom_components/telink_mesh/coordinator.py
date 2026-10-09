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
from functools import partial
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
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_call_later, async_track_time_interval
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
    DOMAIN,
    RECONNECT_DELAYS,
    SIGNAL_NEW_NODE,
    SIGNAL_REMOVED_NODE,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from .mesh import TelinkAuthError, TelinkConnectionError, TelinkMeshConnection
from .protocol import (
    ADDR_ALL,
    ADDR_CONNECTED,
    ADV_SERVICE_UUID,
    OP_ONLINE_STATUS,
    OP_STATUS_REPORT,
    OP_TIME_SET,
    TELINK_MANUFACTURER_ID,
    Notification,
    TelinkProtocolError,
    adv_carries_own_mac,
    adv_local_name,
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
# Adopt a newly seen address only if it is still advertising this long after the
# first sighting, so a single corrupted packet (wrong MAC but intact mesh name)
# cannot spawn a phantom lamp.
ADOPT_CONFIRM_DELAY = 10.0
# Safety cap on lamps per mesh; a real home has far fewer.
MAX_NODES = 64
AVAILABLE_GRACE = 180.0
# After a lamp moves to another mesh, ignore it while Home Assistant's cached
# advertisement may still carry the old mesh name.
MOVED_IGNORE_SECONDS = 600.0
COMMAND_CONNECT_WAIT = 15.0
# How long a lamp that rejects the credentials waits for another lamp of the
# mesh to log in before the whole entry is considered to have wrong credentials.
REJECTED_PEER_WAIT = 60.0
# Pause between changing a lamp's credentials and logging in with the new ones.
VERIFY_DELAY = 2.0


@dataclass
class TelinkNode:
    """State of one lamp."""

    mac: str
    mesh_id: int
    is_on: bool = False
    brightness: int = 0  # 0..100
    rgb: tuple[int, int, int] | None = None
    color_temp_kelvin: int | None = None
    # False until the lamp first answered in this run, so the first turn_on
    # also sends a power-on command.
    online: bool = False
    rssi: int | None = None

    def state_snapshot(self) -> tuple[Any, ...]:
        """Persisted light state, used to detect changes worth saving."""
        return (self.is_on, self.brightness, self.rgb, self.color_temp_kelvin)

    def to_storage(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "mesh_id": self.mesh_id,
            "is_on": self.is_on,
            "brightness": self.brightness,
            "rgb": list(self.rgb) if self.rgb else None,
            "color_temp_kelvin": self.color_temp_kelvin,
        }

    @classmethod
    def from_storage(cls, data: dict[str, Any]) -> TelinkNode | None:
        mac = data.get("mac")
        if not mac or mac.upper() == "00:00:00:00:00:00":
            return None
        rgb = data.get("rgb")
        kelvin = data.get("color_temp_kelvin")
        return cls(
            mac=mac.upper(),
            mesh_id=int(data.get("mesh_id", mesh_id_from_mac(mac))),
            is_on=bool(data.get("is_on", False)),
            brightness=int(data.get("brightness") or 0),
            rgb=tuple(int(c) for c in rgb) if rgb and len(rgb) == 3 else None,
            color_temp_kelvin=int(kelvin) if kelvin else None,
        )


def mesh_id_from_mac(mac: str) -> int:
    """Telink lamps use the last MAC octet as their mesh id."""
    return int(mac.split(":")[-1], 16)


def lamp_unique_id(entry_id: str, mac: str) -> str:
    """Unique id of a lamp's light entity, also its device identifier."""
    return f"{entry_id}_{mac}"


def lamp_mac(entry_id: str, unique_id: str) -> str | None:
    """MAC from :func:`lamp_unique_id`; None for the mesh-wide ids."""
    mac = unique_id.removeprefix(f"{entry_id}_")
    if mac == unique_id or mac.count(":") != 5:
        return None
    return mac


def is_telink_advertisement(service_info: BluetoothServiceInfoBleak) -> bool:
    """Return True when the advertisement comes from a Telink mesh device.

    Telink manufacturer data that names a different MAC is rejected: it is a
    lamp's packet spliced onto another device (an EcoFlow showed up as a mesh)
    or a lamp heard under a corrupted address (the phantom lamps).
    """
    payload = service_info.manufacturer_data.get(TELINK_MANUFACTURER_ID)
    if payload is not None:
        return adv_carries_own_mac(service_info.address, payload) is not False
    return ADV_SERVICE_UUID in service_info.service_uuids


def advertised_mesh_name(service_info: BluetoothServiceInfoBleak) -> str | None:
    """Return the mesh name the device currently advertises, if any.

    Prefer the name in the latest raw packet: Home Assistant keeps the longest
    name an address ever sent, so a lamp moved from ``Fulife`` to ``karp`` would
    otherwise still look like ``Fulife``. Home Assistant also fills in the
    address as the name of a device that sent none.
    """
    if service_info.raw and (name := adv_local_name(service_info.raw)):
        return name

    def bare(text: str) -> str:
        return text.replace(":", "").replace("-", "").upper()

    name = service_info.name
    if not name or bare(name) == bare(service_info.address):
        return None
    return name


def fresh_service_info(
    hass: HomeAssistant, service_info: BluetoothServiceInfoBleak
) -> BluetoothServiceInfoBleak | None:
    """Return a newer advertisement from the same address, if one arrived.

    A corrupted advertisement (garbled MAC or name) is a one-off: a garbled MAC
    never advertises again, and a garbled name is replaced by the real one on
    the next packet. Home Assistant refreshes its history (and ``time``) on
    every advertisement even when the data is unchanged, while callbacks only
    fire on changes, so the history is the reliable place to look.
    """
    last = bluetooth.async_last_service_info(
        hass, service_info.address, connectable=True
    )
    if last is None or last.time <= service_info.time:
        return None
    return last


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
        # Serialises multi-packet commands so they do not interleave.
        self.command_lock = asyncio.Lock()
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
    def logged_in_once(self) -> bool:
        """True once this lamp accepted the mesh credentials in this run."""
        return bool(self._last_connected)

    async def wait_logged_in(self) -> None:
        await self._connected_event.wait()

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
                    await self.coordinator.async_lamp_rejected(self)
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
                    self._last_connected = time.monotonic()
                    self._connected_event.set()
                    self.node.online = True
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

    async def _wait_connected(self) -> None:
        if self._conn.connected:
            return
        self._wake.set()
        try:
            await asyncio.wait_for(self._connected_event.wait(), COMMAND_CONNECT_WAIT)
        except asyncio.TimeoutError:
            raise HomeAssistantError(
                f"Telink lamp {self.node.mac} is not connected"
            ) from None

    async def async_send(self, target: int, opcode: int, params: bytes) -> None:
        await self._wait_connected()
        try:
            await self._conn.send(target, opcode, params)
        except TelinkConnectionError as err:
            self._wake.set()
            raise HomeAssistantError(f"Telink lamp {self.node.mac}: {err}") from err

    def restart(self) -> None:
        """Resume the connection loop after stop()."""
        self._stopping = False
        self._wake.clear()
        self.start()

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
        # Availability keeps a grace window after the link drops; nothing else
        # re-renders the entity when that window ends, so schedule a refresh at
        # its edge to flip the lamp to "unavailable" if it has not returned.
        self.coordinator.hass.loop.call_later(
            AVAILABLE_GRACE + 1.0, self.coordinator.notify_listeners
        )
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
        self._moved: dict[str, float] = {}  # MAC -> ignore until (monotonic)
        self._pending_adopt: dict[str, Callable[[], None]] = {}  # MAC -> cancel

    # -- lifecycle ------------------------------------------------------------------

    async def async_setup(self) -> None:
        data = await self._store.async_load()
        stored = list(((data or {}).get("nodes") or {}).values())
        if len(stored) > MAX_NODES:
            # A pile this large can only be corrupted advertisements adopted by
            # an older version; drop it and let live lamps be re-discovered.
            _LOGGER.warning(
                "Mesh %s: discarding %d stored lamps (over the %d cap, likely "
                "corrupted); real lamps will be re-discovered",
                self.mesh_name, len(stored), MAX_NODES,
            )
            stored = []
            self._schedule_save()
        for item in stored:
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
        self._scan_history()

        self._unsub_poll = async_track_time_interval(
            self.hass, self._async_poll, timedelta(seconds=self._poll_interval)
        )
        for link in self.links.values():
            link.start()

    async def async_shutdown(self) -> None:
        for cancel in self._pending_adopt.values():
            cancel()
        self._pending_adopt.clear()
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
        moved_until = self._moved.get(service_info.address.upper())
        if moved_until is not None:
            if time.monotonic() < moved_until:
                return False
            del self._moved[service_info.address.upper()]
        if service_info.address.upper() in self.nodes:
            return True
        if not is_telink_advertisement(service_info):
            return False
        return advertised_mesh_name(service_info) == self.mesh_name

    @callback
    def _scan_history(self) -> None:
        """Look for new lamps among the advertisements Home Assistant holds.

        Callbacks fire only when advertisement data changes, and a lamp moved
        into this mesh can keep what Home Assistant considers the same data
        (see advertised_mesh_name), so it would never be noticed otherwise.
        """
        for service_info in bluetooth.async_discovered_service_info(
            self.hass, connectable=True
        ):
            if service_info.address.upper() not in self.links:
                self._bluetooth_callback(service_info, BluetoothChange.ADVERTISEMENT)

    @callback
    def _bluetooth_callback(
        self, service_info: BluetoothServiceInfoBleak, change: BluetoothChange
    ) -> None:
        if not self._is_member(service_info):
            return
        mac = service_info.address.upper()
        link = self.links.get(mac)
        if link is None:
            if mac not in self._pending_adopt:
                # Wait for the address to keep advertising: a genuine lamp does so
                # about once a second, a corrupted one-off packet never recurs.
                self._pending_adopt[mac] = async_call_later(
                    self.hass, ADOPT_CONFIRM_DELAY, partial(self._confirm_lamp, service_info)
                )
            return
        link.poke(service_info.rssi)

    @callback
    def _confirm_lamp(self, first: BluetoothServiceInfoBleak, _now: datetime) -> None:
        mac = first.address.upper()
        self._pending_adopt.pop(mac, None)
        if self._unsub_bt is None or mac in self.links:
            return
        service_info = fresh_service_info(self.hass, first)
        if service_info is None or not self._is_member(service_info):
            _LOGGER.debug("Mesh %s: ignoring one-off advertisement from %s", self.mesh_name, mac)
            return
        if len(self.nodes) >= MAX_NODES:
            _LOGGER.warning(
                "Mesh %s: ignoring new lamp %s, already at the %d-lamp cap",
                self.mesh_name, mac, MAX_NODES,
            )
            return
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
        before = node.state_snapshot()
        try:
            if note.opcode == OP_ONLINE_STATUS:
                for entry in parse_online_status(note.params):
                    if entry.mesh_id != node.mesh_id:
                        continue
                    node.online = True
                    node.is_on = entry.is_on
                    if entry.brightness:
                        node.brightness = entry.brightness
            elif note.opcode == OP_STATUS_REPORT:
                if not self.profile.trust_status_report:
                    return
                report = parse_status_report(note.params)
                node.online = True
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
        if node.state_snapshot() != before:
            self._schedule_save()
        self.notify_listeners()

    async def _async_poll(self, _now: datetime) -> None:
        self._scan_history()
        await asyncio.gather(*(link.poll() for link in self.links.values()))
        # Re-render entities so availability reflects the grace window even when
        # no notification arrived this cycle (e.g. a lamp that lost power).
        self.notify_listeners()

    # -- commands -------------------------------------------------------------------

    def _target_links(self, mac: str | None) -> list[LampLink]:
        if mac is None:
            return list(self.links.values())
        link = self.links.get(mac)
        return [link] if link else []

    async def async_set_lamp_credentials(
        self, mac: str, name: str, password: str, ltk: bytes
    ) -> None:
        """Move one lamp to another mesh name / password and drop it here."""
        link = self.links.get(mac)
        if link is None:
            raise HomeAssistantError(f"Telink mesh '{self.mesh_name}': no lamp {mac}")
        device = bluetooth.async_ble_device_from_address(self.hass, mac, connectable=True)
        if device is None:
            raise HomeAssistantError(f"Telink lamp {mac} is not in range of any proxy")

        # Same sequence as tools/set_mesh_credentials.py, which is proven on
        # hardware: a fresh connection and login right before the change, then
        # a new login with the new credentials to make sure the lamp took them.
        # A lamp confirms (0x07) even when it decoded garbage, so only the
        # verification login tells success apart.
        await link.stop()
        try:
            async with link.command_lock:
                await self._async_write_credentials(device, mac, name, password, ltk)
        except HomeAssistantError:
            link.restart()
            raise
        await self._async_remove_lamp(mac)
        await asyncio.sleep(VERIFY_DELAY)
        await self._async_verify_credentials(mac, name, password)
        _LOGGER.info("Mesh %s: lamp %s moved to mesh %s", self.mesh_name, mac, name)

    async def _async_write_credentials(
        self, device: BLEDevice, mac: str, name: str, password: str, ltk: bytes
    ) -> None:
        conn = TelinkMeshConnection(self.mesh_name, self.password)
        try:
            await conn.connect(device)
            # Prove our session key matches the lamp's BEFORE writing: the new
            # name/password are encrypted with this key, and a lamp that decodes
            # them with a different key stores random bytes it can never be
            # logged into again (only a factory reset recovers it).
            if not await conn.verify_session_key(
                ADDR_CONNECTED, *self.profile.status_query()
            ):
                raise HomeAssistantError(
                    f"Telink lamp {mac}: could not confirm a working encrypted "
                    "link (no valid reply); refusing to change its credentials"
                )
            await conn.set_credentials(name, password, ltk)
        except TelinkAuthError as err:
            raise HomeAssistantError(
                f"Telink lamp {mac} rejected the current mesh credentials"
            ) from err
        except (TelinkConnectionError, TelinkProtocolError) as err:
            raise HomeAssistantError(f"Telink lamp {mac}: {err}") from err
        finally:
            await conn.disconnect()

    async def _async_verify_credentials(self, mac: str, name: str, password: str) -> None:
        device = bluetooth.async_ble_device_from_address(self.hass, mac, connectable=True)
        if device is None:
            raise HomeAssistantError(
                f"Telink lamp {mac} took the new credentials but went out of range "
                "before they could be verified; remaining lamps were not changed"
            )
        conn = TelinkMeshConnection(name, password)
        try:
            await conn.connect(device)
        except TelinkAuthError as err:
            raise HomeAssistantError(
                f"Telink lamp {mac} confirmed the change but rejects the new "
                "credentials; it needs a factory reset. Remaining lamps were not changed"
            ) from err
        except TelinkConnectionError as err:
            raise HomeAssistantError(
                f"Telink lamp {mac}: could not verify the new credentials ({err}); "
                "remaining lamps were not changed"
            ) from err
        finally:
            await conn.disconnect()

    async def async_lamp_rejected(self, link: LampLink) -> None:
        """A lamp refused this mesh's name/password.

        If other lamps still accept them, that lamp was moved to another mesh
        (e.g. by the app or tools/set_mesh_credentials.py): drop it from this
        entry. Only when no lamp accepts them are the credentials wrong.
        """
        mac = link.node.mac
        peers = [other for other in self.links.values() if other is not link]
        if peers and not any(other.logged_in_once for other in peers):
            waits = [
                asyncio.ensure_future(other.wait_logged_in()) for other in peers
            ]
            try:
                await asyncio.wait(
                    waits, timeout=REJECTED_PEER_WAIT, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                for task in waits:
                    task.cancel()
        if mac not in self.links:
            return
        if any(other.logged_in_once for other in peers):
            _LOGGER.warning(
                "Mesh %s: lamp %s no longer accepts this mesh name/password while "
                "other lamps do; it was probably moved to another mesh, removing it",
                self.mesh_name,
                mac,
            )
            await self._async_remove_lamp(mac)
            return
        _LOGGER.error(
            "Mesh %s: lamp %s rejected the mesh name/password", self.mesh_name, mac
        )
        self.auth_failed = True
        self.entry.async_start_reauth(self.hass)

    async def async_forget_lamp(self, mac: str) -> None:
        """Drop a lamp whose device the user deleted from the device registry."""
        await self._async_remove_lamp(mac, update_registry=False)

    async def _async_remove_lamp(self, mac: str, update_registry: bool = True) -> None:
        self._moved[mac] = time.monotonic() + MOVED_IGNORE_SECONDS
        link = self.links.pop(mac, None)
        self.nodes.pop(mac, None)
        if link is not None:
            await link.stop()
        self._schedule_save()
        if update_registry:
            self._remove_lamp_device(mac)
        async_dispatcher_send(
            self.hass, f"{SIGNAL_REMOVED_NODE}_{self.entry.entry_id}", mac
        )
        self.notify_listeners()

    def _remove_lamp_device(self, mac: str) -> None:
        registry = dr.async_get(self.hass)
        device = registry.async_get_device(
            identifiers={(DOMAIN, lamp_unique_id(self.entry.entry_id, mac))}
        )
        if device is not None:
            registry.async_update_device(
                device.id, remove_config_entry_id=self.entry.entry_id
            )

    def _updated_links(self, mac: str | None, succeeded: list[LampLink]) -> list[LampLink]:
        """Lamps whose state a command changed.

        The mesh relays a broadcast, so once any connection took it every lamp
        reacted, including those whose own link was down at that moment.
        """
        if mac is None and succeeded:
            return list(self.links.values())
        return succeeded

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
        succeeded: list[LampLink] = []
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
                async with link.command_lock:
                    for index, (opcode, params) in enumerate(commands):
                        if index:
                            await asyncio.sleep(COMMAND_GAP)
                        await link.async_send(target, opcode, params)
            except HomeAssistantError as err:
                errors.append(err)
                continue
            succeeded.append(link)
            link.schedule_refresh()
        for link in self._updated_links(mac, succeeded):
            node = link.node
            node.is_on = True
            if brightness is not None or rgb is not None or color_temp_kelvin is not None:
                node.brightness = brightness if brightness is not None else (node.brightness or 100)
            if rgb is not None:
                node.rgb = rgb
                node.color_temp_kelvin = None
            elif color_temp_kelvin is not None:
                node.color_temp_kelvin = color_temp_kelvin
                node.rgb = None
        self._schedule_save()
        self.notify_listeners()
        if errors and len(errors) == len(links):
            raise errors[0]

    async def async_turn_off(self, mac: str | None) -> None:
        links = self._target_links(mac)
        if not links:
            raise HomeAssistantError(f"Telink mesh '{self.mesh_name}': no such lamp")
        errors: list[Exception] = []
        succeeded: list[LampLink] = []
        for link in links:
            target = ADDR_ALL if mac is None else link.node.mesh_id
            try:
                async with link.command_lock:
                    await link.async_send(target, *self.profile.power(False))
            except HomeAssistantError as err:
                errors.append(err)
                continue
            succeeded.append(link)
            link.schedule_refresh()
        for link in self._updated_links(mac, succeeded):
            link.node.is_on = False
        self._schedule_save()
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
