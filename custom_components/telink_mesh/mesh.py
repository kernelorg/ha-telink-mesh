"""BLE connection to one node of a Telink mesh (bleak based).

Works with any transport Home Assistant provides, including ESPHome
Bluetooth proxies, because it only uses the ``BLEDevice`` handed over by
``homeassistant.components.bluetooth`` and ``bleak_retry_connector``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import logging

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    establish_connection,
)

from .protocol import (
    COMMAND_CHAR_UUID,
    NOTIFY_CHAR_UUID,
    PAIR_CHAR_UUID,
    Notification,
    SequenceCounter,
    TelinkAuthError,
    TelinkError,
    TelinkProtocolError,
    build_command,
    build_pair_request,
    mac_to_le,
    parse_notification,
    parse_pair_response,
)

_LOGGER = logging.getLogger(__name__)

PAIR_SETTLE_DELAY = 0.3
CONNECT_ATTEMPTS = 3


class TelinkConnectionError(TelinkError):
    """Could not establish or use the BLE connection."""


class TelinkMeshConnection:
    """Encrypted GATT session with a single mesh node."""

    def __init__(
        self,
        mesh_name: str,
        mesh_password: str,
        *,
        notification_callback: Callable[[Notification], None] | None = None,
        disconnected_callback: Callable[[], None] | None = None,
        write_with_response: bool = False,
    ) -> None:
        self._mesh_name = mesh_name
        self._mesh_password = mesh_password
        self._notification_callback = notification_callback
        self._disconnected_callback = disconnected_callback
        self._write_with_response = write_with_response
        self._client: BleakClient | None = None
        self._session_key: bytes | None = None
        self._mac_le: bytes | None = None
        self._address: str | None = None
        self._sequence = SequenceCounter()
        self._write_lock = asyncio.Lock()
        self._expected_disconnect = False
        # Set during login: True when we managed to subscribe to status
        # notifications, False when the device/proxy would not allow it.
        self.notifications_enabled = False
        # Stop handle for the ESPHome-proxy notify fallback, if used.
        self._esp_notify_stop = None

    @property
    def address(self) -> str | None:
        return self._address

    @property
    def connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def connect(self, ble_device: BLEDevice) -> None:
        """Connect, log in to the mesh and enable notifications."""
        if self.connected:
            return
        name = ble_device.name or ble_device.address
        self._expected_disconnect = False
        try:
            client = await establish_connection(
                BleakClientWithServiceCache,
                ble_device,
                name,
                disconnected_callback=self._handle_disconnect,
                max_attempts=CONNECT_ATTEMPTS,
                use_services_cache=True,
            )
        except (BleakError, TimeoutError, asyncio.TimeoutError) as err:
            raise TelinkConnectionError(f"{name}: {err}") from err

        try:
            await self._login(client, ble_device.address)
        except BaseException:
            self._expected_disconnect = True
            try:
                await client.disconnect()
            except BleakError:  # pragma: no cover - best effort
                pass
            raise

        self._client = client
        self._address = ble_device.address
        _LOGGER.debug("Connected to mesh %s via %s", self._mesh_name, name)

    async def _login(self, client: BleakClient, address: str) -> None:
        request, random8 = build_pair_request(self._mesh_name, self._mesh_password)
        try:
            await client.write_gatt_char(PAIR_CHAR_UUID, request, response=True)
            await asyncio.sleep(PAIR_SETTLE_DELAY)
            response = bytes(await client.read_gatt_char(PAIR_CHAR_UUID))
        except (BleakError, TimeoutError, asyncio.TimeoutError) as err:
            raise TelinkConnectionError(f"pairing exchange failed: {err}") from err

        self._session_key = parse_pair_response(
            self._mesh_name, self._mesh_password, random8, response
        )
        self._mac_le = mac_to_le(address)

        # Notifications (characteristic ...1911) carry the status feedback.
        # Telink firmwares enable them by writing 0x01 to the characteristic
        # value (not via a CCCD descriptor), and several expose the notify char
        # WITHOUT a CCCD at all -- which makes bleak's standard start_notify
        # refuse to subscribe over an ESPHome proxy. We therefore try bleak
        # first and, on failure, fall back to subscribing directly through the
        # ESPHome proxy by handle (no CCCD needed). Either way it must never
        # block the session: commands are plain writes to ...1912.
        self.notifications_enabled = False
        try:
            await client.start_notify(NOTIFY_CHAR_UUID, self._handle_notification)
            self.notifications_enabled = True
        except (BleakError, TimeoutError, asyncio.TimeoutError) as err:
            _LOGGER.debug("Mesh %s: bleak start_notify failed (%s); trying proxy fallback", self._mesh_name, err)
            self.notifications_enabled = await self._start_notify_via_proxy(client)

        # Tell the device to start reporting; plain value write, harmless if it
        # fails, and required for the proxy fallback to receive anything.
        try:
            await client.write_gatt_char(NOTIFY_CHAR_UUID, b"\x01", response=True)
        except (BleakError, TimeoutError, asyncio.TimeoutError) as err:
            _LOGGER.debug("Mesh %s: notify enable write failed: %s", self._mesh_name, err)

        if not self.notifications_enabled:
            _LOGGER.warning(
                "Mesh %s: status notifications unavailable; the light stays "
                "controllable but its state in Home Assistant is optimistic",
                self._mesh_name,
            )

    async def _start_notify_via_proxy(self, client: BleakClient) -> bool:
        """Subscribe to notifications directly through an ESPHome proxy.

        Bypasses bleak's requirement for a CCCD descriptor by calling the
        aioesphomeapi client's ``bluetooth_gatt_start_notify`` with the notify
        characteristic handle. Only works when the transport is an ESPHome
        proxy; returns False (staying optimistic) for any other backend or if
        the internal API is not shaped as expected.
        """
        try:
            char = client.services.get_characteristic(NOTIFY_CHAR_UUID)
            if char is None:
                return False
            backend = getattr(client, "_backend", None)
            api = getattr(backend, "_client", None)
            addr_int = getattr(backend, "_address_as_int", None)
            if api is None or addr_int is None:
                return False
            start = getattr(api, "bluetooth_gatt_start_notify", None)
            if start is None:
                return False

            def _on_notify(_handle: int, data: bytearray) -> None:
                self._handle_notification(_handle, bytearray(data))

            result = await start(addr_int, char.handle, _on_notify)
            # aioesphomeapi returns (stop_coro, cancel) — keep the stop handle.
            self._esp_notify_stop = result[0] if isinstance(result, tuple) else None
        except Exception as err:  # noqa: BLE001 - never let this break the session
            _LOGGER.debug("Mesh %s: proxy notify fallback failed: %s", self._mesh_name, err)
            return False
        _LOGGER.info("Mesh %s: status notifications enabled via ESPHome proxy", self._mesh_name)
        return True

    async def disconnect(self) -> None:
        client = self._client
        self._client = None
        self._expected_disconnect = True
        stop = self._esp_notify_stop
        self._esp_notify_stop = None
        if stop is not None:
            try:
                await stop()
            except Exception as err:  # noqa: BLE001 - best effort
                _LOGGER.debug("Error stopping proxy notify: %s", err)
        if client is not None:
            try:
                await client.disconnect()
            except BleakError as err:  # pragma: no cover - best effort
                _LOGGER.debug("Error while disconnecting: %s", err)

    async def send(self, target: int, opcode: int, params: bytes | list[int] = b"") -> None:
        """Encrypt and write one command packet."""
        client = self._client
        if client is None or not client.is_connected or self._session_key is None:
            raise TelinkConnectionError("not connected")
        assert self._mac_le is not None
        packet = build_command(
            self._session_key, self._mac_le, self._sequence.next(), target, opcode, params
        )
        async with self._write_lock:
            try:
                await client.write_gatt_char(
                    COMMAND_CHAR_UUID, packet, response=self._write_with_response
                )
            except (BleakError, TimeoutError, asyncio.TimeoutError) as err:
                raise TelinkConnectionError(f"write failed: {err}") from err
        _LOGGER.debug(
            "-> target=0x%04x op=0x%02x params=%s", target, opcode, bytes(params).hex()
        )

    def _handle_notification(self, _sender, data: bytearray) -> None:
        if self._session_key is None or self._mac_le is None:
            return
        try:
            note = parse_notification(self._session_key, self._mac_le, bytes(data))
        except TelinkProtocolError as err:
            _LOGGER.debug("Bad notification %s: %s", bytes(data).hex(), err)
            return
        if note is None:
            return
        _LOGGER.debug(
            "<- src=0x%04x op=0x%02x params=%s", note.source, note.opcode, note.params.hex()
        )
        if self._notification_callback is not None:
            self._notification_callback(note)

    def _handle_disconnect(self, _client: BleakClient) -> None:
        expected = self._expected_disconnect
        self._client = None
        self._session_key = None
        if expected:
            return
        _LOGGER.debug("Mesh %s: connection to %s lost", self._mesh_name, self._address)
        if self._disconnected_callback is not None:
            self._disconnected_callback()


__all__ = [
    "TelinkAuthError",
    "TelinkConnectionError",
    "TelinkError",
    "TelinkMeshConnection",
]
