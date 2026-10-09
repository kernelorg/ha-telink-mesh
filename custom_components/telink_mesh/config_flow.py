"""Config flow for the Telink mesh integration.

The flow has two stages:

1. pick a vendor preset (e.g. "Mesh Lamp" -> Fulife / 2846) or "Manual entry";
2. review / edit the mesh name, password, command profile and colour mode
   (pre-filled from the chosen preset), then validate against a live device.

Bluetooth discovery jumps straight in with the preset stage.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import logging
from typing import Any

from bleak.exc import BleakError
import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    ABS_MAX_KELVIN,
    ABS_MIN_KELVIN,
    COLOR_MODES,
    CONF_COLOR_MODE,
    CONF_COLOR_TEMP_MAX,
    CONF_COLOR_TEMP_MIN,
    CONF_MESH_NAME,
    CONF_MESH_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_PROFILE,
    CONF_WRITE_WITH_RESPONSE,
    CREDENTIAL_PRESETS,
    DEFAULT_COLOR_MODE,
    DEFAULT_MESH_NAME,
    DEFAULT_MESH_PASSWORD,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_PRESET,
    DEFAULT_PROFILE,
    DEFAULT_WRITE_WITH_RESPONSE,
    DOMAIN,
    MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL,
    PRESET_MANUAL,
    PRESETS,
    PROFILES,
)
from .coordinator import (
    advertised_mesh_name,
    fresh_service_info,
    is_telink_advertisement,
)
from .mesh import TelinkAuthError, TelinkError, TelinkMeshConnection
from .protocol import MESH_NAME_MAX_BYTES, get_profile, within_edit_distance_one

_LOGGER = logging.getLogger(__name__)

CONF_PRESET = "preset"
MAX_LOGIN_CANDIDATES = 3
# Before offering a discovery, wait this long for the device to advertise again,
# so one corrupted packet cannot produce a discovery card.
DISCOVERY_CONFIRM_DELAY = 10.0


def _unique_id(mesh_name: str) -> str:
    return f"mesh_{mesh_name.strip().lower()}"


def _is_usable_mesh_name(name: str | None) -> bool:
    """True for a mesh name we can trust from an advertisement.

    Telink mesh names are printable ASCII of at most 16 bytes. Garbage still
    gets through the MAC check when a lamp's own packet carries a corrupted or
    spliced name, and Home Assistant keeps the longest name an address ever
    sent (e.g. ``Fuline\t\xff\x11\x02``), so the delayed re-check alone does
    not clear it.
    """
    return (
        bool(name)
        and name.isascii()
        and name.isprintable()
        and len(name) <= MESH_NAME_MAX_BYTES
    )


def _profile_selector() -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=PROFILES, translation_key=CONF_PROFILE, mode=SelectSelectorMode.DROPDOWN
        )
    )


def _color_mode_selector() -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=COLOR_MODES,
            translation_key=CONF_COLOR_MODE,
            mode=SelectSelectorMode.DROPDOWN,
        )
    )


def _preset_selector() -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=PRESETS, translation_key="preset", mode=SelectSelectorMode.LIST
        )
    )


def _preset_defaults(preset: str, mesh_name_hint: str | None) -> dict[str, Any]:
    """Return default form values for the credentials step given a preset."""
    if preset != PRESET_MANUAL and preset in CREDENTIAL_PRESETS:
        return dict(CREDENTIAL_PRESETS[preset])
    return {
        CONF_MESH_NAME: mesh_name_hint or DEFAULT_MESH_NAME,
        CONF_MESH_PASSWORD: DEFAULT_MESH_PASSWORD,
        CONF_PROFILE: DEFAULT_PROFILE,
        CONF_COLOR_MODE: DEFAULT_COLOR_MODE,
    }


def _credentials_schema(defaults: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(
                CONF_MESH_NAME, default=defaults.get(CONF_MESH_NAME, DEFAULT_MESH_NAME)
            ): TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
            vol.Required(
                CONF_MESH_PASSWORD,
                default=defaults.get(CONF_MESH_PASSWORD, DEFAULT_MESH_PASSWORD),
            ): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
            vol.Required(
                CONF_PROFILE, default=defaults.get(CONF_PROFILE, DEFAULT_PROFILE)
            ): _profile_selector(),
            vol.Required(
                CONF_COLOR_MODE, default=defaults.get(CONF_COLOR_MODE, DEFAULT_COLOR_MODE)
            ): _color_mode_selector(),
        }
    )


def _discovered_telink(hass: HomeAssistant) -> list[BluetoothServiceInfoBleak]:
    infos = [
        info
        for info in bluetooth.async_discovered_service_info(hass, connectable=True)
        if is_telink_advertisement(info)
    ]
    infos.sort(key=lambda info: info.rssi if info.rssi is not None else -127, reverse=True)
    return infos


def _candidate_addresses(hass: HomeAssistant, mesh_name: str, preferred: str | None) -> list[str]:
    """Addresses worth a login attempt for this mesh.

    Only the device that triggered discovery (``preferred``) and devices that
    advertise the exact mesh name are tried. We deliberately do NOT fall back to
    every unnamed Telink device: many unrelated gadgets use Telink chips, and
    probing them would connect to a neighbour's hardware and waste proxy slots.
    """
    addresses: list[str] = []
    if preferred:
        addresses.append(preferred)
    for info in _discovered_telink(hass):
        if info.address in addresses:
            continue
        if advertised_mesh_name(info) == mesh_name:
            addresses.append(info.address)
    return addresses


async def _async_try_login(hass: HomeAssistant, address: str, mesh_name: str, password: str) -> str | None:
    """Return an error key, or None when the credentials work."""
    device = bluetooth.async_ble_device_from_address(hass, address, connectable=True)
    if device is None:
        _LOGGER.warning(
            "Telink mesh '%s': %s is not reachable through any connectable "
            "Bluetooth adapter or proxy",
            mesh_name,
            address,
        )
        return "cannot_connect"
    connection = TelinkMeshConnection(mesh_name, password)
    try:
        _LOGGER.info("Telink mesh '%s': trying to log in via %s", mesh_name, address)
        await connection.connect(device)
    except TelinkAuthError:
        _LOGGER.warning(
            "Telink mesh '%s': %s rejected the mesh name/password", mesh_name, address
        )
        return "invalid_auth"
    except (TelinkError, BleakError, TimeoutError, asyncio.TimeoutError) as err:
        _LOGGER.warning(
            "Telink mesh '%s': login via %s failed: %s", mesh_name, address, err
        )
        return "cannot_connect"
    finally:
        await connection.disconnect()
    _LOGGER.info("Telink mesh '%s': login via %s succeeded", mesh_name, address)
    return None


async def _async_validate(
    hass: HomeAssistant, mesh_name: str, password: str, preferred: str | None
) -> str | None:
    addresses = _candidate_addresses(hass, mesh_name, preferred)
    _LOGGER.info(
        "Telink mesh '%s': validating against %d candidate address(es): %s",
        mesh_name,
        len(addresses),
        ", ".join(addresses) or "none",
    )
    if not addresses:
        return "no_devices_found"
    error: str | None = "cannot_connect"
    for address in addresses[:MAX_LOGIN_CANDIDATES]:
        error = await _async_try_login(hass, address, mesh_name, password)
        if error is None or error == "invalid_auth":
            return error
    return error


class TelinkMeshConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for a Telink mesh."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovery: BluetoothServiceInfoBleak | None = None
        self._discovered_name: str | None = None
        self._preset: str = DEFAULT_PRESET

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return TelinkMeshOptionsFlow()

    # -- preset selection -------------------------------------------------------------

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """First step: pick a vendor preset or manual entry."""
        if user_input is not None:
            self._preset = user_input[CONF_PRESET]
            return await self.async_step_credentials()

        count = len({
            name
            for name in (advertised_mesh_name(i) for i in _discovered_telink(self.hass))
            if _is_usable_mesh_name(name)
        })
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_PRESET, default=DEFAULT_PRESET): _preset_selector()}
            ),
            description_placeholders={"count": str(count)},
        )

    # -- credentials ------------------------------------------------------------------

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        preferred = self._discovery.address if self._discovery else None
        if user_input is not None:
            mesh_name = user_input[CONF_MESH_NAME].strip()
            await self.async_set_unique_id(_unique_id(mesh_name))
            self._abort_if_unique_id_configured()
            error = await _async_validate(
                self.hass, mesh_name, user_input[CONF_MESH_PASSWORD], preferred
            )
            if error is None:
                return self._create(mesh_name, user_input)
            errors["base"] = error
            defaults = user_input
        else:
            defaults = _preset_defaults(self._preset, self._discovered_name)

        return self.async_show_form(
            step_id="credentials",
            data_schema=_credentials_schema(defaults),
            errors=errors,
            description_placeholders={
                "preset": self._preset,
                "address": preferred or "-",
            },
        )

    # -- bluetooth discovery ----------------------------------------------------------

    def _entry_owns_address(self, address: str) -> bool:
        """True when a loaded entry already drives the lamp at this address.

        Guards against a second flow for a mesh that is already set up: the
        advertised name can arrive garbled or in a different case, so matching
        only by mesh name would miss it, HA would show a duplicate discovery,
        and validating it would steal the lamp's single BLE connection from the
        running entry (breaking it and the All-lights entity).
        """
        target = address.upper()
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            coordinator = getattr(entry, "runtime_data", None)
            if coordinator is not None and target in coordinator.nodes:
                return True
        return False

    def _is_near_configured_mesh(self, name: str) -> bool:
        """True when ``name`` is a one-character variant of a configured mesh."""
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            configured = entry.data.get(CONF_MESH_NAME)
            if configured and within_edit_distance_one(name, configured):
                return True
        return False

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        if (reason := self._discovery_abort_reason(discovery_info)) is not None:
            return self.async_abort(reason=reason)
        await self.async_set_unique_id(_unique_id(advertised_mesh_name(discovery_info)))
        self._abort_if_unique_id_configured()
        # Home Assistant runs discovery once per address, possibly on a corrupted
        # packet. Wait for the next advertisement and judge that one instead: a
        # garbled MAC never advertises again, and a garbled name is replaced by
        # the real one (which may belong to a mesh that is already set up).
        await asyncio.sleep(DISCOVERY_CONFIRM_DELAY)
        fresh = fresh_service_info(self.hass, discovery_info)
        if fresh is None:
            return self.async_abort(reason="not_supported")
        if (reason := self._discovery_abort_reason(fresh)) is not None:
            return self.async_abort(reason=reason)
        await self.async_set_unique_id(_unique_id(advertised_mesh_name(fresh)))
        self._abort_if_unique_id_configured()
        self._discovery = fresh
        self._discovered_name = advertised_mesh_name(fresh)
        self.context["title_placeholders"] = {"name": self._discovered_name}
        return await self.async_step_bluetooth_confirm()

    def _discovery_abort_reason(self, info: BluetoothServiceInfoBleak) -> str | None:
        """Why an advertisement must not become a discovery card, if it must not."""
        if not is_telink_advertisement(info):
            return "not_supported"
        if self._entry_owns_address(info.address):
            return "already_configured"
        name = advertised_mesh_name(info)
        # Without a readable mesh name we cannot tell which mesh this lamp
        # belongs to; a mystery discovery card would only invite a duplicate
        # entry, so skip it (the mesh can still be added manually). Telink mesh
        # names are printable ASCII; a garbled advertisement decodes to a
        # non-ASCII replacement character, which isascii() rejects.
        if not _is_usable_mesh_name(name):
            return "not_supported"
        # A single corrupted byte turns a configured name into a near-duplicate
        # (karp -> katp, Fulife -> Futife); treat those as the known mesh.
        if self._is_near_configured_mesh(name):
            return "already_configured"
        return None

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        assert self._discovery is not None
        if user_input is not None:
            self._preset = user_input[CONF_PRESET]
            return await self.async_step_credentials()
        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=vol.Schema(
                {vol.Required(CONF_PRESET, default=DEFAULT_PRESET): _preset_selector()}
            ),
            description_placeholders={
                "name": self._discovered_name or "?",
                "address": self._discovery.address,
            },
        )

    def _create(self, mesh_name: str, user_input: dict[str, Any]) -> ConfigFlowResult:
        return self.async_create_entry(
            title=mesh_name,
            data={
                CONF_MESH_NAME: mesh_name,
                CONF_MESH_PASSWORD: user_input[CONF_MESH_PASSWORD],
            },
            options={
                CONF_PROFILE: user_input[CONF_PROFILE],
                CONF_COLOR_MODE: user_input[CONF_COLOR_MODE],
                CONF_WRITE_WITH_RESPONSE: DEFAULT_WRITE_WITH_RESPONSE,
                CONF_POLL_INTERVAL: DEFAULT_POLL_INTERVAL,
            },
        )

    # -- reauth -------------------------------------------------------------------------------------

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            error = await _async_validate(
                self.hass, entry.data[CONF_MESH_NAME], user_input[CONF_MESH_PASSWORD], None
            )
            if error is None:
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_MESH_PASSWORD: user_input[CONF_MESH_PASSWORD]}
                )
            errors["base"] = error
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MESH_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    )
                }
            ),
            errors=errors,
            description_placeholders={"name": entry.data[CONF_MESH_NAME]},
        )


class TelinkMeshOptionsFlow(OptionsFlow):
    """Options: command profile, colour modes, write mode, poll interval."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        options = {**self.config_entry.data, **self.config_entry.options}
        if user_input is not None:
            if user_input[CONF_COLOR_TEMP_MAX] <= user_input[CONF_COLOR_TEMP_MIN]:
                errors["base"] = "bad_color_temp_range"
            else:
                user_input[CONF_COLOR_TEMP_MIN] = int(user_input[CONF_COLOR_TEMP_MIN])
                user_input[CONF_COLOR_TEMP_MAX] = int(user_input[CONF_COLOR_TEMP_MAX])
                return self.async_create_entry(data=user_input)
            options = {**options, **user_input}

        profile = get_profile(options.get(CONF_PROFILE, DEFAULT_PROFILE))

        def kelvin_field() -> NumberSelector:
            return NumberSelector(
                NumberSelectorConfig(
                    min=ABS_MIN_KELVIN,
                    max=ABS_MAX_KELVIN,
                    step=50,
                    mode=NumberSelectorMode.BOX,
                    unit_of_measurement="K",
                )
            )
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_PROFILE, default=options.get(CONF_PROFILE, DEFAULT_PROFILE)
                ): _profile_selector(),
                vol.Required(
                    CONF_COLOR_MODE, default=options.get(CONF_COLOR_MODE, DEFAULT_COLOR_MODE)
                ): _color_mode_selector(),
                vol.Required(
                    CONF_COLOR_TEMP_MIN,
                    default=int(options.get(CONF_COLOR_TEMP_MIN) or profile.min_kelvin),
                ): kelvin_field(),
                vol.Required(
                    CONF_COLOR_TEMP_MAX,
                    default=int(options.get(CONF_COLOR_TEMP_MAX) or profile.max_kelvin),
                ): kelvin_field(),
                vol.Required(
                    CONF_WRITE_WITH_RESPONSE,
                    default=options.get(CONF_WRITE_WITH_RESPONSE, DEFAULT_WRITE_WITH_RESPONSE),
                ): BooleanSelector(),
                vol.Required(
                    CONF_POLL_INTERVAL,
                    default=options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
                ): NumberSelector(
                    NumberSelectorConfig(
                        min=MIN_POLL_INTERVAL,
                        max=MAX_POLL_INTERVAL,
                        step=5,
                        mode=NumberSelectorMode.BOX,
                        unit_of_measurement="s",
                    )
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
