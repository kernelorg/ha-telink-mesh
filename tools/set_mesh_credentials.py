#!/usr/bin/env python3
"""Move Telink mesh lamps to a new mesh name / password through an ESPHome proxy.

Each lamp is changed over its own direct connection (Telink applies new
credentials only to the node you are logged in to):

    1. log in with the current name/password (pair opcode 0x0C -> 0x0D),
    2. write 0x04 + enc(new name), 0x05 + enc(new password), 0x06 + enc(LTK)
       to the pairing characteristic, each encrypted with the session key,
    3. read the pairing characteristic: 0x07 means the lamp accepted them,
    4. reconnect and log in with the new credentials to verify.

All lamps that must keep relaying for each other need the SAME new name,
password and LTK. Lamps left on the old credentials form a separate mesh.

Usage (try one lamp first, close to the proxy):

    export ESPHOME_NOISE_PSK=...          # or --psk-file
    python3 tools/set_mesh_credentials.py --proxy 192.168.1.50 \\
        --mac FF:00:01:03:09:E3 --check                  # login test only

    python3 tools/set_mesh_credentials.py --proxy 192.168.1.50 \\
        --mac FF:00:01:03:09:E3 --new-name Home1 --new-password 7351

Undo by running it again with --name/--password set to the new values and
--new-name Fulife --new-password 2846.

Requires: pip install aioesphomeapi cryptography
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import sys
from collections.abc import Callable

from aioesphomeapi import APIClient

_PROTO = os.path.join(
    os.path.dirname(__file__), "..", "custom_components", "telink_mesh", "protocol.py"
)
_spec = importlib.util.spec_from_file_location("telink_protocol", _PROTO)
proto = importlib.util.module_from_spec(_spec)
sys.modules["telink_protocol"] = proto
_spec.loader.exec_module(proto)

DEFAULT_LTK = proto.DEFAULT_LTK
PAIR_SET_OK = proto.PAIR_SET_OK
ADV_WAIT = 60.0
CONNECT_TIMEOUT = 20.0
PAIR_SETTLE = 0.3
VERIFY_TIMEOUT = 3.0
VERIFY_ATTEMPTS = 3
COMMIT_SETTLE = 1.0


class LampError(Exception):
    """A step failed for one lamp."""


def mac_to_int(mac: str) -> int:
    return int(mac.replace(":", "").replace("-", ""), 16)


def check_credential(value: str, what: str) -> str:
    if not value or len(value.encode("utf-8")) > proto.MESH_NAME_MAX_BYTES:
        raise argparse.ArgumentTypeError(
            f"{what} must be 1..{proto.MESH_NAME_MAX_BYTES} bytes"
        )
    return value


class ProxyLamp:
    """GATT session with one lamp through the ESPHome Bluetooth proxy."""

    def __init__(self, api: APIClient, feature_flags: int, mac: str, address_type: int) -> None:
        self.api = api
        self.feature_flags = feature_flags
        self.mac = mac
        self.address = mac_to_int(mac)
        self.address_type = address_type
        self.pair_handle: int | None = None
        self.notify_handle: int | None = None
        self.command_handle: int | None = None
        self._cancel = None
        self.connected = False

    def _on_state(self, connected: bool, _mtu: int, error: int) -> None:
        self.connected = connected and not error

    async def connect(self) -> None:
        self._cancel = await self.api.bluetooth_device_connect(
            self.address,
            self._on_state,
            timeout=CONNECT_TIMEOUT,
            feature_flags=self.feature_flags,
            has_cache=False,
            address_type=self.address_type,
        )
        services = await self.api.bluetooth_gatt_get_services(self.address)
        handles = {
            char.uuid.lower(): char.handle
            for service in services.services
            for char in service.characteristics
        }
        self.pair_handle = handles.get(proto.PAIR_CHAR_UUID)
        self.notify_handle = handles.get(proto.NOTIFY_CHAR_UUID)
        self.command_handle = handles.get(proto.COMMAND_CHAR_UUID)
        if self.pair_handle is None:
            raise LampError("pairing characteristic ...1914 not found")

    async def disconnect(self) -> None:
        try:
            await self.api.bluetooth_device_disconnect(self.address)
        except Exception:  # noqa: BLE001 - best effort
            pass
        if self._cancel:
            self._cancel()
            self._cancel = None

    async def write_pair(self, data: bytes) -> None:
        await self.api.bluetooth_gatt_write(self.address, self.pair_handle, data, True)

    async def read_pair(self) -> bytes:
        return bytes(await self.api.bluetooth_gatt_read(self.address, self.pair_handle))

    async def login(self, name: str, password: str) -> bytes:
        request, random8 = proto.build_pair_request(name, password)
        await self.write_pair(request)
        await asyncio.sleep(PAIR_SETTLE)
        response = await self.read_pair()
        return proto.parse_pair_response(name, password, random8, response)

    async def verify_session_key(self, session_key: bytes) -> bool:
        """Confirm the session key matches the lamp's via a decryptable reply.

        Returns False (so the caller does NOT write new credentials) when the
        notify/command characteristics are missing, notifications cannot be
        enabled, or no reply decrypts with our key within the timeout.
        """
        if self.notify_handle is None or self.command_handle is None:
            return False
        mac_le = proto.mac_to_le(self.mac)
        got = asyncio.Event()

        def on_notify(_handle: int, data: bytearray) -> None:
            try:
                note = proto.parse_notification(session_key, mac_le, bytes(data))
            except proto.TelinkProtocolError:
                return
            if note is not None:
                got.set()

        try:
            stop, _cancel = await self.api.bluetooth_gatt_start_notify(
                self.address, self.notify_handle, on_notify
            )
        except Exception:  # noqa: BLE001
            return False
        try:
            # Enable reporting (plain value write) then query status.
            try:
                await self.api.bluetooth_gatt_write(
                    self.address, self.notify_handle, b"\x01", True
                )
            except Exception:  # noqa: BLE001
                pass
            seq = proto.SequenceCounter()
            for _ in range(VERIFY_ATTEMPTS):
                pkt = proto.build_command(
                    session_key, mac_le, seq.next(),
                    proto.ADDR_CONNECTED, *proto.CommandProfile().status_query(),
                )
                await self.api.bluetooth_gatt_write(
                    self.address, self.command_handle, pkt, True
                )
                try:
                    await asyncio.wait_for(got.wait(), VERIFY_TIMEOUT)
                    return True
                except asyncio.TimeoutError:
                    continue
            return False
        finally:
            try:
                await stop()
            except Exception:  # noqa: BLE001
                pass

    async def set_credentials(self, session_key: bytes, name: str, password: str, ltk: bytes) -> bytes:
        for packet in proto.build_set_credentials(session_key, name, password, ltk):
            await self.write_pair(packet)
            await asyncio.sleep(PAIR_SETTLE)
        await asyncio.sleep(COMMIT_SETTLE)
        return await self.read_pair()


async def wait_for_lamps(
    api: APIClient, macs: list[str], wait: float
) -> tuple[dict[str, tuple[int, int]], Callable[[], None]]:
    """Return ({mac: (address_type, rssi)}, unsubscribe) for the lamps heard.

    The subscription must stay open while connecting: the proxy sends
    connection and GATT replies only to the API client subscribed to its
    advertisements.
    """
    wanted = {mac_to_int(m): m for m in macs}
    found: dict[str, tuple[int, int]] = {}
    done = asyncio.Event()

    def on_adv(msg) -> None:
        for adv in msg.advertisements:
            mac = wanted.get(adv.address)
            if mac and mac not in found:
                found[mac] = (adv.address_type, adv.rssi)
                print(f"  heard {mac} rssi {adv.rssi}")
                if len(found) == len(wanted):
                    done.set()

    unsub = api.subscribe_bluetooth_le_raw_advertisements(on_adv)
    try:
        await asyncio.wait_for(done.wait(), wait)
    except asyncio.TimeoutError:
        pass
    return found, unsub


async def process(
    api: APIClient, flags: int, mac: str, address_type: int, args: argparse.Namespace
) -> bool:
    lamp = ProxyLamp(api, flags, mac, address_type)
    print(f"{mac}: connecting")
    try:
        await lamp.connect()
        session_key = await lamp.login(args.name, args.password)
        print(f"{mac}: logged in as '{args.name}'")
        if args.check:
            return True
        if not args.no_verify:
            if await lamp.verify_session_key(session_key):
                print(f"{mac}: session key verified")
            else:
                print(
                    f"{mac}: could NOT verify the session key (no decryptable "
                    "reply); refusing to change credentials. Retry, move closer "
                    "to the proxy, or pass --no-verify to override."
                )
                return False
        reply = await lamp.set_credentials(session_key, args.new_name, args.new_password, args.ltk)
        if not reply or reply[0] != PAIR_SET_OK:
            print(f"{mac}: lamp did NOT confirm the change (reply {reply.hex()})")
            return False
        print(f"{mac}: lamp confirmed new credentials (0x07)")
    except proto.TelinkAuthError:
        print(f"{mac}: login with '{args.name}' rejected -- wrong current name/password?")
        return False
    except Exception as err:  # noqa: BLE001
        print(f"{mac}: failed: {type(err).__name__}: {err}")
        return False
    finally:
        await lamp.disconnect()

    await asyncio.sleep(2)
    lamp = ProxyLamp(api, flags, mac, address_type)
    try:
        await lamp.connect()
        await lamp.login(args.new_name, args.new_password)
        print(f"{mac}: verified -- login with '{args.new_name}' works")
        return True
    except proto.TelinkAuthError:
        print(f"{mac}: WARNING login with the new credentials was rejected")
        return False
    except Exception as err:  # noqa: BLE001
        print(f"{mac}: could not verify ({type(err).__name__}: {err}); run with --check later")
        return False
    finally:
        await lamp.disconnect()


async def main_async(args: argparse.Namespace) -> int:
    host, _, port = args.proxy.partition(":")
    api = APIClient(host, int(port or 6053), None, noise_psk=args.psk)
    await api.connect(login=True)
    try:
        info = await api.device_info()
        flags = info.bluetooth_proxy_feature_flags_compat(api.api_version)
        print(f"proxy {info.name} (ESPHome {info.esphome_version}), listening up to {args.wait:.0f}s...")
        found, unsub = await wait_for_lamps(api, args.mac, args.wait)
        try:
            ok = True
            for mac in args.mac:
                if mac not in found:
                    print(f"{mac}: not heard by the proxy, skipped")
                    ok = False
                    continue
                ok &= await process(api, flags, mac, found[mac][0], args)
        finally:
            unsub()
        return 0 if ok else 1
    finally:
        await api.disconnect()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proxy", required=True, help="ESPHome proxy host[:port]")
    parser.add_argument("--psk", default=os.environ.get("ESPHOME_NOISE_PSK"), help="noise PSK (or env ESPHOME_NOISE_PSK)")
    parser.add_argument("--psk-file", help="file containing the noise PSK")
    parser.add_argument("--mac", action="append", required=True, type=str.upper, help="lamp MAC, repeatable")
    parser.add_argument("--name", default="Fulife", type=lambda v: check_credential(v, "name"), help="current mesh name")
    parser.add_argument("--password", default="2846", type=lambda v: check_credential(v, "password"), help="current password")
    parser.add_argument("--new-name", type=lambda v: check_credential(v, "new name"))
    parser.add_argument("--new-password", type=lambda v: check_credential(v, "new password"))
    parser.add_argument("--ltk", default=DEFAULT_LTK.hex(), help="new 16-byte long-term key, hex (default: Telink SDK c0..cf)")
    parser.add_argument("--wait", type=float, default=ADV_WAIT, help="seconds to wait for the lamps' advertisements")
    parser.add_argument("--check", action="store_true", help="only test login with the current credentials")
    parser.add_argument("--no-verify", action="store_true", help="skip the session-key check before writing (not recommended)")
    args = parser.parse_args()

    if args.psk_file:
        with open(args.psk_file, encoding="utf-8") as fh:
            args.psk = fh.read().strip()
    if not args.check:
        if not (args.new_name and args.new_password):
            parser.error("--new-name and --new-password are required (or use --check)")
        try:
            proto.validate_credentials(args.new_name, args.new_password)
        except ValueError as err:
            parser.error(str(err))
    args.ltk = bytes.fromhex(args.ltk)
    if len(args.ltk) != 16:
        parser.error("--ltk must be 16 bytes (32 hex characters)")
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
