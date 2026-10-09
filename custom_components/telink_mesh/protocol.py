"""Telink BLE mesh protocol primitives.

This module has no Home Assistant dependencies so it can be unit tested on
its own.  The key exchange and packet encryption follow python-dimond
(Google, Apache-2.0) and telinkpp (Vincent Paeder); the command codes come
from the Telink mesh SDK and from the analysis of the Briloner / Lidl
Livarno apps done in telinkpp.

Packet layout (20 bytes, little endian multi-byte fields):

    bytes 0-2   sequence number (only 0-1 are used when sending)
    bytes 3-4   MAC (filled in by encrypt_packet) / source address in replies
    bytes 5-6   target mesh address
    byte  7     opcode
    bytes 8-9   vendor id (0x0211 for Telink)
    bytes 10-19 parameters
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# GATT UUIDs -----------------------------------------------------------------
NOTIFY_CHAR_UUID: Final = "00010203-0405-0607-0809-0a0b0c0d1911"
COMMAND_CHAR_UUID: Final = "00010203-0405-0607-0809-0a0b0c0d1912"
PAIR_CHAR_UUID: Final = "00010203-0405-0607-0809-0a0b0c0d1914"

# Some Telink firmwares advertise the 16-bit mesh service UUID 0x1910; Fulife
# lamps advertise 0xFEF1 plus Telink manufacturer data instead.
ADV_SERVICE_UUID: Final = "00001910-0000-1000-8000-00805f9b34fb"
# Telink's Bluetooth company id: the advertisement's manufacturer data key and
# the vendor id inside every command packet.
TELINK_MANUFACTURER_ID: Final = 0x0211

# Mesh addresses -------------------------------------------------------------
ADDR_CONNECTED: Final = 0x0000  # the node we are connected to
ADDR_ALL: Final = 0xFFFF  # every node of the mesh

# Opcodes shared by all Telink mesh firmwares ---------------------------------
OP_STATUS_QUERY: Final = 0xDA
OP_STATUS_REPORT: Final = 0xDB
OP_ONLINE_STATUS: Final = 0xDC
OP_TIME_SET: Final = 0xE4

# Opcodes of the Lidl Livarno / Briloner firmware (telinkpp)
OP_LIVARNO_ON_OFF: Final = 0xF0
OP_LIVARNO_ATTRIBUTES: Final = 0xF1

# Opcodes of the generic Telink mesh light SDK (python-dimond / tikteck)
OP_GENERIC_ON_OFF: Final = 0xD0
OP_GENERIC_BRIGHTNESS: Final = 0xD2
OP_GENERIC_COLOR: Final = 0xE2

MIN_KELVIN: Final = 2700
MAX_KELVIN: Final = 6500

PAIR_REQUEST: Final = 0x0C
PAIR_RESPONSE_OK: Final = 0x0D
PAIR_RESPONSE_FAIL: Final = 0x0E
# Writing new network credentials to the pairing characteristic.
PAIR_SET_NAME: Final = 0x04
PAIR_SET_PASSWORD: Final = 0x05
PAIR_SET_LTK: Final = 0x06
PAIR_SET_OK: Final = 0x07

# Mesh name and password are each zero padded into one 16-byte AES block.
MESH_NAME_MAX_BYTES: Final = 16

# Long-term key used by the Telink mesh SDK and apps.
DEFAULT_LTK: Final = bytes(range(0xC0, 0xD0))


class TelinkError(Exception):
    """Base error."""


class TelinkAuthError(TelinkError):
    """Wrong mesh name or password."""


class TelinkProtocolError(TelinkError):
    """Malformed data received from the device."""


# Crypto ---------------------------------------------------------------------


def _aes128_ecb(key: bytes, data: bytes) -> bytes:
    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def telink_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB with byte-reversed key, input and output (Telink quirk)."""
    if len(key) != 16 or len(data) % 16:
        raise ValueError("key must be 16 bytes and data a multiple of 16 bytes")
    return _aes128_ecb(bytes(reversed(key)), bytes(reversed(data)))[::-1]


def _pad16(text: str) -> bytes:
    raw = text.encode("utf-8")
    if len(raw) > MESH_NAME_MAX_BYTES:
        raise ValueError(
            f"mesh name and password are limited to {MESH_NAME_MAX_BYTES} bytes"
        )
    return raw.ljust(MESH_NAME_MAX_BYTES, b"\0")


def mesh_key(name: str, password: str) -> bytes:
    """Return name XOR password, both zero padded to 16 bytes."""
    return bytes(a ^ b for a, b in zip(_pad16(name), _pad16(password)))


def build_pair_request(
    name: str, password: str, random8: bytes | None = None
) -> tuple[bytes, bytes]:
    """Build the login packet written to the pairing characteristic.

    Returns ``(packet, random8)``; ``random8`` is needed later to derive the
    session key from the device reply.
    """
    if random8 is None:
        random8 = os.urandom(8)
    if len(random8) != 8:
        raise ValueError("random8 must be 8 bytes")
    key = random8 + bytes(8)
    encrypted = telink_encrypt(key, mesh_key(name, password))
    return bytes([PAIR_REQUEST]) + random8 + encrypted[:8], random8


def parse_pair_response(
    name: str, password: str, random8: bytes, response: bytes
) -> bytes:
    """Derive the 16 byte session key from the pairing characteristic value."""
    # A rejection may be the single byte 0x0E, so check it before the length.
    if response[:1] == bytes([PAIR_RESPONSE_FAIL]):
        raise TelinkAuthError("device rejected mesh name / password")
    if len(response) < 9:
        raise TelinkProtocolError(f"pairing response too short: {response.hex()}")
    if response[0] != PAIR_RESPONSE_OK:
        raise TelinkProtocolError(
            f"unexpected pairing response 0x{response[0]:02x}: {response.hex()}"
        )
    return telink_encrypt(mesh_key(name, password), random8 + bytes(response[1:9]))


def validate_credentials(name: str, password: str) -> None:
    """Raise ValueError for credentials a lamp cannot use safely."""
    if not name or not password:
        raise ValueError("mesh name and password must not be empty")
    # Raises for values over 16 bytes.
    if not any(mesh_key(name, password)):
        # name == password gives an all-zero network key.
        raise ValueError("mesh name and password must differ")


def within_edit_distance_one(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by at most one insert/delete/substitute.

    A single corrupted byte in a BLE advertisement turns e.g. ``karp`` into
    ``katp`` or ``kar@``; such near-duplicates of a known mesh name should not
    be treated as a new mesh.
    """
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:  # one substitution
        return sum(x != y for x, y in zip(a, b)) == 1
    # one insertion/deletion: the shorter must be the longer with one char gone
    if la > lb:
        a, b = b, a  # ensure a is the shorter
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def build_set_credentials(
    session_key: bytes, name: str, password: str, ltk: bytes = DEFAULT_LTK
) -> list[bytes]:
    """Packets that move a logged-in lamp to a new mesh name / password.

    Written in order to the pairing characteristic; the lamp then answers
    ``PAIR_SET_OK`` when read.
    """
    validate_credentials(name, password)
    if len(ltk) != 16:
        raise ValueError("long-term key must be 16 bytes")
    return [
        bytes([PAIR_SET_NAME]) + telink_encrypt(session_key, _pad16(name)),
        bytes([PAIR_SET_PASSWORD]) + telink_encrypt(session_key, _pad16(password)),
        bytes([PAIR_SET_LTK]) + telink_encrypt(session_key, ltk),
    ]


def mac_to_le(address: str) -> bytes:
    """Convert ``AA:BB:CC:DD:EE:FF`` into little-endian 6 bytes."""
    parts = address.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address {address!r}")
    return bytes(int(part, 16) for part in reversed(parts))


def encrypt_packet(session_key: bytes, mac_le: bytes, packet: bytes) -> bytes:
    """Authenticate and encrypt a 20 byte command packet."""
    if len(packet) != 20:
        raise ValueError("packet must be 20 bytes")
    pkt = bytearray(packet)
    nonce = bytes(mac_le[:4]) + b"\x01" + bytes(pkt[0:3]) + b"\x0f" + bytes(7)
    auth = bytearray(telink_encrypt(session_key, nonce))
    for i in range(15):
        auth[i] ^= pkt[i + 5]
    mac = telink_encrypt(session_key, bytes(auth))
    pkt[3] = mac[0]
    pkt[4] = mac[1]
    iv = b"\x00" + bytes(mac_le[:4]) + b"\x01" + bytes(pkt[0:3]) + bytes(7)
    stream = telink_encrypt(session_key, iv)
    for i in range(15):
        pkt[i + 5] ^= stream[i]
    return bytes(pkt)


def decrypt_packet(session_key: bytes, mac_le: bytes, packet: bytes) -> bytes:
    """Decrypt a notification received from the connected node."""
    if len(packet) < 8:
        raise TelinkProtocolError(f"notification too short: {packet.hex()}")
    pkt = bytearray(packet)
    iv = b"\x00" + bytes(mac_le[:3]) + bytes(pkt[0:5]) + bytes(7)
    stream = telink_encrypt(session_key, iv)
    for i in range(min(len(pkt) - 7, 16)):
        pkt[i + 7] ^= stream[i]
    return bytes(pkt)


# Packets ---------------------------------------------------------------------


class SequenceCounter:
    """16 bit packet counter, 1..0xFFFF, random start."""

    def __init__(self, start: int | None = None) -> None:
        self._value = start if start is not None else random.randrange(1, 0xFFFF)

    def next(self) -> int:
        value = self._value
        self._value = self._value + 1 if self._value < 0xFFFF else 1
        return value


def build_command(
    session_key: bytes,
    mac_le: bytes,
    sequence: int,
    target: int,
    opcode: int,
    params: bytes | bytearray | list[int] = b"",
    vendor: int = TELINK_MANUFACTURER_ID,
) -> bytes:
    """Build an encrypted command packet ready to be written to ``…1912``."""
    params = bytes(params)
    if len(params) > 10:
        raise ValueError("at most 10 parameter bytes fit in a packet")
    pkt = bytearray(20)
    pkt[0] = sequence & 0xFF
    pkt[1] = (sequence >> 8) & 0xFF
    pkt[5] = target & 0xFF
    pkt[6] = (target >> 8) & 0xFF
    pkt[7] = opcode & 0xFF
    pkt[8] = vendor & 0xFF
    pkt[9] = (vendor >> 8) & 0xFF
    pkt[10 : 10 + len(params)] = params
    return encrypt_packet(session_key, mac_le, bytes(pkt))


@dataclass(slots=True, frozen=True)
class Notification:
    """A decrypted notification."""

    opcode: int
    source: int
    target: int
    params: bytes
    raw: bytes


def parse_notification(
    session_key: bytes, mac_le: bytes, data: bytes, vendor: int = TELINK_MANUFACTURER_ID
) -> Notification | None:
    """Decrypt a notification; return None when it is not for our vendor."""
    if len(data) < 10:
        return None
    pkt = decrypt_packet(session_key, mac_le, data)
    if pkt[8] != (vendor & 0xFF) or pkt[9] != (vendor >> 8) & 0xFF:
        return None
    return Notification(
        opcode=pkt[7],
        source=pkt[3] | (pkt[4] << 8),
        target=pkt[5] | (pkt[6] << 8),
        params=bytes(pkt[10:]),
        raw=pkt,
    )


@dataclass(slots=True, frozen=True)
class OnlineStatusEntry:
    """One node entry from an online status report (opcode 0xDC).

    Each entry is 4 bytes: mesh address, sequence number (0 when the node
    is offline in the generic SDK), brightness (0 when the light is off)
    and a reserved byte that the Livarno firmware uses as 0x40 = on /
    0x41 = off.
    """

    mesh_id: int
    sequence: int
    brightness: int
    reserved: int

    @property
    def online(self) -> bool:
        return self.sequence != 0 or self.brightness != 0

    @property
    def is_on(self) -> bool:
        if self.reserved == 0x41:
            return False
        if self.reserved == 0x40:
            return True
        return self.brightness > 0


def parse_online_status(params: bytes) -> list[OnlineStatusEntry]:
    """Parse the parameters of an online status notification."""
    entries: list[OnlineStatusEntry] = []
    for offset in range(0, len(params) - 3, 4):
        mesh_id, sequence, brightness, reserved = params[offset : offset + 4]
        if mesh_id in (0x00, 0xFF):
            continue
        entries.append(OnlineStatusEntry(mesh_id, sequence, brightness, reserved))
    return entries


@dataclass(slots=True, frozen=True)
class StatusReport:
    """Light status report (opcode 0xDB) of the Livarno firmware."""

    brightness: int
    red: int
    green: int
    blue: int
    y: int
    w: int

    @property
    def is_rgb(self) -> bool:
        return (self.red or self.green or self.blue) != 0 and not (self.y or self.w)

    @property
    def is_white(self) -> bool:
        return (self.y or self.w) != 0


def parse_status_report(params: bytes) -> StatusReport:
    if len(params) < 6:
        raise TelinkProtocolError(f"status report too short: {params.hex()}")
    return StatusReport(*params[:6])


# Advertisement ---------------------------------------------------------------

AD_TYPE_SHORT_NAME: Final = 0x08
AD_TYPE_COMPLETE_NAME: Final = 0x09


def adv_local_name(raw: bytes) -> str | None:
    """Local name carried in one raw advertisement packet, if any."""
    names: dict[int, bytes] = {}
    offset = 0
    while offset < len(raw):
        length = raw[offset]
        if length == 0 or offset + 1 + length > len(raw):
            break
        ad_type = raw[offset + 1]
        if ad_type in (AD_TYPE_SHORT_NAME, AD_TYPE_COMPLETE_NAME):
            names.setdefault(ad_type, raw[offset + 2 : offset + 1 + length])
        offset += 1 + length
    name = names.get(AD_TYPE_COMPLETE_NAME, names.get(AD_TYPE_SHORT_NAME))
    return name.decode("utf-8", "replace") if name else None



def adv_carries_own_mac(address: str, payload: bytes) -> bool | None:
    """Whether Telink manufacturer data names the device that sent it.

    Telink SDK lamps put the low four bytes of their own MAC, little-endian,
    after the 2-byte mesh UUID (``FF:00:05:01:07:51`` -> ``a0 08 51 07 01 05``).
    A proxy that splices packets can attach a lamp's data to another device's
    address, or deliver it under a corrupted MAC; then the bytes disagree.
    Returns None when the payload is too short (or the address not a MAC) to tell.
    """
    if len(payload) < 6:
        return None
    try:
        mac_le = mac_to_le(address)
    except ValueError:
        return None
    return payload[2:6] == mac_le[:4]


# Colour temperature ------------------------------------------------------------


# The Y (warm) and W (cold) channels cross-fade around the middle of the range:
# below it Y stays full and W rises, above it W stays full and Y falls.
_MID_KELVIN: Final = (MIN_KELVIN + MAX_KELVIN) // 2
_HALF_SPAN: Final = (MAX_KELVIN - MIN_KELVIN) / 2


def kelvin_to_yw(kelvin: int) -> tuple[int, int]:
    """Convert a colour temperature into the (Y, W) channel pair."""
    kelvin = max(MIN_KELVIN, min(MAX_KELVIN, int(kelvin)))
    if kelvin > _MID_KELVIN:
        return int((MAX_KELVIN - kelvin) * 255 / _HALF_SPAN), 255
    return 255, int((kelvin - MIN_KELVIN) * 255 / _HALF_SPAN)


def yw_to_kelvin(y: int, w: int) -> int | None:
    """Inverse of :func:`kelvin_to_yw`; None when the light is not in CCT mode."""
    if not y and not w:
        return None
    if w >= y:
        return int(round(MAX_KELVIN - y * _HALF_SPAN / 255))
    return int(round(MIN_KELVIN + w * _HALF_SPAN / 255))


def clamp_brightness(value: int) -> int:
    return max(0, min(100, int(value)))


# Command profiles ---------------------------------------------------------------


class CommandProfile:
    """Builds ``(opcode, params)`` pairs for a family of Telink lights."""

    key = "base"
    # Whether the 0xDB status report follows the layout parse_status_report
    # expects (verified for Livarno). When False, only the online-status
    # report (0xDC) is trusted for feedback and 0xDB is ignored.
    trust_status_report = True
    # Colour-temperature range the lamp actually supports (Kelvin).
    min_kelvin = MIN_KELVIN
    max_kelvin = MAX_KELVIN

    def power(self, on: bool) -> tuple[int, bytes]:
        raise NotImplementedError

    def brightness(self, brightness: int) -> tuple[int, bytes]:
        raise NotImplementedError

    def rgb(self, red: int, green: int, blue: int, brightness: int) -> tuple[int, bytes]:
        raise NotImplementedError

    def color_temp(
        self, kelvin: int, brightness: int, min_kelvin: int | None = None, max_kelvin: int | None = None
    ) -> tuple[int, bytes]:
        raise NotImplementedError

    def _range(self, min_kelvin: int | None, max_kelvin: int | None) -> tuple[int, int]:
        lo = self.min_kelvin if min_kelvin is None else int(min_kelvin)
        hi = self.max_kelvin if max_kelvin is None else int(max_kelvin)
        if hi <= lo:
            hi = lo + 1
        return lo, hi

    def status_query(self) -> tuple[int, bytes]:
        return OP_STATUS_QUERY, b"\x10"


class LivarnoProfile(CommandProfile):
    """Lidl Livarno LUX / Briloner / C by GE style firmware (telinkpp)."""

    key = "livarno"

    def power(self, on: bool) -> tuple[int, bytes]:
        return OP_LIVARNO_ON_OFF, bytes([1 if on else 0, 0, 0])

    def brightness(self, brightness: int) -> tuple[int, bytes]:
        return OP_LIVARNO_ATTRIBUTES, bytes(
            [clamp_brightness(brightness), 0, 0, 0, 0, 0, 0, 1]
        )

    def rgb(self, red: int, green: int, blue: int, brightness: int) -> tuple[int, bytes]:
        brightness = max(1, clamp_brightness(brightness))
        return OP_LIVARNO_ATTRIBUTES, bytes(
            [brightness, red & 0xFF, green & 0xFF, blue & 0xFF, 0, 0, 0, 0]
        )

    def color_temp(
        self, kelvin: int, brightness: int, min_kelvin: int | None = None, max_kelvin: int | None = None
    ) -> tuple[int, bytes]:
        brightness = max(1, clamp_brightness(brightness))
        lo, hi = self._range(min_kelvin, max_kelvin)
        y, w = kelvin_to_yw(max(lo, min(hi, int(kelvin))))
        return OP_LIVARNO_ATTRIBUTES, bytes([brightness, 0, 0, 0, y, w, 0, 0])


class GenericProfile(CommandProfile):
    """Stock Telink mesh light SDK opcodes (python-dimond / python-tikteck)."""

    key = "generic"
    # The Fulife / Mesh Lamp firmware's 0xDB layout differs from what
    # parse_status_report expects, so we rely on the online-status report only.
    trust_status_report = False
    # This firmware's white range is 3000-6000 K and its CCT byte runs the
    # opposite way (0 = coldest, 100 = warmest).
    min_kelvin = 3000
    max_kelvin = 6000

    def power(self, on: bool) -> tuple[int, bytes]:
        return OP_GENERIC_ON_OFF, bytes([1 if on else 0, 0, 0])

    def brightness(self, brightness: int) -> tuple[int, bytes]:
        return OP_GENERIC_BRIGHTNESS, bytes([clamp_brightness(brightness)])

    def rgb(self, red: int, green: int, blue: int, brightness: int) -> tuple[int, bytes]:
        return OP_GENERIC_COLOR, bytes([0x04, red & 0xFF, green & 0xFF, blue & 0xFF])

    def color_temp(
        self, kelvin: int, brightness: int, min_kelvin: int | None = None, max_kelvin: int | None = None
    ) -> tuple[int, bytes]:
        lo, hi = self._range(min_kelvin, max_kelvin)
        kelvin = max(lo, min(hi, int(kelvin)))
        # Inverted: 0 = coldest (max K), 100 = warmest (min K).
        percent = int(round((hi - kelvin) * 100 / (hi - lo)))
        return OP_GENERIC_COLOR, bytes([0x05, percent])


PROFILES: dict[str, CommandProfile] = {
    LivarnoProfile.key: LivarnoProfile(),
    GenericProfile.key: GenericProfile(),
}


def get_profile(key: str) -> CommandProfile:
    return PROFILES.get(key, PROFILES[LivarnoProfile.key])


def time_set_params(year: int, month: int, day: int, hour: int, minute: int, second: int) -> bytes:
    return bytes([year & 0xFF, (year >> 8) & 0xFF, month, day, hour, minute, second])
