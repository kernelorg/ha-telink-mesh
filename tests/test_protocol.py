"""Tests for the protocol module against a literal port of python-dimond.

Run with:  python3 -m unittest discover -s tests
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load protocol.py directly: the package __init__ imports Home Assistant.
_PROTOCOL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "custom_components", "telink_mesh", "protocol.py"
)
_spec = importlib.util.spec_from_file_location("telink_protocol", _PROTOCOL_PATH)
p = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = p
_spec.loader.exec_module(p)


# --- Literal port of python-dimond (list based) used as the reference -------


def _dimond_encrypt(key, data):
    enc = Cipher(
        algorithms.AES(bytes(reversed(key))), modes.ECB(), backend=default_backend()
    ).encryptor()
    out = enc.update(bytes(reversed(data))) + enc.finalize()
    return list(reversed(list(out)))


def _dimond_generate_sk(name, password, data1, data2):
    name = name.ljust(16, chr(0))
    password = password.ljust(16, chr(0))
    key = [ord(a) ^ ord(b) for a, b in zip(name, password)]
    data = list(data1[0:8]) + list(data2[0:8])
    return _dimond_encrypt(key, data)


def _dimond_key_encrypt(name, password, key):
    name = name.ljust(16, chr(0))
    password = password.ljust(16, chr(0))
    data = [ord(a) ^ ord(b) for a, b in zip(name, password)]
    return _dimond_encrypt(key, data)


def _dimond_encrypt_packet(sk, address, packet):
    packet = list(packet)
    auth_nonce = [address[0], address[1], address[2], address[3], 0x01,
                  packet[0], packet[1], packet[2], 15, 0, 0, 0, 0, 0, 0, 0]
    authenticator = _dimond_encrypt(sk, auth_nonce)
    for i in range(15):
        authenticator[i] = authenticator[i] ^ packet[i + 5]
    mac = _dimond_encrypt(sk, authenticator)
    for i in range(2):
        packet[i + 3] = mac[i]
    iv = [0, address[0], address[1], address[2], address[3], 0x01, packet[0],
          packet[1], packet[2], 0, 0, 0, 0, 0, 0, 0]
    temp_buffer = _dimond_encrypt(sk, iv)
    for i in range(15):
        packet[i + 5] ^= temp_buffer[i]
    return packet


def _dimond_decrypt_packet(sk, address, packet):
    packet = list(packet)
    iv = [address[0], address[1], address[2], packet[0], packet[1], packet[2],
          packet[3], packet[4], 0, 0, 0, 0, 0, 0, 0, 0]
    plaintext = [0] + iv[0:15]
    result = _dimond_encrypt(sk, plaintext)
    for i in range(len(packet) - 7):
        packet[i + 7] ^= result[i]
    return packet


def _dimond_send_packet(sk, macdata, count, vendor, target, command, data):
    packet = [0] * 20
    packet[0] = count & 0xFF
    packet[1] = count >> 8 & 0xFF
    packet[5] = target & 0xFF
    packet[6] = (target >> 8) & 0xFF
    packet[7] = command
    packet[8] = vendor & 0xFF
    packet[9] = (vendor >> 8) & 0xFF
    for i in range(len(data)):
        packet[10 + i] = data[i]
    return _dimond_encrypt_packet(sk, macdata, packet)


MAC = "A4:C1:38:12:34:56"
MACDATA = [0x56, 0x34, 0x12, 0x38, 0xC1, 0xA4]
NAME = "telink_mesh1"
PASSWORD = "123"


class CryptoTests(unittest.TestCase):
    def test_mac_conversion(self):
        self.assertEqual(list(p.mac_to_le(MAC)), MACDATA)
        self.assertEqual(p.le_to_mac(p.mac_to_le(MAC)), MAC)

    def test_pair_request_matches_dimond(self):
        random8 = bytes(range(1, 9))
        packet, _ = p.build_pair_request(NAME, PASSWORD, random8)
        data = list(random8) + [0] * 8
        expected = [0x0C] + data[0:8] + _dimond_key_encrypt(NAME, PASSWORD, data)[0:8]
        self.assertEqual(list(packet), expected)

    def test_session_key_matches_dimond(self):
        random8 = bytes(range(1, 9))
        response = bytes([0x0D]) + bytes(range(0x10, 0x20))
        sk = p.parse_pair_response(NAME, PASSWORD, random8, response)
        expected = _dimond_generate_sk(NAME, PASSWORD, list(random8), list(response[1:9]))
        self.assertEqual(list(sk), expected)

    def test_pair_response_failure(self):
        with self.assertRaises(p.TelinkAuthError):
            p.parse_pair_response(NAME, PASSWORD, bytes(8), bytes([0x0E]) + bytes(16))

    def test_command_matches_dimond(self):
        sk = bytes(range(16))
        params = [0x64, 0xFF, 0x00, 0x80, 0, 0, 0, 0]
        ours = p.build_command(sk, p.mac_to_le(MAC), 0x1234, 0x0005, 0xF1, params)
        ref = _dimond_send_packet(list(sk), MACDATA, 0x1234, 0x0211, 0x0005, 0xF1, params)
        self.assertEqual(list(ours), ref)

    def test_decrypt_matches_dimond(self):
        sk = bytes(range(16, 32))
        raw = bytes(range(20))
        ours = p.decrypt_packet(sk, p.mac_to_le(MAC), raw)
        ref = _dimond_decrypt_packet(list(sk), MACDATA, list(raw))
        self.assertEqual(list(ours), ref)

    def test_notification_roundtrip_via_reference(self):
        """Encrypt a fake notification the way the device would and parse it."""
        sk = bytes(range(32, 48))
        mac_le = p.mac_to_le(MAC)
        plain = bytearray(20)
        plain[0:3] = b"\x01\x02\x03"  # sequence
        plain[3] = 0x07  # source mesh id
        plain[7] = p.OP_ONLINE_STATUS
        plain[8], plain[9] = 0x11, 0x02
        plain[10:14] = bytes([0x07, 0x05, 0x64, 0x40])
        plain[14:18] = bytes([0x08, 0x00, 0x00, 0x00])
        # the stream cipher is symmetric, so "decrypting" plaintext encrypts it
        wire = p.decrypt_packet(sk, mac_le, bytes(plain))
        note = p.parse_notification(sk, mac_le, wire)
        self.assertIsNotNone(note)
        self.assertEqual(note.opcode, p.OP_ONLINE_STATUS)
        self.assertEqual(note.source, 0x07)
        entries = p.parse_online_status(note.params)
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0].is_on)
        self.assertTrue(entries[0].online)
        self.assertEqual(entries[0].brightness, 100)
        self.assertFalse(entries[1].is_on)
        self.assertFalse(entries[1].online)

    def test_wrong_vendor_ignored(self):
        sk = bytes(16)
        mac_le = p.mac_to_le(MAC)
        plain = bytearray(20)
        plain[8], plain[9] = 0x34, 0x12
        wire = p.decrypt_packet(sk, mac_le, bytes(plain))
        self.assertIsNone(p.parse_notification(sk, mac_le, wire))


class ParserTests(unittest.TestCase):
    def test_online_status_livarno_off(self):
        entries = p.parse_online_status(bytes([0x01, 0x03, 0x32, 0x41]))
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0].is_on)
        self.assertTrue(entries[0].online)
        self.assertEqual(entries[0].brightness, 50)

    def test_status_report(self):
        report = p.parse_status_report(bytes([80, 255, 0, 0, 0, 0, 0, 0, 0, 0]))
        self.assertTrue(report.is_rgb)
        self.assertFalse(report.is_white)
        report = p.parse_status_report(bytes([80, 0, 0, 0, 255, 100, 0, 0, 0, 0]))
        self.assertTrue(report.is_white)

    def test_address_report(self):
        params = bytes([0x05, 0x00]) + p.mac_to_le(MAC) + bytes(2)
        report = p.parse_address_report(params)
        self.assertEqual(report.mesh_id, 5)
        self.assertEqual(report.mac, MAC)

    def test_manufacturer_data(self):
        payload = bytes([0x11, 0x02]) + p.mac_to_le(MAC) + bytes([0x01, 0x00, 0x00, 0x09, 0x00])
        adv = p.parse_manufacturer_data(payload)
        self.assertEqual(adv.mesh_uuid, 0x0211)
        self.assertEqual(adv.mac, MAC)
        self.assertEqual(adv.mesh_id, 9)
        self.assertIsNone(p.parse_manufacturer_data(b"\x01"))
        short = p.parse_manufacturer_data(b"\x11\x02")
        self.assertIsNone(short.mac)


class FulifeOnlineStatusTests(unittest.TestCase):
    """Real decrypted 0xDC online-status params captured from a Fulife lamp."""

    def _entry(self, params_hex):
        params = bytes(int(x, 16) for x in params_hex.split(","))
        entries = p.parse_online_status(params)
        self.assertEqual(len(entries), 1)
        return entries[0]

    def test_off(self):
        e = self._entry("51,49,00,FF,00,00,00,00,00,00")
        self.assertEqual(e.mesh_id, 0x51)
        self.assertTrue(e.online)
        self.assertFalse(e.is_on)

    def test_on_full(self):
        e = self._entry("51,64,64,FF,00,00,00,00,00,00")
        self.assertTrue(e.is_on)
        self.assertEqual(e.brightness, 100)

    def test_on_dimmed(self):
        e = self._entry("51,76,37,FF,00,00,00,00,00,00")
        self.assertTrue(e.is_on)
        self.assertEqual(e.brightness, 0x37)


class ProfileStatusTrustTests(unittest.TestCase):
    def test_flags(self):
        self.assertTrue(p.get_profile("livarno").trust_status_report)
        self.assertFalse(p.get_profile("generic").trust_status_report)


class ColorTests(unittest.TestCase):
    def test_kelvin_to_yw_matches_telinkpp(self):
        self.assertEqual(p.kelvin_to_yw(2700), (255, 0))
        self.assertEqual(p.kelvin_to_yw(4600), (255, 255))
        self.assertEqual(p.kelvin_to_yw(6500), (0, 255))
        self.assertEqual(p.kelvin_to_yw(1000), (255, 0))
        self.assertEqual(p.kelvin_to_yw(9000), (0, 255))

    def test_kelvin_roundtrip(self):
        for kelvin in range(2700, 6501, 50):
            y, w = p.kelvin_to_yw(kelvin)
            back = p.yw_to_kelvin(y, w)
            self.assertLessEqual(abs(back - kelvin), 8, kelvin)
        self.assertIsNone(p.yw_to_kelvin(0, 0))


class ProfileTests(unittest.TestCase):
    def test_livarno(self):
        prof = p.get_profile("livarno")
        self.assertEqual(prof.power(True), (0xF0, b"\x01\x00\x00"))
        self.assertEqual(prof.brightness(150), (0xF1, bytes([100, 0, 0, 0, 0, 0, 0, 1])))
        self.assertEqual(prof.rgb(1, 2, 3, 0), (0xF1, bytes([1, 1, 2, 3, 0, 0, 0, 0])))
        self.assertEqual(prof.color_temp(2700, 50), (0xF1, bytes([50, 0, 0, 0, 255, 0, 0, 0])))

    def test_generic(self):
        prof = p.get_profile("generic")
        self.assertEqual(prof.power(False), (0xD0, b"\x00\x00\x00"))
        self.assertEqual(prof.brightness(42), (0xD2, b"\x2a"))
        self.assertEqual(prof.rgb(1, 2, 3, 0), (0xE2, bytes([4, 1, 2, 3])))

    def test_generic_color_temp_inverted_3000_6000(self):
        prof = p.get_profile("generic")
        self.assertEqual(prof.min_kelvin, 3000)
        self.assertEqual(prof.max_kelvin, 6000)
        # coldest (6000 K) -> 0, warmest (3000 K) -> 100
        self.assertEqual(prof.color_temp(6000, 50), (0xE2, bytes([5, 0])))
        self.assertEqual(prof.color_temp(3000, 50), (0xE2, bytes([5, 100])))
        self.assertEqual(prof.color_temp(4500, 50), (0xE2, bytes([5, 50])))
        # out-of-range values clamp into the supported band
        self.assertEqual(prof.color_temp(6500, 50), (0xE2, bytes([5, 0])))
        self.assertEqual(prof.color_temp(2700, 50), (0xE2, bytes([5, 100])))

    def test_unknown_falls_back(self):
        self.assertIs(p.get_profile("nope"), p.PROFILES["livarno"])


if __name__ == "__main__":
    unittest.main()
