"""Verify the built-in credential presets against captured login packets.

The "mesh_lamp" preset (Fulife / 2846) was recovered from two real pairing
writes captured from the Mesh Lamp Android app. This test guards against a
regression in either the preset values or the pairing algorithm.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

_BASE = os.path.join(os.path.dirname(__file__), "..", "custom_components", "telink_mesh")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_BASE, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


p = _load("telink_protocol", "protocol.py")
const = _load("telink_const", "const.py")


def hx(s):
    return bytes(int(x, 16) for x in s.split(","))


# Two real 0x0C pairing writes captured from the Mesh Lamp app for this lamp.
CAPTURED = [
    hx("0C,E4,E6,8C,D0,BB,0B,5F,76,56,2C,0E,53,F6,97,CB,8A"),
    hx("0C,45,18,56,A1,9B,B7,35,4D,9C,CA,08,61,4E,ED,2E,4B"),
]


class PresetTests(unittest.TestCase):
    def test_mesh_lamp_preset_values(self):
        preset = const.CREDENTIAL_PRESETS["mesh_lamp"]
        self.assertEqual(preset[const.CONF_MESH_NAME], "Fulife")
        self.assertEqual(preset[const.CONF_MESH_PASSWORD], "2846")
        self.assertEqual(preset[const.CONF_PROFILE], const.PROFILE_LIVARNO)

    def test_mesh_lamp_preset_reproduces_login(self):
        preset = const.CREDENTIAL_PRESETS["mesh_lamp"]
        name = preset[const.CONF_MESH_NAME]
        pwd = preset[const.CONF_MESH_PASSWORD]
        for packet in CAPTURED:
            random8 = packet[1:9]
            expected = packet[9:17]
            request, _ = p.build_pair_request(name, pwd, random8)
            self.assertEqual(request[9:17], expected)

    def test_manual_is_last_and_default_is_first(self):
        self.assertEqual(const.PRESETS[-1], const.PRESET_MANUAL)
        self.assertEqual(const.DEFAULT_PRESET, "mesh_lamp")
        self.assertNotIn(const.PRESET_MANUAL, const.CREDENTIAL_PRESETS)


if __name__ == "__main__":
    unittest.main()
