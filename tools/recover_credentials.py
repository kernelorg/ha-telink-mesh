#!/usr/bin/env python3
"""Recover a Telink mesh name / password from captured login (pairing) packets.

The Mesh Lamp / weSmart / Telink apps log in by writing a 17-byte packet to the
pairing characteristic 00010203-0405-0607-0809-0a0b0c0d1914:

    0C <8 random bytes> <8 signature bytes>

The signature is AES(name XOR password) over (random + zeros). The random bytes
are in the packet, so any candidate (name, password) can be checked offline: it
matches when the recomputed signature equals the captured one. Passing two
different captures makes a hit certain.

Usage:

    # one or more captured login writes, comma- or space-separated hex:
    python3 tools/recover_credentials.py \\
        "0C,E4,E6,8C,D0,BB,0B,5F,76,56,2C,0E,53,F6,97,CB,8A" \\
        "0C,45,18,56,A1,9B,B7,35,4D,9C,CA,08,61,4E,ED,2E,4B"

    # optionally restrict names / numeric password range:
    python3 tools/recover_credentials.py --names Fulife,telink_mesh1 \\
        --max-digits 6 <packet-hex>

By default it tries a small name list against numeric passwords up to 8 digits
and a handful of common string passwords. Add your own guesses with --names /
--passwords. The lamp's advertised name (e.g. "Fulife") is a strong name guess.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_PROTO = os.path.join(
    os.path.dirname(__file__), "..", "custom_components", "telink_mesh", "protocol.py"
)
_spec = importlib.util.spec_from_file_location("telink_protocol", _PROTO)
proto = importlib.util.module_from_spec(_spec)
sys.modules["telink_protocol"] = proto
_spec.loader.exec_module(proto)

DEFAULT_NAMES = [
    "Fulife", "telink_mesh1", "telink_mesh", "telink", "Telink",
    "wesmart", "weSmart", "smartlight", "SmartLight", "Mesh Lamp", "meshlamp",
]
DEFAULT_STRING_PWDS = [
    "123", "1234", "12345", "123456", "0000", "8888", "888888", "666666",
    "111111", "000000", "admin", "password", "telink", "123456789",
]


def parse_packet(text: str) -> bytes:
    text = text.strip().replace("0x", "").replace(" ", ",")
    parts = [p for p in text.replace(",", " ").split() if p]
    data = bytes(int(p, 16) for p in parts)
    if len(data) < 17 or data[0] != 0x0C:
        raise SystemExit(f"not a 0x0C pairing packet (17 bytes): {text!r}")
    return data[:17]


def _cipher_for(random8: bytes):
    key = bytes(reversed(random8 + bytes(8)))
    return Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())


def _pad(s: str) -> bytes:
    return s.encode("utf-8").ljust(16, b"\0")[:16]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("packets", nargs="+", help="captured 0x0C login write(s), hex")
    ap.add_argument("--names", help="comma-separated candidate mesh names")
    ap.add_argument("--passwords", help="comma-separated extra candidate passwords")
    ap.add_argument("--max-digits", type=int, default=8, help="numeric password length to sweep (default 8)")
    args = ap.parse_args()

    samples = []
    for text in args.packets:
        pkt = parse_packet(text)
        samples.append((pkt[1:9], pkt[9:17], _cipher_for(pkt[1:9])))
    print(f"{len(samples)} login packet(s) loaded")

    names = args.names.split(",") if args.names else DEFAULT_NAMES
    extra_pwds = args.passwords.split(",") if args.passwords else []

    def check(name: str, pwd: str) -> bool:
        mk = bytes(a ^ b for a, b in zip(_pad(name), _pad(pwd)))
        rmk = bytes(reversed(mk))
        for _random8, sig, cipher in samples:
            enc = cipher.encryptor()
            ct = enc.update(rmk) + enc.finalize()
            if bytes(reversed(ct))[:8] != sig:
                return False
        return True

    t0 = time.time()
    # string passwords first
    for name in names:
        for pwd in DEFAULT_STRING_PWDS + extra_pwds:
            if check(name, pwd):
                _report(name, pwd, t0)
                return
    # numeric sweep
    limit = 10 ** args.max_digits
    for name in names:
        for num in range(limit):
            if check(name, str(num)):
                _report(name, str(num), t0)
                return
    print(f"no match after {time.time() - t0:.1f}s; try more --names or --passwords")


def _report(name: str, pwd: str, t0: float) -> None:
    print(f"\nMATCH in {time.time() - t0:.1f}s")
    print(f"  mesh name     : {name}")
    print(f"  mesh password : {pwd}")
    print(f"  mesh key      : {proto.mesh_key(name, pwd).hex()}")


if __name__ == "__main__":
    main()
