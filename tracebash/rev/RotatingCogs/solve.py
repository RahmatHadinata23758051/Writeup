#!/usr/bin/env python3
"""Solver for TBCTF 2026 Reverse - Rotating Cogs.

The VM reads 15 bytes, but the real verifier only hashes input[6:14].
The first four bytes form a fake LEET branch, while the remaining ignored
positions can be chosen freely.
"""

from __future__ import annotations

import itertools
import subprocess
from pathlib import Path

TARGET = 0x817ECE73
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789_"
CORE_PREFIX = b"r0r_"
FLAG_PREFIX = b"c0gs__"
FLAG_SUFFIX = b"!"


def rol32(value: int, bits: int) -> int:
    bits &= 31
    value &= 0xFFFFFFFF
    if bits == 0:
        return value
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def checksum(data: bytes) -> int:
    if len(data) != 8:
        raise ValueError("checksum input must be exactly 8 bytes")

    state = 0x1337
    for byte in data:
        state ^= byte
        state = rol32(state, 7)
        state = (state + 0x11) & 0xFFFFFFFF
    return state


def recover_core() -> bytes:
    """Recover the unique alphanumeric/underscore core beginning with r0r_."""
    state = 0x1337
    for byte in CORE_PREFIX:
        state = (rol32(state ^ byte, 7) + 0x11) & 0xFFFFFFFF

    matches: list[bytes] = []
    for suffix_tuple in itertools.product(ALPHABET, repeat=4):
        candidate_state = state
        for byte in suffix_tuple:
            candidate_state = (
                rol32(candidate_state ^ byte, 7) + 0x11
            ) & 0xFFFFFFFF

        if candidate_state == TARGET:
            matches.append(CORE_PREFIX + bytes(suffix_tuple))

    if matches != [b"r0r_m0d1"]:
        raise RuntimeError(f"unexpected core candidates: {matches!r}")
    return matches[0]


def build_flag() -> bytes:
    core = recover_core()
    inner = FLAG_PREFIX + core + FLAG_SUFFIX

    if len(inner) != 15:
        raise RuntimeError(f"inner key length is {len(inner)}, expected 15")
    if inner[:4] == b"LEET":
        raise RuntimeError("chosen filler triggers the fake LEET branch")
    if checksum(inner[6:14]) != TARGET:
        raise RuntimeError("constructed key does not satisfy the checksum")

    return b"TBCTF{" + inner + b"}"


def validate_with_vm(flag: bytes) -> bytes | None:
    vm_path = Path(__file__).with_name("vm")
    bytecode_path = Path(__file__).with_name("challenge.bin")
    if not (vm_path.exists() and bytecode_path.exists()):
        return None

    inner = flag[len(b"TBCTF{") : -1]
    proc = subprocess.run(
        [str(vm_path), str(bytecode_path)],
        input=inner,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    if not proc.stdout.endswith(b"C"):
        raise RuntimeError(
            f"VM rejected the key: stdout={proc.stdout!r}, stderr={proc.stderr!r}"
        )
    return proc.stdout


def main() -> None:
    flag = build_flag()
    vm_output = validate_with_vm(flag)

    print(f"core     : {flag[12:-2].decode()}")
    print(f"checksum : 0x{TARGET:08x}")
    if vm_output is not None:
        print(f"vm output: {vm_output!r}")
    print(f"<FLAG>{flag.decode()}</FLAG>")


if __name__ == "__main__":
    main()
