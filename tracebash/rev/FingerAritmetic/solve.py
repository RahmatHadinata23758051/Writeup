#!/usr/bin/env python3
"""Reconstruct the 32-byte key for TBCTF Finger Arithmetic."""

from __future__ import annotations

import subprocess
from pathlib import Path

MASK32 = 0xFFFFFFFF

# Integer values recovered from the eight embedded hand-sign PNG targets.
TARGETS = (
    0x65657598,
    0x100F0EDE,
    0x25662659,
    0x41394806,
    0xA09D7C39,
    0x95F9120A,
    0x9E7E2255,
    0xE35F1564,
)


def recover_key() -> bytes:
    t0, t1, t2, t3, t4, t5, t6, t7 = TARGETS

    chunks = (
        (t0 - 0x11223344) & MASK32,
        t1 ^ t0,
        (t2 + t1) & MASK32,
        t3 ^ t2,
        (t4 - t3) & MASK32,
        t5 ^ t4,
        (t6 + t5) & MASK32,
        t7 ^ t6,
    )

    key = b"".join(value.to_bytes(4, "little") for value in chunks)
    if len(key) != 32:
        raise RuntimeError(f"unexpected key length: {len(key)}")
    return key


def validate_locally(binary: Path, key: bytes) -> str:
    proc = subprocess.run(
        [str(binary)],
        input=key + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = proc.stdout.decode("utf-8", errors="replace")
    if "Correct!" not in output:
        raise RuntimeError(f"binary rejected recovered key:\n{output}")
    return output


def main() -> None:
    key = recover_key()
    flag = key.decode("ascii")
    print(flag)

    binary = Path(__file__).with_name("chall(2)")
    if binary.is_file():
        validate_locally(binary, key)
        print("[+] Local validation passed")


if __name__ == "__main__":
    main()
