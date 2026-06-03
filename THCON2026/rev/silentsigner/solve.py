#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path


MASK64 = (1 << 64) - 1
TABLE_OFF = 0x48940
MULT_OFF = 0x48900
SEED_A_OFF = 0x48978
SEED_B_OFF = 0x48980
SEED_C_OFF = 0x48988


def rol64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def ror64(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (64 - shift))) & MASK64


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def load_qwords(data: bytes, offset: int, count: int) -> list[int]:
    return list(struct.unpack_from(f"<{count}Q", data, offset))


def recover_flag(binary: Path) -> str:
    data = binary.read_bytes()

    k_table = load_qwords(data, TABLE_OFF, 6)
    multipliers = load_qwords(data, MULT_OFF, 6)

    seed_a = u64(data, SEED_A_OFF)
    seed_b = u64(data, SEED_B_OFF)
    seed_c = u64(data, SEED_C_OFF)

    # Rebuild the XOR key used to hide the embedded eBPF object.
    _blob_key = ((((seed_a ^ seed_c) - (seed_c ^ seed_b)) & MASK64) ^ 0x4141414141414141)

    # These six target values are the comparison constants inside the eBPF
    # program attached to fw_commit. Reaching them in sequence reconstructs
    # the accepted 48-byte token.
    targets = [
        0x66185FCB3AF43C42,
        0xFB9181FC9D741AC9,
        0xF6F76D94D5F19C7C,
        0x9623BE0FA7985447,
        0xC801D5B2EE724650,
        0x9FAAF86A914846EE,
    ]

    acc = 0
    token = bytearray()

    for i in range(6):
        mixed = (ror64(targets[i], 13) * pow(multipliers[i], -1, 1 << 64)) & MASK64
        lane = acc ^ mixed
        block = k_table[i] ^ ror64(lane, 7)
        token.extend(block.to_bytes(8, "little"))
        acc ^= targets[i]

    flag = token.decode("ascii")

    # Keep a small sanity check so the solver fails loudly if offsets change.
    if acc != 0xAAF62074AAD3EE0E:
        raise ValueError("unexpected accumulator state while reconstructing token")
    if not flag.startswith("THC{") or not flag.endswith("}"):
        raise ValueError("recovered token does not look like the expected flag format")

    return flag


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sst-fwsign")
    print(recover_flag(binary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
