#!/usr/bin/env python3
from __future__ import annotations

import struct
import subprocess
from pathlib import Path

MASK32 = 0xFFFFFFFF
INITIAL_CHAIN = 0x0F1E2D3C4B5A6978
DATA_VA = 0x402000
DATA_OFFSET = 0x2000


def read_va(binary: bytes, va: int, size: int) -> bytes:
    """Read bytes from this binary's fixed .data mapping."""
    offset = DATA_OFFSET + (va - DATA_VA)
    return binary[offset : offset + size]


def rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & MASK32


def substitute_u32(value: int, table: bytes) -> int:
    return (
        table[value & 0xFF]
        | (table[(value >> 8) & 0xFF] << 8)
        | (table[(value >> 16) & 0xFF] << 16)
        | (table[(value >> 24) & 0xFF] << 24)
    )


def recover_flag(checker_path: Path) -> bytes:
    binary = checker_path.read_bytes()

    encrypted_constants = read_va(binary, 0x402020, 6 * 4)
    constants = [
        value ^ 0xA5A5A5A5
        for value in struct.unpack("<6I", encrypted_constants)
    ]

    sboxes = [
        read_va(binary, 0x402080 + index * 0x100, 0x100)
        for index in range(4)
    ]
    target = read_va(binary, 0x402480, 0x88)

    def round_function(left: int, round_index: int) -> int:
        mixed = (
            left
            ^ constants[round_index % 6]
            ^ (((round_index + 1) * 0x9E3779B9) & MASK32)
        ) & MASK32

        table = sboxes[(3 * round_index + 1) & 3]
        rotation = ((7 * round_index + 3) % 31) + 1
        return rol32(substitute_u32(mixed, table), rotation)

    def decrypt_block(cipher_block: int) -> int:
        left = cipher_block & MASK32
        right = (cipher_block >> 32) & MASK32

        for round_index in range(14, -1, -1):
            old_left = right
            old_right = left ^ round_function(old_left, round_index)
            left = old_left
            right = old_right & MASK32

        return left | (right << 32)

    chain = INITIAL_CHAIN
    plaintext = bytearray()

    for offset in range(0, len(target), 8):
        cipher_block = int.from_bytes(target[offset : offset + 8], "big")
        pre_feistel = decrypt_block(cipher_block)
        plaintext.extend((pre_feistel ^ chain).to_bytes(8, "big"))
        chain = cipher_block

    return bytes(plaintext).rstrip(b"\x00")


def main() -> None:
    checker_path = Path(__file__).with_name("flag_checkers")
    if not checker_path.is_file():
        raise SystemExit(f"checker tidak ditemukan: {checker_path}")

    flag = recover_flag(checker_path)

    result = subprocess.run(
        [str(checker_path)],
        input=flag,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    output = result.stdout.decode(errors="replace").strip()

    if output != "Correct":
        raise SystemExit(
            f"hasil rekonstruksi gagal divalidasi: {output or result.stderr.decode(errors='replace')}"
        )

    print(flag.decode())


if __name__ == "__main__":
    main()
