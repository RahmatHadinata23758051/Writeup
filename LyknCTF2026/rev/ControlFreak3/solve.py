#!/usr/bin/env python3
from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
IMAGE_BASE = 0x400000
GOLDEN = 0x9E3779B97F4A7C15
SPLITMIX_A = 0xBF58476D1CE4E5B9
SPLITMIX_B = 0x94D049BB133111EB
BASE_KEY = 0xD6E8FEB86659FD93
INITIAL_VM_KEY = 0x8F4D2C6B1A097835


def u32(value: int) -> int:
    return value & MASK32


def rol32(value: int, count: int) -> int:
    value &= MASK32
    count &= 31
    return ((value << count) | (value >> (32 - count))) & MASK32


def rol64(value: int, count: int) -> int:
    value &= MASK64
    count &= 63
    return ((value << count) | (value >> (64 - count))) & MASK64


def read_u16(data: bytes, address: int) -> int:
    return struct.unpack_from("<H", data, address - IMAGE_BASE)[0]


def read_u64(data: bytes, address: int) -> int:
    return struct.unpack_from("<Q", data, address - IMAGE_BASE)[0]


def decrypt_blocks(data: bytes) -> list[bytes]:
    blob = data[0x3060:0x3060 + 0x3B2]
    blocks: list[bytes] = []

    vm_key = INITIAL_VM_KEY
    rolling_golden = GOLDEN
    rolling_base = BASE_KEY

    for block_index in range(5):
        record = 0x403420 + block_index * 0x20
        offset = read_u16(data, record)
        length = read_u16(data, record + 2)
        key_a = read_u64(data, record + 8)
        key_b = read_u64(data, record + 16)
        chain_target = read_u64(data, record + 24)

        state = rol64(
            rolling_base + vm_key + key_b,
            11 * block_index + 1,
        ) ^ key_a

        plaintext = bytearray()
        for index in range(length):
            state = (state + GOLDEN + index) & MASK64

            mixed = state
            mixed = ((mixed ^ (mixed >> 30)) * SPLITMIX_A) & MASK64
            mixed = ((mixed ^ (mixed >> 27)) * SPLITMIX_B) & MASK64
            mixed ^= mixed >> 31

            shift = (index & 7) * 8
            mask_byte = (
                (vm_key >> shift)
                + 17 * block_index
                + 29 * index
            ) & 0xFF

            decoded = mask_byte ^ blob[offset + index] ^ ((mixed >> shift) & 0xFF)
            plaintext.append(decoded)

        blocks.append(bytes(plaintext))

        vm_key = rol64(
            vm_key ^ rolling_golden ^ chain_target,
            7 * block_index + 21,
        )
        rolling_golden = (rolling_golden + GOLDEN) & MASK64
        rolling_base = (rolling_base + BASE_KEY) & MASK64

    return blocks


def opcode(raw: int, dispatch_table: bytes) -> int:
    return (((37 * raw + 0x5A) & 0xFF) ^ dispatch_table[raw])


def parse_constraints(blocks: list[bytes], dispatch_table: bytes):
    one_constraints: list[tuple[int, int, int]] = []
    two_constraints: list[tuple[int, int, int, int]] = []
    maximum_index = -1

    for block in blocks:
        ip = 0
        while ip < len(block):
            op = opcode(block[ip], dispatch_table)

            if op in (0, 1):
                break
            if op == 2:
                ip += 9
            elif op == 3:
                index = block[ip + 1]
                immediate, expected = struct.unpack_from("<II", block, ip + 2)
                one_constraints.append((index, immediate, expected))
                maximum_index = max(maximum_index, index)
                ip += 10
            elif op == 4:
                index_a = block[ip + 1]
                index_b = block[ip + 2]
                immediate, expected = struct.unpack_from("<II", block, ip + 3)
                two_constraints.append((index_a, index_b, immediate, expected))
                maximum_index = max(maximum_index, index_a, index_b)
                ip += 11
            elif op == 5:
                maximum_index = max(maximum_index, *block[ip + 1:ip + 4])
                ip += 12
            elif op == 6:
                ip += 13
            elif op == 7:
                ip += 5
            else:
                raise ValueError(f"Invalid VM opcode {op} at offset {ip:#x}")

    return one_constraints, two_constraints, maximum_index + 1


def check_one(index: int, immediate: int, expected: int, char: int) -> int:
    edx = index
    r11 = u32(expected + 0x9E3779B9)
    r8 = u32(index + expected)

    edx = u32((edx << 8) | char)
    edx ^= r11
    r11 = u32(char << ((index & 3) + 1))
    edx = u32(edx * 0x045D9F3B)

    rotate_a = ((expected >> 27) & 0xF) + 5
    rotate_b = ((expected ^ char) & 7) + 3

    edx = u32(edx + r11)
    edx = rol32(edx, rotate_a)
    edx ^= edx >> 11
    edx = u32(edx * 0x27D4EB2D)

    r8 = u32(r8 + char * 0x165667B1)
    result = rol32(r8, rotate_b) ^ immediate ^ edx
    return u32(result)


def check_two(
    index_a: int,
    index_b: int,
    immediate: int,
    expected: int,
    char_a: int,
    char_b: int,
) -> int:
    r11 = u32(index_a * 0x9E3779B1)
    r11 ^= u32(index_b * 0x85EBCA77)
    r11 ^= expected

    r11 = u32((char_a + 0x101) * (expected | 1) + r11)
    r11 ^= u32(char_b * 0xC2B2AE3D - 0x6576DEB3)

    selector = u32(index_a * 2) ^ u32(expected ^ index_b)
    r11 = rol32(r11, (selector & 0xF) + 5)

    mixed = u32((char_a ^ char_b) * 0x27D4EB2D)
    mixed = u32(r11 + mixed - 0x10952609)

    second = u32((char_b << 8) + index_b * 0x1D + index_a * 17 + char_a)
    second = u32(second * 0x165667B1)
    second = rol32(second, ((expected >> 5) & 0xF) + 3)
    second ^= mixed

    result = u32(char_a * char_b + 0x9E37)
    result = u32(result * ((expected >> 16) | 1) + second)
    result ^= result >> 13
    result = u32(result * 0x85EBCA6B)

    return u32(immediate ^ result ^ (result >> 16))


def solve(binary_path: Path) -> str:
    data = binary_path.read_bytes()
    dispatch_table = data[0x34C0:0x35C0]
    blocks = decrypt_blocks(data)
    one_constraints, two_constraints, flag_length = parse_constraints(
        blocks,
        dispatch_table,
    )

    possibilities: dict[int, set[int]] = {}

    for index, immediate, expected in one_constraints:
        solutions = {
            value
            for value in range(256)
            if check_one(index, immediate, expected, value) == 0
        }
        possibilities[index] = possibilities.get(index, set(range(256))) & solutions

    changed = True
    while changed:
        changed = False
        for index_a, index_b, immediate, expected in two_constraints:
            values_a = possibilities.get(index_a, set(range(256)))
            values_b = possibilities.get(index_b, set(range(256)))

            if len(values_a) == 256 and len(values_b) == 256:
                continue

            valid_pairs = {
                (value_a, value_b)
                for value_a in values_a
                for value_b in values_b
                if check_two(
                    index_a,
                    index_b,
                    immediate,
                    expected,
                    value_a,
                    value_b,
                ) == 0
            }

            next_a = {value_a for value_a, _ in valid_pairs}
            next_b = {value_b for _, value_b in valid_pairs}

            if possibilities.get(index_a) != next_a:
                possibilities[index_a] = next_a
                changed = True
            if possibilities.get(index_b) != next_b:
                possibilities[index_b] = next_b
                changed = True

    result = bytearray()
    for index in range(flag_length):
        printable = sorted(
            value
            for value in possibilities.get(index, set())
            if 0x20 <= value <= 0x7E
        )
        if len(printable) != 1:
            raise RuntimeError(
                f"Character {index} is not uniquely solved: {printable}"
            )
        result.append(printable[0])

    return result.decode("ascii")


def main() -> int:
    binary_path = Path(sys.argv[1] if len(sys.argv) > 1 else "chall-4")
    if not binary_path.is_file():
        print(f"[-] Binary not found: {binary_path}", file=sys.stderr)
        return 1

    flag = solve(binary_path)
    print(f"[+] Flag: {flag}")

    if os.access(binary_path, os.X_OK):
        completed = subprocess.run(
            [str(binary_path.resolve()), flag],
            text=True,
            capture_output=True,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip()
        print(f"[+] Checker: {output}")
        if "Correct!" not in output:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
