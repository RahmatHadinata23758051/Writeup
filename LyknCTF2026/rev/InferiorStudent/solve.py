#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

MASK32 = 0xFFFFFFFF
RC4_KEY = b"L0i_Y3u_Kh0_N0i"
USERNAME_MASK = bytes.fromhex("add993f24ca678dc1d369f61e40236")
CIPHERTEXT_RVA = 0x6280
CIPHERTEXT_SIZE = 0x60
EXPECTED_CHECK_PREFIX = bytes.fromhex("7db51c69a8dd7926")


def rol32(value: int, count: int) -> int:
    value &= MASK32
    return ((value << count) | (value >> (32 - count))) & MASK32


def rc4_ksa(key: bytes) -> list[int]:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return state


def recover_username(state: list[int]) -> bytes:
    selected = (0x42, 0x3D, 0x38, 0x33, 0x2E, 0x29, 0x24, 0x1F)
    packed = 0
    for index in selected:
        packed = (packed << 8) | state[index]

    username = bytearray(15)
    packed ^= int.from_bytes(USERNAME_MASK[:8], "little")
    username[:8] = packed.to_bytes(8, "little")

    for position in range(8, 15):
        table_index = 0x47 + 5 * (position - 8)
        username[position] = USERNAME_MASK[position] ^ state[table_index]

    return bytes(username)


def generate_license(username: bytes, state: list[int], anti_debug: int = 0) -> str:
    r8 = ((anti_debug & 0xFF) * 0x01010101) ^ 0x4C594B4E
    r9 = 0xAE054FB9
    r11 = 0x43544632
    accumulator = 0xA5A5F00D

    for offset in (0, 7, 14):
        for character in username:
            table_value = state[(character + offset) & 0xFF]

            mixed_r8 = rol32(r8 ^ table_value, 5)
            mixed_r11 = rol32((table_value + r11) & MASK32, 11)
            r8 = (mixed_r8 + r11) & MASK32

            mixed_r9 = rol32(
                ((table_value * 0x9E3779B1) & MASK32) ^ r9,
                17,
            )
            r11 = mixed_r11 ^ r9
            r9 = (mixed_r9 + accumulator) & MASK32

            mixed_accumulator = rol32(
                (state[r8 & 0xFF] + accumulator) & MASK32,
                3,
            )
            accumulator = mixed_accumulator ^ r8

    for _ in range(4):
        r8 = (r8 + accumulator) & MASK32
        r11 ^= rol32(r8, 7)
        r9 = (r9 + r11) & MASK32
        accumulator ^= rol32(r9, 13)

    groups = [
        (r8 >> 16) & 0xFFFF,
        (r8 ^ r11) & 0xFFFF,
        (r11 >> 16) & 0xFFFF,
        (r9 ^ accumulator) & 0xFFFF,
    ]
    checksum = (
        groups[0]
        + groups[2]
        + groups[1]
        + groups[3]
    ) ^ ((r9 >> 16) & 0xFFFF)
    groups.append(checksum & 0xFFFF)

    return "-".join(f"{group:04X}" for group in groups)


def parse_pe_sections(data: bytes) -> list[dict[str, int | str]]:
    if data[:2] != b"MZ":
        raise ValueError("input is not a PE file")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")

    number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_header_size

    sections: list[dict[str, int | str]] = []
    for index in range(number_of_sections):
        offset = section_table + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
            }
        )
    return sections


def section_by_name(sections: list[dict[str, int | str]], name: str) -> dict[str, int | str]:
    for section in sections:
        if section["name"] == name:
            return section
    raise ValueError(f"section {name!r} not found")


def rva_to_offset(sections: list[dict[str, int | str]], rva: int) -> int:
    for section in sections:
        start = int(section["virtual_address"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= rva < start + span:
            return int(section["raw_offset"]) + (rva - start)
    raise ValueError(f"RVA 0x{rva:x} is not mapped by a section")


def loaded_section_bytes(data: bytes, section: dict[str, int | str]) -> bytes:
    virtual_size = int(section["virtual_size"])
    raw_size = int(section["raw_size"])
    raw_offset = int(section["raw_offset"])
    raw = data[raw_offset : raw_offset + min(raw_size, virtual_size)]
    return raw.ljust(virtual_size, b"\0")


def decrypt_flag(executable: bytes, username: bytes, license_key: str, anti_debug: int = 0) -> bytes:
    sections = parse_pe_sections(executable)
    text = loaded_section_bytes(executable, section_by_name(sections, ".text"))
    text_digest = hashlib.sha256(text).digest()

    master = hashlib.sha256(
        username
        + b"\x1f"
        + license_key.encode("ascii")
        + b"\x1f"
        + text_digest
        + bytes([anti_debug & 0xFF])
    ).digest()

    keystream = b"".join(
        hashlib.sha256(master + struct.pack("<I", counter)).digest()
        for counter in range(3)
    )

    ciphertext_offset = rva_to_offset(sections, CIPHERTEXT_RVA)
    ciphertext = executable[
        ciphertext_offset : ciphertext_offset + CIPHERTEXT_SIZE
    ]
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, keystream))
    flag = plaintext.split(b"\0", 1)[0]

    check = hashlib.sha256(b"LYKN2026" + flag).digest()
    if check[:8] != EXPECTED_CHECK_PREFIX:
        raise ValueError("decryption checksum did not match")

    return flag


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "KeygenMe.exe")
    executable = path.read_bytes()

    state = rc4_ksa(RC4_KEY)
    username = recover_username(state)
    license_key = generate_license(username, state, anti_debug=0)
    flag = decrypt_flag(executable, username, license_key, anti_debug=0)

    print(f"[+] Username : {username.decode('ascii')}")
    print(f"[+] License  : {license_key}")
    print(f"[+] Flag     : {flag.decode('ascii')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
