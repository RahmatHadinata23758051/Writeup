#!/usr/bin/env python3
"""Recover the flag embedded in WrongKube+++.exe."""

from pathlib import Path
import struct
import zlib


def extract_validator(exe: bytes) -> bytes:
    # PyInstaller's 88-byte v2.1+ cookie is appended to the executable.
    magic, package_len, toc_offset, toc_len, _pyver = struct.unpack(
        "!8sIIII", exe[-88:-64]
    )
    assert magic == b"MEI\x0c\x0b\x0a\x0b\x0e"

    package_start = len(exe) - package_len
    toc = package_start + toc_offset
    toc_end = toc + toc_len

    while toc < toc_end:
        entry_len = struct.unpack("!I", exe[toc : toc + 4])[0]
        entry = exe[toc : toc + entry_len]
        offset, compressed_size, _raw_size = struct.unpack("!III", entry[4:16])
        compressed = entry[16]
        name = entry[18:].split(b"\0", 1)[0].decode()
        if name == r"build\wrongkube_validator.dll":
            data = exe[package_start + offset : package_start + offset + compressed_size]
            return zlib.decompress(data) if compressed else data
        toc += entry_len

    raise ValueError("validator DLL not found")


def decrypt_flag(dll: bytes) -> str:
    # DLL .rdata: raw offset 0x2aa00, RVA 0x2c000. The 48-byte ciphertext
    # is referenced by validate_cluster at RVA 0x2d5a0.
    ciphertext_offset = 0x2AA00 + (0x2D5A0 - 0x2C000)
    ciphertext = dll[ciphertext_offset : ciphertext_offset + 48]

    mask = 0xFFFFFFFF
    state = 0x34AF33DB
    lane = 0x49
    addend = 0x47502943
    seed = 0x47502932
    bias = 0x3C6EF35F
    plaintext = bytearray()

    for index in range(0, 48, 2):
        first = (state * 0x19660D + bias) & mask
        plaintext.append(ciphertext[index] ^ ((lane - 0x49) ^ (first >> 16) ^ first) & 0xFF)

        second = (state * 0x17385CA9) & mask
        state = (index + ((index | 1) << 4) + 1 + seed + second) & mask
        second = (second + addend) & mask
        plaintext.append(ciphertext[index + 1] ^ (lane ^ (second >> 16) ^ second) & 0xFF)

        lane = (lane + 0x92) & mask
        addend = (addend + 0x35F8DDC) & mask
        seed = (seed + 0x35F8DBA) & mask
        bias = (bias + 0x22) & mask

    return plaintext.decode()


if __name__ == "__main__":
    exe = Path(__file__).with_name("WrongKube+++.exe").read_bytes()
    print(decrypt_flag(extract_validator(exe)))
