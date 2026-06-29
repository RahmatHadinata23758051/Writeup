#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise SystemExit("Dependency missing: pip install cryptography") from exc

BASE_DIR = Path(__file__).resolve().parent
FLASH_PATH = BASE_DIR / "flash_dump.bin"
EFUSE_PATH = BASE_DIR / "efuse_sum.json"

# Recovered from the stripped provisioning firmware.
HMAC_KEY = bytes.fromhex("855780fc45bce8878d68f0040630cdbb")
PBKDF2_ROUNDS = 4096
PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_SIZE = 0x1000


def load_efuse_summary(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="strict")
    json_start = text.find("{")
    if json_start < 0:
        raise ValueError("JSON object not found in efuse summary")
    return json.loads(text[json_start:])


def parse_hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value.replace(" ", ""))


def derive_xts_key(summary: dict) -> tuple[bytes, bytes, bytes, bytes]:
    user_block = parse_hex_bytes(summary["BLOCK_USR_DATA"]["value"])
    user_data = user_block[:24]

    mac_text = summary["MAC"]["value"].split()[0]
    mac = bytes.fromhex(mac_text.replace(":", ""))

    digest = hmac.new(HMAC_KEY, user_data, hashlib.sha256).digest()
    xts_key = hashlib.pbkdf2_hmac(
        "sha256",
        digest,
        mac,
        PBKDF2_ROUNDS,
        dklen=32,
    )
    return user_data, mac, digest, xts_key


def find_partition(flash: bytes, label: str) -> tuple[int, int]:
    table = flash[
        PARTITION_TABLE_OFFSET : PARTITION_TABLE_OFFSET + PARTITION_TABLE_SIZE
    ]

    for offset in range(0, len(table), 32):
        entry = table[offset : offset + 32]
        if len(entry) < 32:
            break
        if entry[:2] == b"\xeb\xeb":
            break
        if entry[:2] != b"\xaa\x50":
            continue

        part_offset, part_size = struct.unpack_from("<II", entry, 4)
        part_label = entry[12:28].split(b"\x00", 1)[0].decode(
            "ascii", errors="replace"
        )
        if part_label == label:
            return part_offset, part_size

    raise ValueError(f"Partition {label!r} not found")


def decrypt_esp32s3_xts(ciphertext: bytes, key: bytes, address: int) -> bytes:
    if address % 16 != 0:
        raise ValueError("Flash address must be 16-byte aligned")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")

    # ESP32-S3 flash encryption operates on 128-byte units. The hardware uses
    # the aligned physical flash address as a little-endian tweak and reverses
    # the complete 128-byte unit around the standard AES-XTS operation.
    output = bytearray()
    for block_offset in range(0, len(ciphertext), 0x80):
        block = ciphertext[block_offset : block_offset + 0x80]
        block_address = address + block_offset
        tweak = struct.pack("<I", block_address & ~0x7F) + b"\x00" * 12

        decryptor = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
        plaintext_reversed = decryptor.update(block[::-1]) + decryptor.finalize()
        output.extend(plaintext_reversed[::-1])

    return bytes(output)


def main() -> int:
    if not FLASH_PATH.is_file() or not EFUSE_PATH.is_file():
        print("[-] flash_dump.bin or efuse_sum.json is missing", file=sys.stderr)
        return 1

    flash = FLASH_PATH.read_bytes()
    summary = load_efuse_summary(EFUSE_PATH)
    user_data, mac, digest, xts_key = derive_xts_key(summary)

    flag_offset, flag_size = find_partition(flash, "flagdata")
    encrypted_flag = flash[flag_offset : flag_offset + flag_size]
    if len(encrypted_flag) != flag_size:
        print("[-] flagdata partition is truncated", file=sys.stderr)
        return 1

    plaintext = decrypt_esp32s3_xts(encrypted_flag, xts_key, flag_offset)
    match = re.search(rb"V1T\{[^}\r\n]+\}", plaintext)
    if not match:
        print("[-] flag pattern not found", file=sys.stderr)
        return 1

    flag = match.group().decode("ascii")
    print(f"[+] BLOCK_USR_DATA[:24]: {user_data.hex()}")
    print(f"[+] MAC salt:              {mac.hex()}")
    print(f"[+] HMAC digest:           {digest.hex()}")
    print(f"[+] AES-XTS key:           {xts_key.hex()}")
    print(f"[+] flagdata:              offset={flag_offset:#x}, size={flag_size:#x}")
    print(f"[+] flag:                  {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
