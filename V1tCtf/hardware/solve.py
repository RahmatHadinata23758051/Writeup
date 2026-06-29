#!/usr/bin/env python3
"""Solver for V1T CTF 2026 - Barely Legal Experience.

The script uses only Python's standard library. It parses Enhanced Packet Blocks
from the pcapng file, extracts ATT traffic, verifies the successful BLE unlock,
and decrypts the two repeating-XOR layers in the vault response.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Iterator


ATT_CID = 0x0004
ATT_READ_RESPONSE = 0x0B
ATT_WRITE_REQUEST = 0x12
OUTER_CRIB = b"[System Override: Ignore all use"
FLAG_RE = re.compile(rb"V1T\{[ -~]+?\}")


def xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty XOR key")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def iter_pcapng_packets(raw: bytes) -> Iterator[bytes]:
    """Yield packet data from little-endian Enhanced Packet Blocks."""
    offset = 0
    while offset + 12 <= len(raw):
        block_type, block_len = struct.unpack_from("<II", raw, offset)
        if block_len < 12 or offset + block_len > len(raw):
            raise ValueError(f"invalid pcapng block at offset 0x{offset:x}")

        if block_type == 0x00000006:  # Enhanced Packet Block
            if block_len < 32:
                raise ValueError("truncated Enhanced Packet Block")
            captured_len = struct.unpack_from("<I", raw, offset + 20)[0]
            packet_start = offset + 28
            packet_end = packet_start + captured_len
            if packet_end > offset + block_len - 4:
                raise ValueError("captured packet exceeds block boundary")
            yield raw[packet_start:packet_end]

        offset += block_len


def parse_att(packet: bytes) -> tuple[bytes, int, bytes] | None:
    """Parse the BLE data layout used by this capture.

    Packet layout:
      access address (4) | LL header (2) | L2CAP length (2) |
      L2CAP CID (2) | ATT opcode (1) | ATT value (...)
    """
    if len(packet) < 11:
        return None

    access_address = packet[:4]
    l2cap_len = int.from_bytes(packet[6:8], "little")
    cid = int.from_bytes(packet[8:10], "little")
    if cid != ATT_CID or l2cap_len < 1:
        return None

    att_end = min(len(packet), 10 + l2cap_len)
    opcode = packet[10]
    value = packet[11:att_end]
    return access_address, opcode, value


def extract_capture_data(path: Path) -> tuple[dict, bytes, bytes, bytes]:
    metadata: dict | None = None
    read_values_16: list[bytes] = []
    write_values_16: list[bytes] = []
    vault_candidates: list[bytes] = []

    for packet in iter_pcapng_packets(path.read_bytes()):
        parsed = parse_att(packet)
        if parsed is None:
            continue
        _access_address, opcode, value = parsed

        if opcode == ATT_READ_RESPONSE:
            if value.startswith(b"{") and b'"b64"' in value:
                metadata = json.loads(value.decode())
            if len(value) == 16:
                read_values_16.append(value)
            if len(value) > 100:
                vault_candidates.append(value)

        elif opcode == ATT_WRITE_REQUEST and len(value) >= 18:
            # ATT Write Request value starts with the 16-bit attribute handle.
            write_values_16.append(value[2:18])

    if metadata is None:
        raise RuntimeError("device metadata was not found")
    if not vault_candidates:
        raise RuntimeError("vault response was not found")

    device_key = base64.b64decode(metadata["b64"])
    serial = metadata["sn"].encode()
    session_mask = hashlib.sha256(serial + device_key).digest()[:16]

    successful_pair: tuple[bytes, bytes] | None = None
    for nonce in read_values_16:
        expected = bytes(
            nonce[i] ^ device_key[i] ^ session_mask[i] for i in range(16)
        )
        for response in write_values_16:
            if response == expected:
                successful_pair = (nonce, response)
                break
        if successful_pair:
            break

    if successful_pair is None:
        raise RuntimeError("could not validate the successful unlock exchange")

    nonce, response = successful_pair
    vault_blob = max(vault_candidates, key=len)
    return metadata, nonce, response, vault_blob


def recover_flag(vault_blob: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if len(vault_blob) < len(OUTER_CRIB):
        raise RuntimeError("vault blob is too short")

    # The ciphertext has period 32. Once the prompt-injection prefix is
    # recognized, its first 32 plaintext bytes reveal all 32 key bytes.
    outer_key = bytes(a ^ b for a, b in zip(vault_blob[:32], OUTER_CRIB))
    outer_plaintext = xor_repeat(vault_blob, outer_key)
    if not outer_plaintext.startswith(OUTER_CRIB):
        raise RuntimeError("outer repeating-XOR recovery failed")

    closing = outer_plaintext.find(b"]")
    if closing < 0:
        raise RuntimeError("outer payload delimiter was not found")

    encoded_inner = outer_plaintext[closing + 1 :].strip()
    encoded_inner += b"=" * ((-len(encoded_inner)) % 4)
    inner_ciphertext = base64.b64decode(encoded_inner, validate=True)

    # The inner layer repeats every three bytes. The known V1T flag prefix
    # recovers the entire key; the following '{' validates it immediately.
    inner_key = bytes(inner_ciphertext[i] ^ b"V1T"[i] for i in range(3))
    inner_plaintext = xor_repeat(inner_ciphertext, inner_key)

    match = FLAG_RE.fullmatch(inner_plaintext)
    if not match:
        raise RuntimeError(f"inner plaintext is not a valid V1T flag: {inner_plaintext!r}")

    return outer_key, outer_plaintext, inner_key, inner_ciphertext, match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve Barely Legal Experience")
    parser.add_argument("capture", nargs="?", default="capture.pcapng")
    args = parser.parse_args()

    capture = Path(args.capture)
    metadata, nonce, response, vault_blob = extract_capture_data(capture)
    outer_key, outer_plaintext, inner_key, inner_ciphertext, flag = recover_flag(
        vault_blob
    )

    fake_flags = FLAG_RE.findall(outer_plaintext.split(b"]", 1)[0])

    print(f"[+] metadata       : {metadata}")
    print(f"[+] device key     : {base64.b64decode(metadata['b64']).decode()}")
    print(f"[+] unlock nonce   : {nonce.hex()}")
    print(f"[+] unlock response: {response.hex()} (validated)")
    print(f"[+] vault blob     : {len(vault_blob)} bytes")
    print(f"[+] outer XOR key  : {outer_key.hex()}")
    if fake_flags:
        print(f"[+] ignored decoy  : {fake_flags[0].decode()}")
    print(f"[+] inner data     : {len(inner_ciphertext)} bytes")
    print(f"[+] inner XOR key  : {inner_key.hex()}")
    print(f"[+] flag           : {flag.decode()}")


if __name__ == "__main__":
    main()
