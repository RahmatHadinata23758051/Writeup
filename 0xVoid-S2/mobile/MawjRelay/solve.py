#!/usr/bin/env python3
"""Decode the hidden push route from assets/push_routes.bin."""

import hashlib
import json
import struct
import zlib
from pathlib import Path


ACTION = "com.void.echo.PUSH"
LABEL = "EchoPush"


def main() -> None:
    blob = Path(__file__).with_name("extracted").joinpath(
        "assets", "push_routes.bin"
    ).read_bytes()
    assert blob[:6] == b"VPUSH1"

    payload_len = blob[8]
    encrypted = blob[9 : 9 + payload_len]
    stored_crc = blob[9 + payload_len : 13 + payload_len]

    key = hashlib.sha256(f"{ACTION}:{LABEL}".encode()).digest()
    plaintext = bytes(value ^ key[index % len(key)] for index, value in enumerate(encrypted))

    assert struct.unpack(">I", stored_crc)[0] == zlib.crc32(plaintext)
    record = json.loads(plaintext)
    print(record["flag"])


if __name__ == "__main__":
    main()
