#!/usr/bin/env python3
"""Recover the master shard from the APK's leftover native source and DB."""

import hashlib
import re
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "extracted" / "libshard.c"
DATABASE = ROOT / "extracted" / "assets" / "shard.db"


def main() -> None:
    native = SOURCE.read_text()
    fragments = {
        int(index): value
        for index, value in re.findall(r'sk_f(\d+)\s*=\s*"SKFRAG\d+:([^"]*)"', native)
    }
    order_text = re.search(r'sk_order\s*=\s*"seq=([0-9,]+)"', native).group(1)
    order = [int(item) for item in order_text.split(",")]
    payload = "".join(fragments[index] for index in order).encode()
    key = hashlib.sha256(payload).digest()

    with sqlite3.connect(DATABASE) as db:
        name, iv, tag, ciphertext, context = db.execute(
            "SELECT name, iv, tag, ciphertext, context "
            "FROM shard WHERE name = 'master_shard'"
        ).fetchone()

    plaintext = AESGCM(key).decrypt(
        bytes.fromhex(iv), bytes.fromhex(ciphertext + tag), context.encode()
    )
    print(plaintext.decode())


if __name__ == "__main__":
    main()
