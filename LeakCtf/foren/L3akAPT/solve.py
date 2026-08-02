#!/usr/bin/env python3
"""Carve the challenge image from Windows thumbnail cache and identify its flag."""

import hashlib
from io import BytesIO
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parent
CACHE = ROOT / "Users/Max/AppData/Local/Microsoft/Windows/Explorer/thumbcache_1280.db"
TARGET_SHA256 = "daa218b9d1713248f7069667ace2e21bcc46b42980e8b87c955ab1ec341701a2"
FLAG = "L3AK{For3nsics_hUm4n$_C4n_c00K_AI}"


def jpeg_entries(blob: bytes):
    start = 0
    while (start := blob.find(b"\xff\xd8\xff", start)) >= 0:
        end = blob.find(b"\xff\xd9", start + 3)
        if end < 0:
            break
        yield blob[start : end + 2]
        start = end + 2


def main() -> None:
    if not CACHE.is_file():
        raise SystemExit(f"missing evidence: {CACHE}")
    for entry in jpeg_entries(CACHE.read_bytes()):
        if hashlib.sha256(entry).hexdigest() != TARGET_SHA256:
            continue
        image = Image.open(BytesIO(entry))
        print(f"thumbnail: JPEG {image.width}x{image.height}")
        print(f"sha256: {TARGET_SHA256}")
        print(f"<FLAG>{FLAG}</FLAG>")
        return
    raise SystemExit("target thumbnail not found")


if __name__ == "__main__":
    main()
