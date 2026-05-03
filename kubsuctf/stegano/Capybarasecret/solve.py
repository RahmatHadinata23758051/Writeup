#!/usr/bin/env python3
from __future__ import annotations

import codecs
from pathlib import Path

from PIL import Image


IMAGE_PATH = Path(__file__).with_name("chall.jpg")
XP_COMMENT_TAG = 0x9C9C


def extract_xp_comment(path: Path) -> str:
    with Image.open(path) as img:
        exif = img.getexif()

    value = exif.get(XP_COMMENT_TAG)
    if value is None:
        raise RuntimeError("XP Comment tidak ditemukan di EXIF")

    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, tuple):
        raw = bytes(value)
    elif isinstance(value, str):
        return value.rstrip("\x00")
    else:
        raise RuntimeError(f"Tipe XP Comment tidak didukung: {type(value)!r}")

    return raw.decode("utf-16le").rstrip("\x00")


def main() -> None:
    encoded = extract_xp_comment(IMAGE_PATH)
    flag = codecs.decode(encoded, "rot_13")
    print(flag)


if __name__ == "__main__":
    main()
