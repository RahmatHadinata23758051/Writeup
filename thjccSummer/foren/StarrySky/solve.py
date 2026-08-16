#!/usr/bin/env python3
"""
Solver Starry Sky.

Data disimpan pada LSB kanal Blue.
Ambil bit mulai indeks 0, lompat setiap 5 piksel, pack MSB-first,
lalu XOR setiap byte dengan 0x5a.
"""

from pathlib import Path
import argparse
from PIL import Image

XOR_KEY = 0x5A
START_BIT = 0
BIT_STRIDE = 5
EXPECTED_PREFIX = "THJCC{"


def bits_to_byte_msb(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | (bit & 1)
    return value


def extract_flag(image_path: Path) -> str:
    image = Image.open(image_path).convert("RGB")
    pixels = list(image.getdata())

    # Ambil LSB kanal Blue dari tiap piksel row-major.
    blue_lsb = [(b & 1) for (_r, _g, b) in pixels]

    chars = []
    pos = START_BIT

    while pos + 7 * BIT_STRIDE < len(blue_lsb):
        bits = [blue_lsb[pos + i * BIT_STRIDE] for i in range(8)]
        enc = bits_to_byte_msb(bits)
        dec = enc ^ XOR_KEY

        if dec < 32 or dec > 126:
            raise ValueError(f"Byte non-printable di posisi {pos}: 0x{dec:02x}")

        chars.append(chr(dec))

        if dec == ord("}"):
            break

        pos += 8 * BIT_STRIDE
    else:
        raise ValueError("Penutup flag tidak ditemukan")

    flag = "".join(chars)

    if not flag.startswith(EXPECTED_PREFIX) or not flag.endswith("}"):
        raise ValueError(f"Hasil tidak cocok format flag: {flag!r}")

    return flag


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Starry Sky flag")
    parser.add_argument("image", nargs="?", default="challenge.png", type=Path)
    args = parser.parse_args()

    flag = extract_flag(args.image)

    print("channel    : Blue")
    print("bit        : LSB / bit 0")
    print(f"start bit  : {START_BIT}")
    print(f"bit stride : {BIT_STRIDE}")
    print(f"xor key    : 0x{XOR_KEY:02x}")
    print(f"flag       : {flag}")
    print(f"\n<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
