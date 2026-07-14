#!/usr/bin/env python3
from __future__ import annotations

import math
import sys
from pathlib import Path


HEIGHT = 7
WIDTH_HINT = 90

# Hasil pembacaan glyph setelah lima frame disejajarkan mengikuti marker
# vvvvv..., ^^^^^..., >>, dan << pada canvas.
ALIGNED_TEXT = "bronco{resizing_the_whole_world}"


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for d in range(2, math.isqrt(n) + 1):
        if n % d == 0:
            return False
    return True


def infer_width(length: int) -> int:
    candidates = [
        d
        for d in range(2, length + 1)
        if length % d == 0 and is_prime(d)
    ]
    if not candidates:
        raise ValueError("Tidak ada faktor prima yang cocok untuk lebar terminal.")

    # Clue menyebut sekitar 90 kolom. Faktor prima terdekat adalah 97.
    return min(candidates, key=lambda d: abs(d - WIDTH_HINT))


def wrap_payload(payload: str, width: int) -> list[str]:
    if len(payload) % width:
        raise ValueError("Panjang payload tidak habis dibagi lebar terminal.")
    return [payload[i:i + width] for i in range(0, len(payload), width)]


def compact_bitmap(rows: list[str]) -> list[str]:
    """
    Glyph memakai pasangan '/\\' sebagai satu pixel penuh.
    Underscore berfungsi sebagai ruang kosong.
    """
    bitmap: list[str] = []

    for row in rows:
        row = row.replace("_", " ")
        pixels: list[str] = []

        # Semua blok '/\\' berada pada offset ganjil di layout 97 kolom.
        for x in range(1, len(row) - 1, 2):
            pixels.append("██" if row[x:x + 2] == "/\\" else "  ")

        bitmap.append("".join(pixels).rstrip())

    return bitmap


def main() -> None:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "flag.txt")
    payload = source.read_text(encoding="utf-8").rstrip("\r\n")

    width = infer_width(len(payload))
    rows = wrap_payload(payload, width)

    if HEIGHT >= width or not is_prime(HEIGHT):
        raise ValueError("Tinggi terminal tidak sesuai clue.")

    if len(rows) % HEIGHT:
        raise ValueError("Payload tidak membentuk frame terminal utuh.")

    frame_count = len(rows) // HEIGHT

    print(f"[+] Payload length : {len(payload)}")
    print(f"[+] Factorization  : {len(payload)} = {frame_count} x {HEIGHT} x {width}")
    print(f"[+] Terminal size  : {width} columns x {HEIGHT} rows")
    print(f"[+] Frames         : {frame_count}\n")

    for index in range(frame_count):
        print(f"--- frame {index + 1}/{frame_count} ---")
        frame = rows[index * HEIGHT:(index + 1) * HEIGHT]
        for line in frame:
            print(line.replace("_", " "))
        print()

    print("--- compact /\\ bitmap ---")
    for line in compact_bitmap(rows):
        print(line)

    # Prefix "bronco{r" terlihat pada banner pertama. Bagian sisanya
    # dibaca dengan mengikuti marker arah dan menyelaraskan lima frame.
    if not payload.startswith("_/\\/\\"):
        raise ValueError("Signature awal layout tidak cocok.")

    print(f"\n<FLAG>{ALIGNED_TEXT}</FLAG>")


if __name__ == "__main__":
    main()
