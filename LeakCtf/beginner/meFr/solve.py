#!/usr/bin/env python3
import re
import sys
from pathlib import Path


def build_decoder() -> dict[str, str]:
    """
    Mapping karakter hasil salah ketik -> karakter sebenarnya.

    Asumsi:
    - Hanya tangan kanan yang bergeser satu tombol ke kanan.
    - Tangan kiri tetap berada di posisi normal.
    - Kapitalisasi dan simbol tidak dinormalisasi.
    """
    keyboard_pairs = [
        # Number row
        ("7890-=", "67890-"),
        ("&*()_+", "^&*()_"),

        # Top letter row
        ("uiop[]\\", "yuiop[]"),
        ("UIOP{}|", "YUIOP{}"),

        # Home row
        ("jkl;'", "hjkl;"),
        ('JKL:"', "HJKL:"),

        # Bottom row
        ("m,./", "nm,."),
        ("M<>?", "NM<>"),
    ]

    decoder = {}

    for mistyped_chars, correct_chars in keyboard_pairs:
        if len(mistyped_chars) != len(correct_chars):
            raise ValueError("Panjang mapping tidak sama")

        decoder.update(zip(mistyped_chars, correct_chars))

    return decoder


def decode(text: str) -> str:
    decoder = build_decoder()
    return "".join(decoder.get(char, char) for char in text)


def main() -> None:
    filename = sys.argv[1] if len(sys.argv) > 1 else "me_fr.txt"
    path = Path(filename)

    if not path.exists():
        raise SystemExit(f"File tidak ditemukan: {path}")

    ciphertext = path.read_text(encoding="utf-8").strip()
    plaintext = decode(ciphertext)

    print("=== DECODED TEXT ===")
    print(plaintext)

    flags = re.findall(r"[A-Za-z0-9_]+\{[^}\n]+\}", plaintext)

    print("\n=== FLAG CANDIDATE ===")
    if flags:
        for flag in flags:
            print(repr(flag))
    else:
        print("Flag tidak ditemukan otomatis.")


if __name__ == "__main__":
    main()
