#!/usr/bin/env python3
"""Solver for Crypto CTF challenge: Vigroterse."""

from pathlib import Path
import re
import sys

KEY = "H"  # Discord profile clue: '"H" ~♡'
FLAG_RE = re.compile(r"Thryve\{[^\r\n}]+\}")


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt alphabetic characters with a standard Vigenere key.

    Non-alphabetic characters are preserved. Key position advances only
    across alphabetic characters; for the one-letter key H this is a
    Caesar shift of -7.
    """
    shifts = [ord(ch.upper()) - ord("A") for ch in key if ch.isalpha()]
    if not shifts:
        raise ValueError("Vigenere key must contain at least one letter")

    out = []
    key_index = 0

    for ch in text:
        if "A" <= ch <= "Z":
            shift = shifts[key_index % len(shifts)]
            out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            key_index += 1
        elif "a" <= ch <= "z":
            shift = shifts[key_index % len(shifts)]
            out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            key_index += 1
        else:
            out.append(ch)

    return "".join(out)


def rot47(text: str) -> str:
    """Apply ROT47 to printable ASCII characters (33..126)."""
    out = []
    for ch in text:
        value = ord(ch)
        if 33 <= value <= 126:
            out.append(chr(33 + ((value - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def solve(ciphertext: str) -> str:
    # Challenge title "Vigroterse" hints at:
    #   VIG(enere) + ROT + (re)VERSE
    layer1 = vigenere_decrypt(ciphertext, KEY)
    layer2 = rot47(layer1)
    plaintext = layer2[::-1]

    print(f"[+] Ciphertext        : {ciphertext}")
    print(f"[+] Vigenere key      : {KEY}")
    print(f"[+] After Vigenere    : {layer1}")
    print(f"[+] After ROT47       : {layer2}")
    print(f"[+] After reverse     : {plaintext}")

    match = FLAG_RE.search(plaintext)
    if not match:
        raise SystemExit("[-] Flag format Thryve{...} not found")

    flag = match.group(0)
    print(f"\n<FLAG>{flag}</FLAG>")
    return flag


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("chall.enc")
    ciphertext = path.read_text(encoding="utf-8").strip()
    solve(ciphertext)


if __name__ == "__main__":
    main()

