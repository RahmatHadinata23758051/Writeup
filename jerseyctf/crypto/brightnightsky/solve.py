#!/usr/bin/env python3
import re

CIPHERTEXT = "ucrx{ARMBPCR GCIMF}"
KEYWORDS = [
    "salt",
    "vinegar",
    "saltvinegar",
    "chips",
    "lays",
    "borya",
    "ivanov",
    "soviet",
    "brightnightsky",
]


def vigenere_decrypt(text: str, key: str) -> str:
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            k = ord(key[j % len(key)].lower()) - ord("a")
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - k) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def looks_like_flag(s: str) -> bool:
    return re.fullmatch(r"[a-z]{4}\{[A-Z0-9_ ]+\}", s) is not None


def main() -> None:
    for key in KEYWORDS:
        pt = vigenere_decrypt(CIPHERTEXT, key)
        if looks_like_flag(pt) and pt.startswith("jctf{"):
            print(pt)
            return

    # Fallback brute-force for short lowercase keys if needed.
    # Not reached for this challenge, but keeps script self-contained.
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                for d in alphabet:
                    key = a + b + c + d
                    pt = vigenere_decrypt(CIPHERTEXT, key)
                    if looks_like_flag(pt) and pt.startswith("jctf{"):
                        print(pt)
                        return


if __name__ == "__main__":
    main()
