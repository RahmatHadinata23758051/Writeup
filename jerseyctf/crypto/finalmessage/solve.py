#!/usr/bin/env python3
"""
JerseyCTF - Final Message

Ciphertext and key are extracted from the audio challenge:
  ciphertext: НОЫЭОЦПЪУЗРМХУЛЭЯ
  key       : ЛАЙКА
"""

ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
KEY = "ЛАЙКА"
CIPHERTEXT = "НОЫЭОЦПЪУЗРМХУЛЭЯ"


def vigenere_decrypt(ciphertext: str, key: str, alphabet: str) -> str:
    pos = {c: i for i, c in enumerate(alphabet)}
    out = []
    for i, ch in enumerate(ciphertext):
        k = key[i % len(key)]
        out.append(alphabet[(pos[ch] - pos[k]) % len(alphabet)])
    return "".join(out)


def main() -> None:
    plaintext = vigenere_decrypt(CIPHERTEXT, KEY, ALPHABET)
    flag = f"jctf{{{plaintext}}}"
    print("ciphertext:", CIPHERTEXT)
    print("key:", KEY)
    print("plaintext:", plaintext)
    print("flag:", flag)


if __name__ == "__main__":
    main()
