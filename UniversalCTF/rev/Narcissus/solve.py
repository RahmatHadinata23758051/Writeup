#!/usr/bin/env python3
"""Recover the Narcissus passphrase from the challenge source."""

from hashlib import sha256
from pathlib import Path
import re


def main() -> None:
    source = Path(__file__).with_name("chall.py").read_text(encoding="utf-8")

    # chall.py hashes 28823 bytes starting at the decimal marker passed to
    # str.index(), then XORs the digest with this 32-byte constant.
    marker = re.search(r"\.index\('([0-9]+)'\)", source).group(1)
    start = source.index(marker)
    digest = sha256(source[start : start + 28823].encode()).digest()
    mask = bytes.fromhex(
        "5795e385f5fc7643968255125c2c74d8"
        "5fb18ed7015fb634265084bae5d4e6f0"
    )
    flag = bytes(a ^ b for a, b in zip(digest, mask)).decode()
    print(flag)


if __name__ == "__main__":
    main()
