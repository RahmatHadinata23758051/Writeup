#!/usr/bin/env python3
"""Offline solver for V1t CTF 2026 - B1tsy Ducky.

The only value not embedded in the attachment is document.referrer from the
original parent page. Supply that exact string using --referrer or the
B1TSY_REFERRER environment variable.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError as exc:
    raise SystemExit(
        "PyCryptodome is required. Install it with: pip install pycryptodome"
    ) from exc

SECRET = b"b1tsy-ducky-aesgcm"
CIPHERTEXT_HEX = (
    "9e8c2b395bbf6bd7434230ab998c6e86"
    "f3228c503324c8660715ccd0bc74deb7"
    "d6346dfcc4a9614e58cb"
)


def extract_game_data(html: str) -> str:
    match = re.search(
        r'<script\s+type="text/bitsyGameData"[^>]*>(.*?)</script>',
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if not match:
        raise ValueError("Bitsy game-data block was not found")
    return match.group(1).strip("\r\n")


def extract_room3_block(game_data: str) -> str:
    # ROOM 3 ends at the next blank line. Its field order in the attachment is
    # identical to serializeRoomBlock("3") in game.html.
    match = re.search(r"(?ms)^ROOM 3\r?\n.*?(?=\r?\n\r?\n)", game_data)
    if not match:
        raise ValueError("ROOM 3 block was not found")
    return match.group(0).replace("\r\n", "\n").rstrip("\n")


def extract_picked32(html: str) -> str:
    # Reproduce the useful result of pick32(): the Cloudflare beacon token.
    beacon = re.search(
        r'data-cf-beacon=[\'\"][^\'\"]*?"token"\s*:\s*"([0-9a-fA-F]{32})"',
        html,
    )
    if beacon:
        return beacon.group(1)

    candidates = re.findall(r"\b[0-9a-fA-F]{32}\b", html)
    if len(candidates) != 1:
        raise ValueError(
            f"Expected one unambiguous 32-hex token, found {len(candidates)}"
        )
    return candidates[0]


def derive_key(material: bytes) -> bytes:
    return hmac.new(SECRET, material, hashlib.sha256).digest()


def derive_nonce(material: bytes) -> bytes:
    return hashlib.sha256(b"nonce|" + material).digest()[:12]


def decrypt_flag(referrer: str, room3_block: str, picked32: str) -> str:
    material = f"{referrer}|{room3_block}|{picked32}".encode()
    key = derive_key(material)
    nonce = derive_nonce(material)

    blob = bytes.fromhex(CIPHERTEXT_HEX)
    ciphertext, tag = blob[:-16], blob[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--game",
        type=Path,
        default=Path(__file__).with_name("game.html"),
        help="path to game.html",
    )
    parser.add_argument(
        "--referrer",
        default=os.environ.get("B1TSY_REFERRER"),
        help="exact document.referrer from the original game tab",
    )
    parser.add_argument(
        "--dump-inputs",
        action="store_true",
        help="print the extracted ROOM 3 block and picked32 token",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.game.is_file():
        print(f"[-] game file not found: {args.game}", file=sys.stderr)
        return 2
    if args.referrer is None:
        print(
            "[-] missing referrer\n"
            "    Open the game through its original parent/index page, run\n"
            "    document.referrer in DevTools, then pass the exact value:\n"
            "    python3 solve.py --referrer 'https://parent.example/path'",
            file=sys.stderr,
        )
        return 2

    html = args.game.read_text(encoding="utf-8", errors="strict")
    game_data = extract_game_data(html)
    room3 = extract_room3_block(game_data)
    picked32 = extract_picked32(html)

    if args.dump_inputs:
        print(f"[*] picked32: {picked32}")
        print("[*] ROOM 3 serialization:")
        print(room3)

    try:
        flag = decrypt_flag(args.referrer, room3, picked32)
    except ValueError:
        print(
            "[-] AES-GCM authentication failed. The referrer must match "
            "document.referrer byte-for-byte.",
            file=sys.stderr,
        )
        return 1
    except UnicodeDecodeError:
        print("[-] decrypted data is not UTF-8", file=sys.stderr)
        return 1

    if not re.fullmatch(r"v1t\{[^\r\n]+\}", flag, flags=re.IGNORECASE):
        print(f"[-] decrypted plaintext has an unexpected format: {flag!r}")
        return 1

    print(f"[+] picked32 : {picked32}")
    print(f"[+] flag     : {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
