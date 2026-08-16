#!/usr/bin/env python3

import os
import re
import sys

import requests


TARGET = os.environ.get(
    "TARGET",
    "https://7b5f0d66-18b4-4dbe-a0a2-b5cdb855dc5c.challs.scriptsorcerers.xyz",
).rstrip("/")
FLAG_RE = re.compile(r"(?:scriptCTF|CTF|FLAG)\{[^{}]+\}")


def main() -> int:
    url = f"{TARGET}/the-best-robot"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"request gagal: {exc}", file=sys.stderr)
        return 1

    match = FLAG_RE.search(response.text)
    if not match:
        print("flag tidak ditemukan pada response /the-best-robot", file=sys.stderr)
        return 1

    print(f"<FLAG>{match.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
