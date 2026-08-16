#!/usr/bin/env python3
"""
scriptCTF - Diabolical solve

The crypto validator is a decoy/dead-end. The real flag is left as a base64
string in the Go binary's rodata.
"""
from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

FLAG_RE = re.compile(rb"scriptCTF\{[^}\r\n]+\}")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")


def find_flag(path: str) -> bytes:
    data = Path(path).read_bytes()

    # Direct check, just in case.
    m = FLAG_RE.search(data)
    if m:
        return m.group(0)

    # Decode all plausible base64 blobs from the binary.
    for token in B64_RE.findall(data):
        # base64 length should be multiple of 4; pad defensively.
        padded = token + b"=" * ((4 - len(token) % 4) % 4)
        try:
            dec = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        m = FLAG_RE.search(dec)
        if m:
            print(f"[+] base64 blob: {token.decode(errors='ignore')}")
            return m.group(0)

    raise SystemExit("[-] flag not found")


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "./vault"
    flag = find_flag(path)
    print(flag.decode())


if __name__ == "__main__":
    main()
