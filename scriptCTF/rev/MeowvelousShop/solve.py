#!/usr/bin/env python3
"""
MeowvelousShop solver.

Usage:
  Local : python3 solve_meowvelousshop.py ./chall
  Remote: python3 solve_meowvelousshop.py HOST PORT

The valid membership ID triggers the first printf() call. The binary has a
poisoned printf GOT entry, so that lazy binding trampoline calls print_flag().
"""
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

MEMBERSHIP_ID = b"N0Fl4gY37"
PAYLOAD = b"2\n" + MEMBERSHIP_ID + b"\n4\n"
FLAG_RE = re.compile(rb"scriptCTF\{[^}\r\n]+\}")


def extract_flag(data: bytes) -> str | None:
    m = FLAG_RE.search(data)
    return m.group(0).decode() if m else None


def run_remote(host: str, port: int) -> bytes:
    out = bytearray()
    with socket.create_connection((host, port), timeout=8) as s:
        s.settimeout(2)
        # Sending all menu answers at once is fine: the program reads line by line.
        s.sendall(PAYLOAD)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
    return bytes(out)


def run_local(path: str) -> bytes:
    p = Path(path).resolve()
    cwd = str(p.parent)
    proc = subprocess.run(
        [str(p)],
        input=PAYLOAD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
        timeout=5,
    )
    return proc.stdout


def main() -> int:
    if len(sys.argv) == 2:
        data = run_local(sys.argv[1])
    elif len(sys.argv) == 3:
        data = run_remote(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"Usage: {sys.argv[0]} ./chall", file=sys.stderr)
        print(f"   or: {sys.argv[0]} HOST PORT", file=sys.stderr)
        return 1

    sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
        print()

    flag = extract_flag(data)
    if flag:
        print(f"\n[+] flag: {flag}")
    else:
        print("\n[-] flag not found in output. On local, make sure flag.txt is in the binary directory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

