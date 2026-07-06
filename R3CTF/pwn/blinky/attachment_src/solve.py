#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_TARGET = "challenge.ctf2026.r3kapig.com:30866"
FLAG_RE = re.compile(rb"R3CTF\{[^}\r\n]+\}")


def submit(target: str, timeout: float) -> bytes:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    target = target.rstrip("/")
    if not target.endswith("/submit"):
        target += "/submit"

    payload_path = Path(__file__).with_name("exploit.mem")
    try:
        payload = payload_path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"[-] gagal membaca {payload_path}: {exc}") from exc

    request = urllib.request.Request(
        target,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "User-Agent": "blinky-solver/1.0",
        },
    )

    print(f"[*] upload {payload_path.name} -> {target}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        sys.stderr.write(f"[-] HTTP {exc.code}: {exc.reason}\n")
        if body:
            sys.stderr.buffer.write(body + (b"\n" if not body.endswith(b"\n") else b""))
        raise SystemExit(1) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"[-] koneksi gagal: {exc.reason}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Upload payload Blinky yang memulihkan PAC tag di dalam simulator."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=DEFAULT_TARGET,
        help=f"host:port atau URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    body = submit(args.target, args.timeout)
    sys.stdout.buffer.write(body)
    if body and not body.endswith(b"\n"):
        print()

    match = FLAG_RE.search(body)
    if match:
        flag = match.group().decode("ascii", errors="replace")
        print(f"<FLAG>{flag}</FLAG>")
    else:
        print("[-] flag belum terlihat di response")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
