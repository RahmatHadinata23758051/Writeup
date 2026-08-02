#!/usr/bin/env python3
from pwn import *
import re

HOST = "tcp-01kyy2f1bkmdgq5kf88dnh7fcs.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

def iroot3(n: int) -> int:
    lo, hi = 0, 1
    while hi ** 3 <= n:
        hi *= 2

    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid

    return lo

def long_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

io = remote(HOST, PORT, ssl=True, sni=True)

banner = io.recvuntil(b"reply> ")
print(banner.decode(errors="ignore"))

c = int(re.search(rb"c = (\d+)", banner).group(1))

m = iroot3(c)

if m ** 3 != c:
    print("[-] Cube root tidak exact, ada yang beda.")
    exit()

token = long_to_bytes(m).decode()
print("[+] token:", token)

io.sendline(token.encode())

print(io.recvall(timeout=5).decode(errors="ignore"))
