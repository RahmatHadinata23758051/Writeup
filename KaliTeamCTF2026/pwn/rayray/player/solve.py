#!/usr/bin/env python3
from pwn import *
from ctypes import CDLL
import time, os, re

HOST = "chall.kali-team.online"
PORT = 10071

context.log_level = "error"

# pakai libc challenge kalau ada di folder yang sama
if os.path.exists("./libc.so.6"):
    libc = CDLL("./libc.so.6")
else:
    libc = CDLL("libc.so.6")

def get_idx(seed):
    libc.srand(seed)
    return libc.rand() % 100

def try_block(idx):
    io = remote(HOST, PORT)
    io.recvuntil(b"enter Block number:")
    io.sendline(str(idx).encode())
    out = io.recvall(timeout=2)
    io.close()
    return out

# urutan offset waktu: sekarang, -1, +1, dst
offsets = [0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -10, 10]

for attempt in range(200):
    now = int(time.time())

    tried = set()

    for off in offsets:
        seed = now + off
        idx = get_idx(seed)

        if idx in tried:
            continue
        tried.add(idx)

        out = try_block(idx)
        text = out.decode(errors="replace")

        print(f"[try] seed={seed} idx={idx}")
        print(text)

        m = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", text)
        if m:
            print("\n[+] FLAG FOUND:")
            print(m.group(0))
            exit()

    time.sleep(0.15)

print("[-] flag belum ketemu, coba jalankan ulang solve.py")
