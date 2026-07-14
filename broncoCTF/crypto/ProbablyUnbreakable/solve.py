#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from typing import Iterable

from pwn import context, remote


KEYSTRING = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
HEX_LINE = re.compile(rb"^[0-9a-fA-F]+$")


def possible_plaintexts(cipher_byte: int) -> set[int]:
    return {cipher_byte ^ key_byte for key_byte in KEYSTRING}


def recover_flag(ciphertexts: Iterable[bytes]) -> tuple[bytes, list[set[int]]]:
    ciphertexts = list(ciphertexts)
    if not ciphertexts:
        raise ValueError("Tidak ada ciphertext yang diterima")

    flag_length = len(ciphertexts[0])
    if any(len(item) != flag_length for item in ciphertexts):
        raise ValueError("Panjang ciphertext tidak konsisten")

    candidates = [set(range(256)) for _ in range(flag_length)]

    for ciphertext in ciphertexts:
        for index, cipher_byte in enumerate(ciphertext):
            candidates[index].intersection_update(
                possible_plaintexts(cipher_byte)
            )

    unresolved = [index for index, values in enumerate(candidates) if len(values) != 1]
    if unresolved:
        details = []
        for index in unresolved:
            printable = sorted(
                value for value in candidates[index]
                if 0x20 <= value <= 0x7E
            )
            rendered = "".join(chr(value) for value in printable)
            details.append(
                f"pos {index}: {len(candidates[index])} kandidat "
                f"(printable={rendered!r})"
            )
        raise RuntimeError(
            "Flag belum unik. Naikkan --samples.\n" + "\n".join(details)
        )

    flag = bytes(next(iter(values)) for values in candidates)
    return flag, candidates


def receive_ciphertexts(io, count: int) -> list[bytes]:
    ciphertexts: list[bytes] = []

    while len(ciphertexts) < count:
        line = io.recvline(timeout=15)
        if not line:
            raise EOFError(
                f"Koneksi ditutup setelah menerima "
                f"{len(ciphertexts)}/{count} ciphertext"
            )

        candidate = line.strip()
        if not HEX_LINE.fullmatch(candidate) or len(candidate) % 2 != 0:
            continue

        try:
            decoded = bytes.fromhex(candidate.decode())
        except ValueError:
            continue

        ciphertexts.append(decoded)

        if len(ciphertexts) % 100 == 0 or len(ciphertexts) == count:
            print(f"[+] Received {len(ciphertexts)}/{count}")

    return ciphertexts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve BroncoCTF Probably Unbreakable"
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
        default=16474,
        help="remote port",
    )
    parser.add_argument(
        "-n",
        "--samples",
        type=int,
        default=512,
        help="jumlah encrypted flag yang diminta (default: 512)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="aktifkan log pwntools",
    )
    args = parser.parse_args()

    if args.samples <= 0 or args.samples > 20_000:
        parser.error("--samples harus berada pada rentang 1..20000")

    context.log_level = "debug" if args.debug else "error"

    io = remote(args.host, args.port)

    io.sendlineafter(
        b"How many list-scrambles do you want?",
        b"0",
    )
    io.sendlineafter(
        b"How many random-letter-pickings do you want?",
        b"0",
    )
    io.sendlineafter(
        b"How many flag encryptions do you want?",
        str(args.samples).encode(),
    )

    ciphertexts = receive_ciphertexts(io, args.samples)
    io.close()

    flag, _ = recover_flag(ciphertexts)

    try:
        decoded_flag = flag.decode("ascii")
    except UnicodeDecodeError:
        decoded_flag = repr(flag)

    print(f"<FLAG>{decoded_flag}</FLAG>")


if __name__ == "__main__":
    main()
