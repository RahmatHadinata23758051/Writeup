#!/usr/bin/env python3
"""Solver for cachebrowns (authorized CTF service only)."""

from pathlib import Path
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
SOURCE_PATH = BASE_DIR / "main.java"
HOST = "34.40.133.67"
PORT = 7777

context.log_level = "info"


def java_hash(data: bytes) -> int:
    """Java String.hashCode() for the ASCII password generated below."""
    value = 0
    for byte in data:
        value = (31 * value + byte) & 0xFFFFFFFF
    return value if value < (1 << 31) else value - (1 << 32)


def make_password(target: int = -110) -> bytes:
    """Return 16 printable ASCII bytes whose Java hash is *target*.

    All characters start at 0x20.  The final seven positions encode a
    base-31 residual; every digit is 0..30, so the generated input remains
    printable and cannot accidentally contain a newline.
    """
    modulus = 1 << 32
    length = 16
    baseline = (0x20 * sum(pow(31, i, modulus) for i in range(length))) % modulus
    residual = ((target & 0xFFFFFFFF) - baseline) % modulus

    for multiplier in range(10):
        value = residual + multiplier * modulus
        if value < 31**7:
            digits = []
            for _ in range(7):
                digits.append(value % 31)
                value //= 31
            password = b" " * 9 + bytes(0x20 + digit for digit in reversed(digits))
            if java_hash(password) != target:
                raise RuntimeError("internal hash construction failure")
            return password
    raise RuntimeError("could not represent the hash residual")


def start():
    if args.REMOTE:
        host = args.HOST or HOST
        port = int(args.PORT or PORT)
        return remote(host, port, timeout=10)

    if not SOURCE_PATH.exists():
        raise FileNotFoundError(f"source is missing: {SOURCE_PATH}")
    if args.GDB:
        log.warn("This is Java source, so GDB mode runs the local Java launcher (no native symbols).")
    return process(["java", str(SOURCE_PATH)], cwd=str(BASE_DIR))


def exploit(io):
    password = make_password()
    log.info("password = %r", password)
    log.info("verified Java hashCode = %d", java_hash(password))
    io.recvuntil(b"> ", timeout=10)
    io.sendline(password)
    result = io.recvall(timeout=10)
    if b"Authenticated!" not in result:
        raise RuntimeError(f"authentication unexpectedly failed: {result!r}")
    print(result.decode("utf-8", errors="replace"), end="")
    return result


def main():
    io = start()
    try:
        exploit(io)
    finally:
        io.close()


if __name__ == "__main__":
    main()
