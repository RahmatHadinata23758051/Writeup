#!/usr/bin/env python3
"""
R3CTF 2026 - Homework solver

Usage:
    python3 solve.py HOST PORT
    python3 solve.py --local ./chall

Dependency:
    pip install mpmath
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from typing import Protocol

try:
    import mpmath as mp
except ImportError:
    print("[-] mpmath belum terpasang: pip install mpmath", file=sys.stderr)
    raise SystemExit(1)


mp.mp.dps = 260

OVERWRITE_B_TEXT = b"1e80"
OVERWRITE_B = mp.mpf("1e80")
PRINTABLE_MIN = 33
PRINTABLE_MAX = 126
EXPECTED_BLOCKS = 32


class Tube(Protocol):
    def sendline(self, data: bytes) -> None: ...
    def recvuntil(self, token: bytes, timeout: float = 30.0) -> bytes: ...
    def recvall(self, timeout: float = 5.0) -> bytes: ...
    def close(self) -> None: ...


class SocketTube:
    def __init__(self, host: str, port: int, timeout: float = 30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(0.25)
        self.buffer = bytearray()

    def sendline(self, data: bytes) -> None:
        self.sock.sendall(data + b"\n")

    def recvuntil(self, token: bytes, timeout: float = 30.0) -> bytes:
        deadline = time.monotonic() + timeout
        while token not in self.buffer:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timeout menunggu {token!r}; tail={bytes(self.buffer[-500:])!r}"
                )
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError(f"remote menutup koneksi; tail={bytes(self.buffer[-1000:])!r}")
            self.buffer.extend(chunk)

        end = self.buffer.index(token) + len(token)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def recvall(self, timeout: float = 5.0) -> bytes:
        output = bytearray(self.buffer)
        self.buffer.clear()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            output.extend(chunk)
        return bytes(output)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class ProcessTube:
    def __init__(self, path: str):
        self.proc = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("gagal membuat pipe proses")
        self.stdin = self.proc.stdin
        self.stdout = self.proc.stdout
        self.buffer = bytearray()

    def sendline(self, data: bytes) -> None:
        self.stdin.write(data + b"\n")
        self.stdin.flush()

    def recvuntil(self, token: bytes, timeout: float = 30.0) -> bytes:
        deadline = time.monotonic() + timeout
        while token not in self.buffer:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timeout menunggu {token!r}; tail={bytes(self.buffer[-500:])!r}"
                )
            chunk = os.read(self.stdout.fileno(), 1)
            if not chunk:
                raise EOFError(f"proses berhenti; tail={bytes(self.buffer[-1000:])!r}")
            self.buffer.extend(chunk)

        end = self.buffer.index(token) + len(token)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def recvall(self, timeout: float = 5.0) -> bytes:
        output = bytearray(self.buffer)
        self.buffer.clear()
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                output.extend(self.stdout.read() or b"")
                break
            time.sleep(0.01)
        return bytes(output)

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=2)


def parse_scalar(transcript: bytes, name: str) -> str:
    pattern = rb"(?m)^" + re.escape(name.encode()) + rb" = ([^\r\n]+)"
    match = re.search(pattern, transcript)
    if match is None:
        raise ValueError(f"field {name!r} tidak ditemukan")
    return match.group(1).decode().strip()


def quadratic_pair_pow(t: mp.mpf, k: mp.mpf, exponent: int) -> tuple[mp.mpf, mp.mpf]:
    """Compute (t + u)^exponent as p + q*u in Q[u]/(u^2-k)."""
    result_p, result_q = mp.mpf(1), mp.mpf(0)
    base_p, base_q = t, mp.mpf(1)

    while exponent:
        if exponent & 1:
            result_p, result_q = (
                result_p * base_p + result_q * base_q * k,
                result_p * base_q + result_q * base_p,
            )

        base_p, base_q = (
            base_p * base_p + base_q * base_q * k,
            2 * base_p * base_q,
        )
        exponent >>= 1

    return result_p, result_q


def parse_ciphertext(transcript: bytes) -> tuple[int, mp.mpf, mp.mpf, list[tuple[mp.mpf, mp.mpf]]]:
    n = int(parse_scalar(transcript, "n"))
    trace = mp.mpf(parse_scalar(transcript, "a_plus_d"))
    bc = mp.mpf(parse_scalar(transcript, "bc"))

    match = re.search(rb"(?s)C = \[(.*?)\]\r?\nT: ", transcript)
    if match is None:
        raise ValueError("ciphertext C tidak ditemukan")

    raw_pairs = re.findall(rb"\(([^,()]+),([^,()]+)\)", match.group(1))
    pairs = [(mp.mpf(x.decode()), mp.mpf(y.decode())) for x, y in raw_pairs]
    if len(pairs) != EXPECTED_BLOCKS:
        raise ValueError(f"jumlah pair C salah: {len(pairs)}, seharusnya {EXPECTED_BLOCKS}")

    return n, trace, bc, pairs


def recover_target(transcript: bytes) -> tuple[bytes, mp.mpf, mp.mpf]:
    n, trace, bc, pairs = parse_ciphertext(transcript)

    # A = tI + B, dengan B^2 = (delta^2 + bc)I.
    # Checker memaksa delta^2 sangat kecil dibanding |bc|, sehingga k=bc
    # memberi aproksimasi jauh di bawah error output 200 digit.
    t = trace / 2
    k = bc
    p, q = quadratic_pair_pow(t, k, n)
    determinant_power = p * p - q * q * k

    first_x, first_y = pairs[0]
    candidates: list[tuple[bool, mp.mpf, mp.mpf, mp.mpf, list[int]]] = []

    for first_char in range(PRINTABLE_MIN, PRINTABLE_MAX + 1):
        # Dari baris pertama inverse A^n:
        # m = (pX - qbY - q*delta*X) / det(A^n)
        delta = (
            p * first_x
            - q * OVERWRITE_B * first_y
            - mp.mpf(first_char) * determinant_power
        ) / (q * first_x)

        recovered: list[int] = []
        errors: list[mp.mpf] = []

        for x, y in pairs:
            value = (
                p * x
                - q * OVERWRITE_B * y
                - q * delta * x
            ) / determinant_power
            rounded = int(mp.nint(value))
            recovered.append(rounded)
            errors.append(abs(value - rounded))

        all_printable = all(PRINTABLE_MIN <= value <= PRINTABLE_MAX for value in recovered)
        candidates.append(
            (not all_printable, max(errors), sum(errors), delta, recovered)
        )

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    invalid, max_error, _, delta, recovered = candidates[0]

    if invalid or max_error > mp.mpf("1e-12"):
        raise ValueError(
            "recovery plaintext tidak meyakinkan; "
            f"max_error={mp.nstr(max_error, 12)}"
        )

    return bytes(recovered), max_error, delta


def exploit(io: Tube) -> tuple[bytes, bytes, mp.mpf, mp.mpf]:
    io.recvuntil(b"X size: ")
    io.sendline(b"1 1")

    io.recvuntil(b"Y size: ")
    io.sendline(b"1 1")

    io.recvuntil(b"X data: ")
    io.sendline(b"0")

    io.recvuntil(b"Y data: ")
    io.sendline(OVERWRITE_B_TEXT)

    io.recvuntil(b"op: ")
    io.sendline(b"blend 3")

    transcript = io.recvuntil(b"T: ", timeout=60.0)
    target, max_error, delta = recover_target(transcript)
    io.sendline(target)
    response = io.recvall(timeout=8.0)
    return target, response, max_error, delta


def extract_flag(data: bytes) -> bytes | None:
    matches = re.findall(rb"[A-Za-z0-9_]{2,24}\{[^{}\r\n]+\}", data)
    return matches[-1] if matches else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solver untuk rev/Homework")
    parser.add_argument("host", nargs="?", help="host remote")
    parser.add_argument("port", nargs="?", type=int, help="port remote")
    parser.add_argument("--local", metavar="PATH", help="jalankan binary lokal")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.local:
        io: Tube = ProcessTube(args.local)
        destination = f"local:{args.local}"
    else:
        if args.host is None or args.port is None:
            print("usage: python3 solve.py HOST PORT", file=sys.stderr)
            print("   atau python3 solve.py --local ./chall", file=sys.stderr)
            return 2
        io = SocketTube(args.host, args.port)
        destination = f"{args.host}:{args.port}"

    try:
        print(f"[*] connecting to {destination}")
        target, response, max_error, delta = exploit(io)
        print(f"[+] recovered T = {target.decode('ascii')}")
        print(f"[+] max rounding error = {mp.nstr(max_error, 6)}")
        print(f"[+] recovered delta = {mp.nstr(delta, 24)}")

        flag = extract_flag(response)
        if flag is not None:
            print(f"<FLAG>{flag.decode(errors='replace')}</FLAG>")
            return 0

        print("[-] flag tidak ditemukan pada respons akhir")
        print(response.decode(errors="replace"))
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    raise SystemExit(main())
