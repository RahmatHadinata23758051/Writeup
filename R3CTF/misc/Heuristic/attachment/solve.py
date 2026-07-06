#!/usr/bin/env python3
"""
HEuristic solver

Usage:
    python3 solve.py HOST PORT

The service allows exactly three actions. We use them as:
    1. encrypt one chosen 4096-coefficient plaintext
    2. decrypt the returned ciphertext
    3. submit the recovered delta

No third-party Python packages are required.
"""

from __future__ import annotations

import math
import re
import socket
import sys
from dataclasses import dataclass
from typing import List, Sequence, Tuple


N = 4096
LEAKED = 96
MAX_ATTEMPTS = 3


class ProtocolError(RuntimeError):
    pass


class Tube:
    def __init__(self, host: str, port: int, timeout: float = 25.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def sendline(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recvuntil(self, marker: bytes) -> bytes:
        while True:
            pos = self.buf.find(marker)
            if pos != -1:
                end = pos + len(marker)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProtocolError(f"connection closed before marker {marker!r}")
            self.buf.extend(chunk)

    def recvline(self) -> bytes:
        return self.recvuntil(b"\n")

    def recvn(self, count: int) -> bytes:
        while len(self.buf) < count:
            chunk = self.sock.recv(min(65536, count - len(self.buf)))
            if not chunk:
                raise ProtocolError("connection closed during fixed-size receive")
            self.buf.extend(chunk)
        out = bytes(self.buf[:count])
        del self.buf[:count]
        return out

    def recvall(self) -> bytes:
        chunks = [bytes(self.buf)]
        self.buf.clear()
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def nearest_div(numerator: int, denominator: int) -> int:
    """Round numerator / denominator to the nearest integer, including negatives."""
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    if numerator >= 0:
        return (numerator + denominator // 2) // denominator
    return -((-numerator + denominator // 2) // denominator)


def centered_abs(value: int, modulus: int) -> int:
    value %= modulus
    return min(value, modulus - value)


def plaintext_is_valid(value: int, q: int) -> bool:
    reduced = value % q
    return min(reduced, q - reduced) >= q // 8


@dataclass
class ChosenPlaintext:
    coefficients: List[int]
    multipliers: List[int]
    gaps: List[int]
    total_shift: int


def build_chosen_plaintext(q: int) -> ChosenPlaintext:
    """
    Build m_i such that m_i = 2^g_i * m_(i-1) (mod q).

    Each selected coefficient must survive the server's plaintext check:
        min(m_i, q-m_i) >= q/8.

    Gaps start at 3. This makes the accumulated exponent exceed the roughly
    188-bit error size while keeping each local multiplication small enough
    that the correct quotient is unambiguous.
    """
    m0 = q // 3
    if math.gcd(m0, q) != 1:
        raise RuntimeError("unexpected non-invertible initial multiplier")
    if not plaintext_is_valid(m0, q):
        raise RuntimeError("initial multiplier rejected by plaintext bounds")

    multipliers = [m0]
    gaps: List[int] = []
    total_shift = 0

    for _ in range(LEAKED - 1):
        previous = multipliers[-1]
        for gap in range(3, 33):
            candidate = (previous * pow(2, gap, q)) % q
            if plaintext_is_valid(candidate, q):
                multipliers.append(candidate)
                gaps.append(gap)
                total_shift += gap
                break
        else:
            raise RuntimeError("could not find a valid doubling step")

    # Hidden coefficients still have to pass encrypt()'s validation.
    coefficients = multipliers + [m0] * (N - LEAKED)
    return ChosenPlaintext(coefficients, multipliers, gaps, total_shift)


def recover_delta(q: int, chosen: ChosenPlaintext, observations: Sequence[int]) -> Tuple[int, int, int]:
    if len(observations) != LEAKED:
        raise ValueError(f"expected {LEAKED} observations")

    # Let y_i = m_i*delta + e_i (mod q). Recursively choose the unique lift
    # U_i congruent to y_i mod q and close to 2^g_i * U_(i-1).
    lifted = observations[0]
    shift = 0
    for y, gap in zip(observations[1:], chosen.gaps):
        factor = 1 << gap
        quotient = nearest_div(factor * lifted - y, q)
        lifted = y + quotient * q
        shift += gap

    # After unrolling:
    #   lifted = 2^shift * (m0*delta mod q + kq) + final_error
    # and shift is much larger than the error bit length.
    recovered_product = nearest_div(lifted, 1 << shift) % q
    delta = (recovered_product * pow(chosen.multipliers[0], -1, q)) % q

    # Wrong quotient choices produce essentially random residuals (~q/4).
    # Correct recovery leaves only the service's ~2^188 noise.
    residuals = [
        centered_abs(y - (m * delta) % q, q)
        for m, y in zip(chosen.multipliers, observations)
    ]
    return delta, max(residuals), shift


def parse_q(io: Tube) -> int:
    line = io.recvline().strip()
    match = re.fullmatch(rb"q\s*=\s*(\d+)", line)
    if not match:
        raise ProtocolError(f"unexpected q line: {line!r}")
    return int(match.group(1))


def encrypt_once(io: Tube, coefficients: Sequence[int]) -> bytes:
    io.recvuntil(b"> ")
    io.sendline("1")
    io.recvuntil(b"input n followed by n lines of m\n")

    payload = [str(N)]
    payload.extend(str(value) for value in coefficients)
    io.send(("\n".join(payload) + "\n").encode())

    io.recvuntil(b"ciphertext length: ")
    length_line = io.recvline().strip()
    try:
        ciphertext_length = int(length_line)
    except ValueError as exc:
        raise ProtocolError(f"bad ciphertext length: {length_line!r}") from exc

    ciphertext = io.recvn(ciphertext_length)
    return ciphertext


def decrypt_once(io: Tube, ciphertext: bytes) -> List[int]:
    # Consume the newline following the raw ciphertext plus the next menu.
    io.recvuntil(b"> ")
    io.sendline("2")
    io.recvuntil(b"ciphertext length> ")
    io.send(str(len(ciphertext)).encode() + b"\n" + ciphertext + b"\n")

    line = io.recvline().strip()
    tokens = line.split()
    if len(tokens) < LEAKED:
        raise ProtocolError(f"short decrypt response: {line[:200]!r}")

    try:
        return [int(token) for token in tokens[:LEAKED]]
    except ValueError as exc:
        raise ProtocolError(f"non-integer leaked coefficient: {line[:200]!r}") from exc


def submit_delta(io: Tube, delta: int) -> bytes:
    io.recvuntil(b"> ")
    io.sendline("3")
    io.recvuntil(b"delta> ")
    io.sendline(str(delta))
    return io.recvall()


def solve(host: str, port: int) -> str:
    last_error: Exception | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        io: Tube | None = None
        try:
            print(f"[*] connecting to {host}:{port} (attempt {attempt}/{MAX_ATTEMPTS})")
            io = Tube(host, port)
            q = parse_q(io)
            print(f"[+] q bits = {q.bit_length()}")

            chosen = build_chosen_plaintext(q)
            print(
                f"[+] chosen chain: {LEAKED} coefficients, "
                f"total shift = {chosen.total_shift}, max gap = {max(chosen.gaps)}"
            )

            ciphertext = encrypt_once(io, chosen.coefficients)
            print(f"[+] ciphertext length = {len(ciphertext)}")

            observations = decrypt_once(io, ciphertext)
            delta, max_residual, recovered_shift = recover_delta(q, chosen, observations)
            print(f"[+] recovered delta = {delta}")
            print(f"[+] max residual bits = {max_residual.bit_length()}")

            # q is about 240 bits and valid residuals are around 188 bits.
            # Keep a generous margin for SEAL's own encryption noise.
            if recovered_shift < 210:
                raise RuntimeError("insufficient accumulated shift")
            if max_residual >= (1 << 205):
                raise RuntimeError("candidate failed residual validation")

            response = submit_delta(io, delta)
            text = response.decode(errors="replace").strip()
            if text:
                print(text)

            match = re.search(rb"[A-Za-z0-9_]+\{[^\r\n}]*\}", response)
            if not match:
                raise RuntimeError("server did not return a flag")

            flag = match.group(0).decode(errors="replace")
            print(f"<FLAG>{flag}</FLAG>")
            return flag

        except (OSError, ProtocolError, RuntimeError, ValueError) as exc:
            last_error = exc
            print(f"[-] attempt failed: {exc}", file=sys.stderr)
        finally:
            if io is not None:
                io.close()

    raise SystemExit(f"solver failed after {MAX_ATTEMPTS} attempts: {last_error}")


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} HOST PORT", file=sys.stderr)
        raise SystemExit(2)

    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("PORT must be an integer", file=sys.stderr)
        raise SystemExit(2)

    solve(host, port)


if __name__ == "__main__":
    main()
