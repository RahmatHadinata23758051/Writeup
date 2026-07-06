#!/usr/bin/env python3
"""
r3ticket solver

Usage:
    source /home/nata/ctf_env/bin/activate
    python3 solve.py HOST PORT

The attack uses the leading decimal digits of sum(num_i ** x). For almost every
24-bit x, the largest 16-bit num dominates the sum. The 64-digit prefix is then
an extremely precise mantissa fingerprint of M ** x. Recover x with a 2D CVP
instance over fixed-point log10(M).

If a rare non-dominant round is detected, the connection is abandoned and the
solver starts a fresh attempt instead of guessing.
"""

from __future__ import annotations

import argparse
import math
import re
import socket
import sys
import time
from dataclasses import dataclass

import mpmath as mp

# Fixed-point/CVP parameters.
MP_DPS = 100
P = 256
C = 1 << P
W = 1 << 128
X_LIMIT = 1 << 24

# For 128 uniform 16-bit values, max(nums) is overwhelmingly above 50000.
# Restricting the candidate range keeps each round comfortably below 3 seconds.
MIN_MAX_CANDIDATE = 50_000
MAX_MAX_CANDIDATE = 65_535

# 60 bits of mantissa agreement is enough to identify x while tolerating a tiny
# contribution from the second-largest value.
MATCH_BITS = 60
MATCH_THRESHOLD = 1 << (P - MATCH_BITS)

FLAG_RE = re.compile(rb"(?:R3CTF|r3ctf)\{[^}\r\n]+\}")


class RecoveryError(RuntimeError):
    pass


class RemoteClosed(RuntimeError):
    pass


@dataclass(frozen=True)
class ReducedBasis:
    x1: int
    y1: int
    x2: int
    y2: int
    norm1: int
    det: int


def nearest_integer_div(num: int, den: int) -> int:
    """Round num / den to the nearest integer using integer arithmetic."""
    if den < 0:
        num, den = -num, -den
    if num >= 0:
        return (num + den // 2) // den
    return -((-num + den // 2) // den)


def gauss_reduce(a_fixed: int) -> ReducedBasis:
    """Gauss reduction for lattice <(C, 0), (a_fixed, W)> in dimension 2."""
    b1 = [C, 0]
    b2 = [a_fixed, W]

    while True:
        n1 = b1[0] * b1[0] + b1[1] * b1[1]
        n2 = b2[0] * b2[0] + b2[1] * b2[1]

        if n2 < n1:
            b1, b2 = b2, b1
            n1, n2 = n2, n1

        dot = b1[0] * b2[0] + b1[1] * b2[1]
        mu = nearest_integer_div(dot, n1)
        if mu == 0:
            return ReducedBasis(
                x1=b1[0],
                y1=b1[1],
                x2=b2[0],
                y2=b2[1],
                norm1=n1,
                det=b1[0] * b2[1] - b1[1] * b2[0],
            )

        b2[0] -= mu * b1[0]
        b2[1] -= mu * b1[1]


def build_bases() -> list[ReducedBasis]:
    mp.mp.dps = MP_DPS
    log10_const = mp.log(10)
    bases: list[ReducedBasis] = []

    for maximum in range(MIN_MAX_CANDIDATE, MAX_MAX_CANDIDATE + 1):
        a_fixed = int(mp.nint((mp.log(maximum) / log10_const) * C))
        bases.append(gauss_reduce(a_fixed))

    return bases


def circular_fraction_distance(value: mp.mpf) -> mp.mpf:
    return abs(value - mp.nint(value))


def search_fixed_target(
    target_fixed: int,
    beta: mp.mpf,
    multiplicity: int,
    bases: list[ReducedBasis],
) -> list[tuple[mp.mpf, int, int, int]]:
    """
    Return candidates as (score, x, M, multiplicity).

    The lattice point has form (C*k + A*x, W*x), near (target_fixed, 0).
    Checking v0 +/- 1 is enough after Gauss reduction in dimension 2.
    """
    candidates: list[tuple[mp.mpf, int, int, int]] = []
    log_t = mp.log10(multiplicity)

    for maximum, basis in enumerate(bases, MIN_MAX_CANDIDATE):
        v0 = nearest_integer_div(-basis.y1 * target_fixed, basis.det)
        best_error: int | None = None
        best_x: int | None = None

        for v in (v0 - 1, v0, v0 + 1):
            rx = target_fixed - v * basis.x2
            ry = -v * basis.y2
            u = nearest_integer_div(
                rx * basis.x1 + ry * basis.y1,
                basis.norm1,
            )

            px = u * basis.x1 + v * basis.x2
            py = u * basis.y1 + v * basis.y2

            if py % W != 0:
                continue

            x = abs(py // W)
            error = abs(px - target_fixed)

            if x >= X_LIMIT or error >= MATCH_THRESHOLD:
                continue

            if best_error is None or error < best_error:
                best_error = error
                best_x = x

        if best_x is not None:
            predicted = mp.mpf(best_x) * mp.log10(maximum) + log_t
            score = circular_fraction_distance(predicted - beta)
            candidates.append((score, best_x, maximum, multiplicity))

    return candidates


def recover_small_x(full_value: int) -> int:
    """Handle x values whose complete sum has fewer than 64 decimal digits."""
    if full_value == 128:
        return 0

    observed_log = mp.log10(full_value)
    # E[sum(U^x)] ~= 128 * 65535^x / (x + 1). Adjacent x values are
    # separated by about 4.8 decimal digits, so this classifier is robust.
    choices = range(1, 20)
    return min(
        choices,
        key=lambda x: abs(
            observed_log
            - (
                mp.log10(128)
                + x * mp.log10(65_535)
                - mp.log10(x + 1)
            )
        ),
    )


def recover_x(challenge_text: str, bases: list[ReducedBasis]) -> tuple[int, str]:
    challenge_text = challenge_text.strip()
    if not challenge_text.isdigit():
        raise RecoveryError(f"invalid challenge text: {challenge_text!r}")

    if len(challenge_text) < 64:
        x = recover_small_x(int(challenge_text))
        return x, "small-x length classifier"

    prefix_int = int(challenge_text)
    beta = mp.log10(mp.mpf(prefix_int) / mp.power(10, 63))

    all_candidates: list[tuple[mp.mpf, int, int, int]] = []

    # t > 1 handles the rare case where the maximum occurs more than once.
    for multiplicity in (1, 2, 3):
        target = beta - mp.log10(multiplicity)
        target -= mp.floor(target)
        target_fixed = int(mp.nint(target * C))
        all_candidates.extend(
            search_fixed_target(
                target_fixed=target_fixed,
                beta=beta,
                multiplicity=multiplicity,
                bases=bases,
            )
        )

        # t=1 is the normal case. Returning early saves time and still requires
        # a strict 60-bit match.
        if multiplicity == 1 and all_candidates:
            break

    if not all_candidates:
        raise RecoveryError("no high-confidence lattice candidate")

    # Decimal scaling can produce multiple M values with the same x. Group by x
    # and keep the best score for each recovered exponent.
    best_by_x: dict[int, tuple[mp.mpf, int, int, int]] = {}
    for candidate in all_candidates:
        score, x, maximum, multiplicity = candidate
        previous = best_by_x.get(x)
        if previous is None or score < previous[0]:
            best_by_x[x] = candidate

    ranked = sorted(best_by_x.values(), key=lambda item: item[0])
    best = ranked[0]

    # Avoid sending an ambiguous result. A retry is safer than a guess.
    if len(ranked) > 1 and ranked[1][0] <= best[0] * 4:
        raise RecoveryError("ambiguous lattice candidates")

    score, x, maximum, multiplicity = best
    detail = (
        f"M≈{maximum}, multiplicity={multiplicity}, "
        f"log-error≈{mp.nstr(score, 4)}"
    )
    return x, detail


class BufferedSocket:
    def __init__(self, host: str, port: int, timeout: float = 20.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def sendline(self, data: str | bytes) -> None:
        raw = data.encode() if isinstance(data, str) else data
        self.sock.sendall(raw + b"\n")

    def recvuntil(self, token: bytes) -> bytes:
        while True:
            index = self.buffer.find(token)
            if index >= 0:
                end = index + len(token)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result

            chunk = self.sock.recv(4096)
            if not chunk:
                raise RemoteClosed("remote closed the connection")
            self.buffer.extend(chunk)

    def recvline(self) -> bytes:
        return self.recvuntil(b"\n")

    def recvall(self, timeout: float = 5.0) -> bytes:
        chunks = [bytes(self.buffer)]
        self.buffer.clear()
        self.sock.settimeout(timeout)
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def solve_connection(host: str, port: int, bases: list[ReducedBasis]) -> bytes:
    io = BufferedSocket(host, port)
    try:
        io.recvuntil(b"Which number you want to know: ")
        io.sendline("0")

        # Consume the number leak and the built-in 10-second preparation delay.
        io.recvuntil(b"Lets play!")

        for round_index in range(16):
            io.recvuntil(b"challenge = ")
            challenge = io.recvline().strip().decode("ascii")

            started = time.perf_counter()
            x, detail = recover_x(challenge, bases)
            elapsed = time.perf_counter() - started

            io.recvuntil(b"x = ")
            io.sendline(str(x))
            print(
                f"[+] round {round_index + 1:02d}/16: x={x} "
                f"({elapsed:.3f}s, {detail})",
                flush=True,
            )

        result = io.recvall(timeout=5.0)
        return result
    finally:
        io.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Solver for R3CTF 2026 r3ticket")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--attempts",
        type=int,
        default=30,
        help="maximum fresh connections before giving up (default: 30)",
    )
    args = parser.parse_args()

    mp.mp.dps = MP_DPS
    print("[*] precomputing 2D reduced bases...", flush=True)
    started = time.perf_counter()
    bases = build_bases()
    print(
        f"[+] prepared {len(bases)} bases in "
        f"{time.perf_counter() - started:.2f}s",
        flush=True,
    )

    for attempt in range(1, args.attempts + 1):
        print(f"[*] connection attempt {attempt}/{args.attempts}", flush=True)
        try:
            output = solve_connection(args.host, args.port, bases)
        except (OSError, socket.timeout, RemoteClosed, RecoveryError) as exc:
            print(f"[-] retrying: {exc}", flush=True)
            continue

        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()

        match = FLAG_RE.search(output)
        if match:
            flag = match.group(0).decode("ascii", errors="replace")
            print(f"\n<FLAG>{flag}</FLAG>")
            return

        print("[-] connection completed but no flag was found; retrying", flush=True)

    raise SystemExit("[-] exhausted all connection attempts")


if __name__ == "__main__":
    main()
