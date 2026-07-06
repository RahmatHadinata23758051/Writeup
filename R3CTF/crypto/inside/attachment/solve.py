#!/usr/bin/env sage -python
"""
Solver for Crypto / Inside.

Run:
    conda activate sage
    sage -python solve.py HOST PORT

The exploit chooses s_i = e_i = -1, so every bit witness is zero.
The verifier only checks the RLWE relation inside the secp256k1 scalar
field. Since 3329 is invertible modulo the curve order, arbitrary k_i can
be chosen to make the relation hold.
"""

from sage.all import EllipticCurve, GF, inverse_mod

import argparse
import ast
import hashlib
import itertools
import multiprocessing as mp
import os
import re
import socket
import string
import sys
from typing import Iterable, Optional, Sequence, Tuple


# secp256k1 parameters, copied from sigma.py
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
E = EllipticCurve(GF(P), [0, 7])
O = E(0)
G = E(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

N = 256
RLWE_Q = 3329
ALPHABET = string.ascii_letters + string.digits


class CurveHomomorphism:
    """Exact string representation used by the challenge hash."""

    def __init__(self, generators):
        self.Gs = generators
        self.n, self.m = len(generators[0]), len(generators)

    def __str__(self):
        return f"CurveHomomorphism(Gs={self.Gs})"


class Tube:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port))
        self.buf = bytearray()

    def recvuntil(self, token: bytes) -> bytes:
        while token not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"connection closed before token {token!r}")
            self.buf.extend(chunk)
        end = self.buf.index(token) + len(token)
        out = bytes(self.buf[:end])
        del self.buf[:end]
        return out

    def recvline(self) -> bytes:
        return self.recvuntil(b"\n")

    def sendline(self, data) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def recvall(self) -> bytes:
        out = bytes(self.buf)
        self.buf.clear()
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            out += chunk
        return out


# One task checks all prefixes beginning with a fixed first character.
def _pow_worker(args: Tuple[str, bytes, bytes]) -> Optional[str]:
    first, suffix, target_digest = args
    first_b = first.encode()
    alphabet_b = ALPHABET.encode()
    for b1 in alphabet_b:
        for b2 in alphabet_b:
            for b3 in alphabet_b:
                prefix = first_b + bytes((b1, b2, b3))
                if hashlib.sha256(prefix + suffix).digest() == target_digest:
                    return prefix.decode()
    return None


def solve_pow(suffix: str, target_hex: str, workers: int) -> str:
    suffix_b = suffix.encode()
    target_digest = bytes.fromhex(target_hex)
    tasks = [(c, suffix_b, target_digest) for c in ALPHABET]

    if workers <= 1:
        for task in tasks:
            result = _pow_worker(task)
            if result is not None:
                return result
        raise RuntimeError("PoW prefix was not found")

    pool = mp.Pool(processes=workers)
    try:
        for result in pool.imap_unordered(_pow_worker, tasks, chunksize=1):
            if result is not None:
                pool.terminate()
                pool.join()
                return result
    finally:
        # Safe even when terminate() has already been called.
        try:
            pool.close()
            pool.join()
        except Exception:
            pass
    raise RuntimeError("PoW prefix was not found")


def parse_point(value):
    return E(value)


def point_literal(point):
    if point == O:
        return 0
    x, y = point.xy()
    return int(x), int(y)


def oracle(R, Y, phi: CurveHomomorphism) -> int:
    data = str(R).encode() + str(Y).encode() + str(phi).encode()
    return int(hashlib.sha256(data).hexdigest(), 16) % CURVE_ORDER


def build_forgery(crs_raw, st):
    if len(crs_raw) != N:
        raise ValueError(f"expected {N} CRS points, got {len(crs_raw)}")

    crs = [parse_point(point) for point in crs_raw]
    a, b = st
    if len(a) != N or len(b) != N:
        raise ValueError("invalid RLWE statement dimensions")

    # Select s_i = e_i = -1. Their encodings are s_i+1=e_i+1=0,
    # therefore every bit commitment and every bit witness is zero.
    aux_s = [[O, O] for _ in range(N)]
    aux_e = [[O, O] for _ in range(N)]

    # For all-(-1) s, cyclic convolution has the same coefficient everywhere:
    #   (a * s)_i = -sum_j a_j.
    # The verifier checks, in the EC scalar field,
    #   (a*s)_i = 3329*k_i + b_i - e_i.
    # Hence:
    #   k_i = (-sum(a) - b_i - 1) / 3329 mod curve_order.
    a_sum = sum(int(x) for x in a)
    inv_3329 = int(inverse_mod(RLWE_Q, CURVE_ORDER))
    k = [
        ((-a_sum - int(b_i) - 1) * inv_3329) % CURVE_ORDER
        for b_i in b
    ]
    aux_k = [k_i * crs_i for k_i, crs_i in zip(k, crs)]

    # Proof 0 and proof 1 use the all-zero witness and all-zero nonce.
    # R=0 and z=0 verify for any Fiat-Shamir challenge.
    proof_s_R = [O] * (1 + 4 * N)
    proof_s_z = [0] * (2 * N)
    proof_e_R = [O] * (4 * N)
    proof_e_z = [0] * (2 * N)

    # Proof 2 is a diagonal discrete-log relation aux_k[i] = k_i * crs[i].
    # Use nonce r=0, so R=0 and z=c*k.
    phi_k = CurveHomomorphism([
        [O] * i + [crs[i]] + [O] * (N - i - 1)
        for i in range(N)
    ])
    proof_k_R = [O] * N
    challenge = oracle(proof_k_R, aux_k, phi_k)
    proof_k_z = [(challenge * k_i) % CURVE_ORDER for k_i in k]

    aux_wire = [
        [[point_literal(p) for p in row] for row in aux_s],
        [[point_literal(p) for p in row] for row in aux_e],
        [point_literal(p) for p in aux_k],
    ]
    proof_wire = [
        ([point_literal(p) for p in proof_s_R], proof_s_z),
        ([point_literal(p) for p in proof_e_R], proof_e_z),
        ([point_literal(p) for p in proof_k_R], proof_k_z),
    ]
    return aux_wire, proof_wire


def extract_assignment(line: bytes, prefix: bytes):
    if prefix not in line:
        raise ValueError(f"missing {prefix!r} in line")
    return ast.literal_eval(line.split(prefix, 1)[1].decode().strip())


def run_remote(host: str, port: int, workers: int) -> int:
    io = Tube(host, port)

    pow_prompt = io.recvuntil(b"XXXX>")
    match = re.search(
        rb"sha256\(XXXX \+ ([A-Za-z0-9]+)\) == ([0-9a-fA-F]{64})",
        pow_prompt,
    )
    if not match:
        raise RuntimeError(f"failed to parse PoW prompt:\n{pow_prompt.decode(errors='replace')}")

    suffix = match.group(1).decode()
    target = match.group(2).decode()
    print(f"[*] solving PoW with {workers} worker(s)", flush=True)
    prefix = solve_pow(suffix, target, workers)
    print(f"[+] PoW: {prefix}", flush=True)
    io.sendline(prefix)

    io.recvuntil(b">")
    io.sendline("c")
    io.recvuntil(b"crs = ")
    crs_raw = ast.literal_eval(io.recvline().decode().strip())
    print(f"[+] received CRS ({len(crs_raw)} points)", flush=True)

    io.recvuntil(b">")
    io.sendline("r")
    io.recvuntil(b"st = ")
    st = ast.literal_eval(io.recvline().decode().strip())
    print("[+] received RLWE statement", flush=True)

    aux, proof = build_forgery(crs_raw, st)
    print("[+] forged auxiliary commitments and sigma proofs", flush=True)

    io.recvuntil(b">")
    io.sendline("p")
    io.recvuntil(b"aux>")
    io.sendline(repr(aux))
    io.recvuntil(b"proof>")
    io.sendline(repr(proof))

    response = io.recvall()
    text = response.decode(errors="replace")
    print(text, end="" if text.endswith("\n") else "\n")

    flag_match = re.search(rb"[A-Za-z0-9_]+\{[^\r\n}]*\}", response)
    if flag_match:
        flag = flag_match.group(0).decode()
        print(f"<FLAG>{flag}</FLAG>")
        return 0

    print("[-] no flag found in server response", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Solver for Crypto / Inside")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(8, os.cpu_count() or 1)),
        help="PoW worker processes (default: up to 8)",
    )
    args = parser.parse_args()
    return run_remote(args.host, args.port, max(1, args.workers))


if __name__ == "__main__":
    raise SystemExit(main())
