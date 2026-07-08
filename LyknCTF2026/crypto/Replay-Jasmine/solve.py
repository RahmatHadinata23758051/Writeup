#!/usr/bin/env python3
"""Solver for LYKN CTF - Replay-Jasmine?

Dependencies:
    pip install sympy fpylll cysignals scrypt

The `scrypt` package is optional. When its private `_scrypt` extension is not
available, the solver falls back to hashlib.scrypt, which is considerably
slower for p=4000.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import multiprocessing as mp
import os
import struct
import sys
from pathlib import Path
from typing import Iterable, Sequence

from fpylll import CVP, LLL, IntegerMatrix
from sympy import Matrix
from sympy.matrices.normalforms import hermite_normal_form

try:
    from _aux import Shiina256PIGE
except ImportError as exc:
    raise SystemExit("[-] Put solve.py beside _aux.py") from exc


def centered(value: int, modulus: int) -> int:
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def solve_modular_system(
    matrix: Sequence[Sequence[int]],
    target: Sequence[int],
    modulus: int,
) -> list[int]:
    """Solve A*x = target (mod prime modulus) with modular Gaussian elimination."""
    rows = len(matrix)
    cols = len(matrix[0])
    aug = [
        [int(matrix[i][j]) % modulus for j in range(cols)]
        + [int(target[i]) % modulus]
        for i in range(rows)
    ]

    pivot_row = 0
    pivots: list[int] = []

    for col in range(cols):
        pivot = next(
            (row for row in range(pivot_row, rows) if aug[row][col] % modulus),
            None,
        )
        if pivot is None:
            continue

        aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]
        inv = pow(aug[pivot_row][col], -1, modulus)
        aug[pivot_row] = [(value * inv) % modulus for value in aug[pivot_row]]

        for row in range(rows):
            if row == pivot_row:
                continue
            factor = aug[row][col] % modulus
            if factor:
                aug[row] = [
                    (aug[row][j] - factor * aug[pivot_row][j]) % modulus
                    for j in range(cols + 1)
                ]

        pivots.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break

    if len(pivots) != cols:
        raise ValueError(f"matrix rank is {len(pivots)}, expected {cols}")

    solution = [0] * cols
    for row, col in enumerate(pivots):
        solution[col] = aug[row][-1]
    return solution


def recover_lwe_secret(
    matrix: Sequence[Sequence[int]],
    target: Sequence[int],
    modulus: int,
) -> tuple[list[int], list[int]]:
    """Recover a small LWE secret through a q-ary lattice CVP attack."""
    a = Matrix(matrix)
    b = [int(value) for value in target]
    rows, cols = a.shape

    # Column lattice Λ = {A*s + q*z}.  HNF gives a square column basis.
    generators = Matrix.hstack(modulus * Matrix.eye(rows), a)
    column_basis = hermite_normal_form(generators)
    row_basis = column_basis.T

    lattice = IntegerMatrix.from_matrix(
        [[int(row_basis[i, j]) for j in range(rows)] for i in range(rows)]
    )
    LLL.reduction(lattice, delta=0.99)

    closest = list(CVP.closest_vector(lattice, b))
    error = [b[i] - int(closest[i]) for i in range(rows)]

    residues = solve_modular_system(matrix, closest, modulus)
    secret = [centered(value, modulus) for value in residues]

    # Independent validation against the original samples.
    checked_error = []
    for i in range(rows):
        residue = (
            b[i]
            - sum(int(matrix[i][j]) * secret[j] for j in range(cols))
        ) % modulus
        checked_error.append(centered(residue, modulus))

    if checked_error != error:
        raise ValueError("CVP result failed the LWE residual check")

    return secret, error


# Globals initialized in each multiprocessing worker.
_SCRYPT_LIB = None
_SMIX = None
_LIBC = None
_V = None
_XY = None
_SCRYPT_N = 0
_SCRYPT_R = 0


def _aligned_alloc(size: int, alignment: int = 64) -> ctypes.c_void_p:
    pointer = ctypes.c_void_p()
    result = _LIBC.posix_memalign(ctypes.byref(pointer), alignment, size)
    if result:
        raise OSError(result, "posix_memalign failed")
    return pointer


def _init_scrypt_worker(n: int, r: int, extension_path: str) -> None:
    global _SCRYPT_LIB, _SMIX, _LIBC, _V, _XY, _SCRYPT_N, _SCRYPT_R

    _SCRYPT_N = n
    _SCRYPT_R = r
    _SCRYPT_LIB = ctypes.CDLL(extension_path)
    _SMIX = _SCRYPT_LIB.crypto_scrypt_smix
    _SMIX.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _SMIX.restype = None

    _LIBC = ctypes.CDLL(None)
    _LIBC.posix_memalign.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_size_t,
        ctypes.c_size_t,
    ]
    _LIBC.posix_memalign.restype = ctypes.c_int
    _LIBC.free.argtypes = [ctypes.c_void_p]
    _LIBC.free.restype = None

    block_size = 128 * r
    _V = _aligned_alloc(n * block_size)
    _XY = _aligned_alloc(256 * r + 64)


def _romix_block(item: tuple[int, bytes]) -> tuple[int, bytes]:
    index, block = item
    pointer = _aligned_alloc(len(block))
    try:
        ctypes.memmove(pointer, block, len(block))
        _SMIX(pointer, _SCRYPT_R, _SCRYPT_N, _V, _XY)
        return index, ctypes.string_at(pointer, len(block))
    finally:
        _LIBC.free(pointer)


def parallel_scrypt(
    password: bytes,
    salt: bytes,
    n: int,
    r: int,
    p: int,
    dklen: int,
    workers: int,
) -> bytes:
    """RFC 7914 scrypt with independent ROMix blocks distributed to workers."""
    spec = importlib.util.find_spec("_scrypt")
    if spec is None or not spec.origin:
        print("[!] _scrypt extension unavailable; using slower hashlib.scrypt")
        return hashlib.scrypt(
            password,
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=2**31 - 1,
        )

    block_size = 128 * r
    initial = hashlib.pbkdf2_hmac(
        "sha256", password, salt, 1, dklen=p * block_size
    )
    items = (
        (index, initial[index * block_size : (index + 1) * block_size])
        for index in range(p)
    )

    workers = max(1, min(workers, p, os.cpu_count() or 1))
    context = mp.get_context("fork")
    chunksize = max(1, p // (workers * 8))

    with context.Pool(
        workers,
        initializer=_init_scrypt_worker,
        initargs=(n, r, spec.origin),
    ) as pool:
        mixed = list(pool.imap_unordered(_romix_block, items, chunksize=chunksize))

    mixed.sort(key=lambda pair: pair[0])
    final_blocks = b"".join(block for _, block in mixed)
    return hashlib.pbkdf2_hmac(
        "sha256", password, final_blocks, 1, dklen=dklen
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge", nargs="?", default="chall.json")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    challenge_path = Path(args.challenge)
    data = json.loads(challenge_path.read_text())

    secret_1, error_1 = recover_lwe_secret(
        data["Alcginlcgchall"], data["donttimebabybob"], 769
    )
    secret_2, error_2 = recover_lwe_secret(data["timeforR"], data["c"], 503)

    print(f"[+] secret 1: {secret_1}")
    print(f"[+] error 1 range: [{min(error_1)}, {max(error_1)}]")
    print(f"[+] secret 2: {secret_2}")
    print(f"[+] error 2 range: [{min(error_2)}, {max(error_2)}]")

    all_coefficients = secret_1 + secret_2
    password = struct.pack(f"<{len(all_coefficients)}i", *all_coefficients)

    kdf = data["kdf"]
    salt = bytes.fromhex(kdf["eww_too_salty"])
    master_key = parallel_scrypt(
        password=password,
        salt=salt,
        n=int(kdf["subset_sum_problem?"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
        dklen=int(kdf["dklen"]),
        workers=args.workers,
    )

    print(f"[+] master key: {master_key.hex()}")
    plaintext = Shiina256PIGE(master_key).decrypt(bytes.fromhex(data["finally"]))
    decoded = plaintext.decode()
    print(f"[+] plaintext: {decoded}")
    print(f"<FLAG>{decoded}</FLAG>")


if __name__ == "__main__":
    main()
