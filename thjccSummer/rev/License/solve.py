#!/usr/bin/env python3
"""Solver for the License REV challenge.

No external dependencies are required. The script reconstructs the affine
4-round validator, solves the resulting GF(2) system, filters candidates by
the original hexadecimal input alphabet, rebuilds the dashed license, then
decodes the success-path flag blob.
"""

from __future__ import annotations

import os
import subprocess

N = 24

# .rodata @ 0x2001f0: order used before the per-byte pre-transform.
PERM = [
    0x07, 0x00, 0x13, 0x04, 0x0C, 0x17, 0x02, 0x10,
    0x09, 0x05, 0x15, 0x0B, 0x01, 0x0E, 0x12, 0x06,
    0x14, 0x03, 0x0F, 0x0A, 0x08, 0x16, 0x0D, 0x11,
]

# Final 24-byte validator target from comparisons at 0x201a34..0x201bba.
TARGET = bytes.fromhex(
    "95540c2f5ac7a99fbca49ad296c32d883a578bad1d2f2b46"
)

# Low byte selected from each 32-bit round constant according to i % 4.
ROUND_KEYS = [
    [0xDF, 0x9B, 0x57, 0x13],  # 0x13579bdf
    [0xE0, 0xAC, 0x68, 0x24],  # 0x2468ace0
    [0x0D, 0xF0, 0xAD, 0x0B],  # 0x0badf00d
    [0xAA, 0x55, 0xAA, 0x55],  # 0x55aa55aa
]

# Success-path encoded bytes from .rodata @ 0x200210.
FLAG_BLOB = bytes.fromhex(
    "2536c1dbe6c9d3a5ba839d736845575d312b37011be7d0eeccd4b6b9b19e8a"
)

HEX_CHARS = b"0123456789ABCDEFabcdef"


def rol8(x: int, r: int) -> int:
    r &= 7
    if not r:
        return x & 0xFF
    return ((x << r) | (x >> (8 - r))) & 0xFF


def pre_transform_byte(c: int, j: int) -> int:
    """Per-byte transform applied after the 24-byte permutation.

    Recovered from the vectorized block at 0x201410..0x2016e5 and the scalar
    tail at 0x2016eb..0x201766.
    """
    xor_key = (0x31 + 0x11 * j) & 0xFF
    add_key = (0x0B * j) & 0xFF
    return (rol8(c ^ xor_key, j % 5) + add_key) & 0xFF


def round_transform(state: list[int], r: int) -> list[int]:
    """One of the four affine validator rounds."""
    out = [0] * N
    for i in range(N):
        v = state[i] ^ state[(i + 7) % N]
        v ^= (i + 0x1D * r) & 0xFF
        v ^= ROUND_KEYS[r][i % 4]
        out[i] = rol8(v, (i + r) % 7)
    return out


def pipeline(state: list[int]) -> list[int]:
    state = list(state)
    for r in range(4):
        state = round_transform(state, r)
    return state


def pack_le_bits(bs: list[int] | bytes) -> int:
    """Pack byte/bit index i*8+j into bit position i*8+j of an integer."""
    out = 0
    for i, b in enumerate(bs):
        out |= int(b) << (8 * i)
    return out


def build_affine_system() -> tuple[list[list[int]], int]:
    """Build A*x=b for the 192 input bits of the 4-round pipeline."""
    zero = pipeline([0] * N)
    zero_int = pack_le_bits(zero)
    rhs_int = pack_le_bits(TARGET) ^ zero_int

    # Each column is the output delta caused by toggling one input bit.
    columns: list[int] = []
    for bit in range(N * 8):
        state = [0] * N
        state[bit // 8] = 1 << (bit % 8)
        out = pipeline(state)
        delta = [a ^ b for a, b in zip(out, zero)]
        columns.append(pack_le_bits(delta))

    rows: list[list[int]] = []
    for out_bit in range(N * 8):
        coeff = 0
        for var, column in enumerate(columns):
            if (column >> out_bit) & 1:
                coeff |= 1 << var
        rows.append([coeff, (rhs_int >> out_bit) & 1])
    return rows, N * 8


def rref_gf2(rows: list[list[int]], nvars: int):
    """Reduced row-echelon form over GF(2)."""
    row = 0
    pivots: list[int] = []

    for col in range(nvars):
        pivot = None
        for rr in range(row, len(rows)):
            if (rows[rr][0] >> col) & 1:
                pivot = rr
                break
        if pivot is None:
            continue

        rows[row], rows[pivot] = rows[pivot], rows[row]
        pcoeff, prhs = rows[row]

        for rr in range(len(rows)):
            if rr != row and ((rows[rr][0] >> col) & 1):
                rows[rr][0] ^= pcoeff
                rows[rr][1] ^= prhs

        pivots.append(col)
        row += 1

    for coeff, rhs in rows:
        if coeff == 0 and rhs:
            raise RuntimeError("validator equations are inconsistent")

    return rows, pivots


def solve_license() -> str:
    rows, nvars = build_affine_system()
    rows, pivots = rref_gf2(rows, nvars)
    pivot_set = set(pivots)
    free = [i for i in range(nvars) if i not in pivot_set]

    # The recovered system has rank 178 -> 14 free bits -> only 16384 states.
    if len(free) != 14:
        raise RuntimeError(f"unexpected nullity: {len(free)}")

    pivot_rows = {pivots[i]: rows[i] for i in range(len(pivots))}

    particular = 0
    for p, (_, rhs) in pivot_rows.items():
        if rhs:
            particular |= 1 << p

    basis: list[int] = []
    for f in free:
        v = 1 << f
        for p, (coeff, _) in pivot_rows.items():
            if (coeff >> f) & 1:
                v |= 1 << p
        basis.append(v)

    # Allowed pre-transform byte -> original ASCII character for each position.
    domains: list[dict[int, int]] = []
    for j in range(N):
        domains.append({pre_transform_byte(c, j): c for c in HEX_CHARS})

    matches: list[str] = []
    for mask in range(1 << len(free)):
        x = particular
        for k, basis_vec in enumerate(basis):
            if (mask >> k) & 1:
                x ^= basis_vec

        transformed = [(x >> (8 * i)) & 0xFF for i in range(N)]
        if not all(transformed[j] in domains[j] for j in range(N)):
            continue

        permuted_chars = [domains[j][transformed[j]] for j in range(N)]
        raw = [0] * N
        for j, c in enumerate(permuted_chars):
            raw[PERM[j]] = c

        raw_text = bytes(raw).decode("ascii")
        license_text = "-".join(raw_text[i:i + 4] for i in range(0, N, 4))
        matches.append(license_text)

    if len(matches) != 1:
        raise RuntimeError(f"expected one valid license, got {len(matches)}")

    return matches[0]


def validate_license_locally(license_text: str) -> bool:
    """Pure-Python reproduction of the binary's core validation path."""
    if len(license_text) != 29:
        return False
    if any(license_text[i] != "-" for i in (4, 9, 14, 19, 24)):
        return False

    raw = license_text.replace("-", "")
    if len(raw) != 24 or any(ord(c) not in HEX_CHARS for c in raw):
        return False

    permuted = [ord(raw[idx]) for idx in PERM]
    state = [pre_transform_byte(c, j) for j, c in enumerate(permuted)]
    return bytes(pipeline(state)) == TARGET


def decode_flag() -> str:
    out = bytearray()
    cl = 0x7E

    for j in range(0, len(FLAG_BLOB), 2):
        out.append(FLAG_BLOB[j] ^ ((cl - 0x0D) & 0xFF))
        if j + 1 < len(FLAG_BLOB):
            out.append(FLAG_BLOB[j + 1] ^ cl)
        cl = (cl + 0x1A) & 0xFF

    return out.decode("ascii")


def main() -> None:
    license_text = solve_license()
    flag = decode_flag()

    assert validate_license_locally(license_text)

    print(f"[+] license: {license_text}")
    print(f"[+] decoded success flag: {flag}")

    binary = os.path.join(os.path.dirname(__file__), "license_v2")
    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        proc = subprocess.run(
            [binary, license_text],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        binary_output = proc.stdout.strip()
        print(f"[+] binary output: {binary_output}")
        print(f"[+] binary exit code: {proc.returncode}")
        if proc.returncode != 0 or binary_output != flag:
            raise RuntimeError("binary verification failed")

    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
