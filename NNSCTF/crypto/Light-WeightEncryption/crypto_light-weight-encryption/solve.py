#!/usr/bin/env python3
import os
import sys

# Sympy bisa kena assertion internal pas LLL, jadi rerun pakai -O
if __debug__:
    os.execv(sys.executable, [sys.executable, "-O"] + sys.argv)

import random
from pathlib import Path
from math import gcd

import sympy as sp

q = 2**768
n, m, w = 16, 112, 130


def long_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def centered(x: int) -> int:
    x %= q
    if x >= q // 2:
        x -= q
    return int(x)


def load_output(path="output.py"):
    ns = {}
    exec(Path(path).read_text(), {}, ns)
    A_flat, B = ns["pk"]
    C, D = ns["ct"]
    A = [list(map(int, A_flat[i * n : (i + 1) * n])) for i in range(m)]
    return A, list(map(int, B)), list(map(int, C)), int(D)


def null_relation(A, idxs):
    # Cari integer c dengan sum(c_i * A[idx_i]) = 0
    mat = sp.Matrix([[A[j][col] for j in idxs] for col in range(n)])
    ns = mat.nullspace()
    if not ns:
        return None

    vec = ns[0]
    den = 1
    for x in vec:
        den = sp.ilcm(den, int(x.q))

    coeff = [int(x * den) for x in vec]
    g = 0
    for c in coeff:
        g = gcd(g, abs(c))
    coeff = [c // g for c in coeff]

    for c in coeff:
        if c:
            if c < 0:
                coeff = [-x for x in coeff]
            break
    return coeff


def build_relations(A, B, total=80, seed=1):
    random.seed(seed)
    rels, seen = [], set()

    while len(rels) < total:
        idxs = tuple(sorted(random.sample(range(m), n + 1)))
        if idxs in seen:
            continue
        seen.add(idxs)

        coeff = null_relation(A, idxs)
        if coeff is None:
            continue

        assert all(
            sum(coeff[k] * A[idxs[k]][col] for k in range(n + 1)) == 0
            for col in range(n)
        )

        v = sum(coeff[k] * B[idxs[k]] for k in range(n + 1)) % q
        rels.append((max(abs(c) for c in coeff).bit_length(), idxs, coeff, v))

    rels.sort(key=lambda r: r[0])
    return rels


def recover_sk(rels):
    # Untuk relation uA = 0:
    #   uB = k * (ue) mod q
    #
    # Kalau dikali sk:
    #   sk * uB = p * (ue) mod q
    #
    # Nilainya kecil secara centered residue.
    # Ini jadi Hidden Number Problem sederhana, diselesaikan pakai LLL.
    for dim in (8, 10, 12, 14):
        samples = rels[:dim]
        max_coeff_bits = max(r[0] for r in samples)
        residue_bits = max_coeff_bits + 5 + 32 + 520 + 3
        scale = 2 ** max(1, residue_bits - 128)

        basis = []

        for i in range(dim):
            row = [0] * (dim + 1)
            row[i] = q
            basis.append(row)

        basis.append([r[3] for r in samples] + [scale])

        reduced = sp.Matrix(basis).lll()

        for row in reduced.tolist():
            last = int(row[-1])
            if last == 0 or last % scale != 0:
                continue

            cand = abs(last) // scale
            if not (2**120 < cand < 2**130):
                continue

            max_res_bits = max(
                abs(centered(cand * r[3])).bit_length()
                for r in samples
            )

            if max_res_bits <= residue_bits + 8:
                return cand

    raise RuntimeError("failed to recover sk")


def recover_p(sk, rels):
    g = 0

    for _, _, _, v in rels:
        g = gcd(g, abs(centered(sk * v)))

    if sp.isprime(g):
        return int(g)

    # Fallback kalau gcd kebawa faktor kecil accidental
    factors = sp.factorint(g, limit=1_000_000)
    big = [int(f) ** e for f, e in factors.items() if int(f).bit_length() > 400]

    if big:
        return max(big)

    raise RuntimeError("failed to isolate p")


def short_linear_solution(A, C):
    # Cari x kecil dengan:
    #   sum x_i = 130
    #   sum x_i * A_i = C
    #
    # Entry negatif tetap aman karena noise masih jauh di bawah q.
    cols = [[1] + [A[i][col] for col in range(n)] for i in range(m)]
    target = [w] + C

    for Q in (20, 10, 30, 50, 100):
        rows = []

        for i in range(m):
            row = [0] * (m + n + 1)
            row[i] = 1

            for j in range(n + 1):
                row[m + j] = Q * cols[i][j]

            rows.append(row)

        target_row = [0] * (m + n + 1)

        for j in range(n + 1):
            target_row[m + j] = Q * target[j]

        rows.append(target_row)

        reduced = sp.Matrix(rows).lll()

        for row in reduced.tolist():
            x = [int(v) for v in row[:m]]

            diff = [
                sum(x[i] * cols[i][j] for i in range(m)) - target[j]
                for j in range(n + 1)
            ]

            diff_neg = [
                sum(x[i] * cols[i][j] for i in range(m)) + target[j]
                for j in range(n + 1)
            ]

            if all(v == 0 for v in diff):
                return x

            if all(v == 0 for v in diff_neg):
                return [-v for v in x]

    raise RuntimeError("failed to find short x")


def decrypt(A, B, C, D, sk, p, x):
    assert sum(x) == w

    assert all(
        sum(x[i] * A[i][col] for i in range(m)) == C[col]
        for col in range(n)
    )

    masked = (D + sum(x[i] * B[i] for i in range(m))) % q
    small = centered(sk * masked)

    flag_int = (small % p) * pow(sk, -1, p) % p
    return long_to_bytes(flag_int)


def main():
    A, B, C, D = load_output()

    rels = build_relations(A, B)

    sk = recover_sk(rels)
    p = recover_p(sk, rels)

    x = short_linear_solution(A, C)

    flag = decrypt(A, B, C, D, sk, p, x)
    print(f"<FLAG>{flag.decode()}</FLAG>")


if __name__ == "__main__":
    main()
