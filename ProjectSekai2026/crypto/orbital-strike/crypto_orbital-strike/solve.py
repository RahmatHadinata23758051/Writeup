#!/usr/bin/env python3
"""Solver for SEKAI CTF 2026 Crypto - orbital-strike.

Dependencies:
    pip install pycryptodome sympy fpylll cysignals
"""

from __future__ import annotations

import itertools
import math
import re
from dataclasses import dataclass

import sympy as sp
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fpylll import IntegerMatrix, LLL

ORBIT = [
    46157012221654917396851254347154820393060391878580715960476654689260395468184,
    36926194633341127588542680684095293820802193681748458943524916140809713523560,
    16005201943847263206512436577001283414470030273089746675203830598137794555134,
    28937919714389596084610407023450127584695575606301484773390370819366639643218,
    11459012353705334109041842799942754581703065868230253271729711591416155557180,
    31030059279554219046464541926833857543445131889728181065565033726460506326840,
    20987315604501021667042879662101693092441980938033961081037347214532349371248,
    76741461130245451493723909055453557280102065396647043801270629949855565452326,
    84258885183671683674472390974667571532577240974449641001706593550302243268268,
    59535034089467707172052245359810812420431903279354584714432674122159502991956,
    7115679899033391144975170596669540596311296590450661546000723388170577963715,
    35572951991838484594163260879328705523576344587262461128887804475450813563036,
    85569022704397114858282741078883377190544624744955636482627379979792474136036,
    5047270986830280372910174287287823507537624765267582560460157826800286170460,
]
STAR = bytes.fromhex(
    "1664ff83cbca2643b357bcdc8c3d6e15"
    "48615a18cec73e734a82e163b32a9b0c"
    "367c61bab01140a04ac8eda8b007d1d6"
)


@dataclass(frozen=True)
class Recovered:
    P: int
    p: int
    A: int
    a: int
    b: int
    X: int
    moons: tuple[int, ...]
    flag: bytes


def vector_bits(v: list[int]) -> int:
    return max((abs(x).bit_length() for x in v), default=0)


def build_public_kernel(differences: list[int]) -> list[list[int]]:
    """Find short polynomials annihilating three shifted orbit-difference windows."""
    n_windows = 11
    shifts = 3
    scale = 1 << 512

    basis = IntegerMatrix(n_windows, n_windows + shifts)
    for i in range(n_windows):
        for j in range(shifts):
            basis[i, j] = scale * differences[i + j]
        basis[i, shifts + i] = 1

    LLL.reduction(basis, delta=0.999)

    rows: list[list[int]] = []
    for row in range(n_windows):
        prefix = [int(basis[row, j]) for j in range(shifts)]
        coeffs = [int(basis[row, shifts + i]) for i in range(n_windows)]
        if prefix == [0, 0, 0]:
            rows.append(coeffs)

    rows.sort(key=lambda v: (vector_bits(v), sum(x * x for x in v)))
    if len(rows) < 6:
        raise RuntimeError("failed to recover enough exact public-kernel vectors")
    return rows


def prime_factor_with_bits(value: int, bits: int) -> int | None:
    value = abs(value)
    if value <= 1:
        return None
    if value.bit_length() == bits and sp.isprime(value):
        return value

    # In this instance the cofactor is tiny. A bounded factorization strips it
    # and leaves the 311-bit prime intact.
    factors = sp.factorint(value, limit=100_000)
    for factor in factors:
        q = int(factor)
        if q.bit_length() == bits and sp.isprime(q):
            return q
    return None


def recover_inner_parameters(kernel_rows: list[list[int]]) -> tuple[int, int, list[list[int]]]:
    """Recover inner modulus p and multiplier a from polynomial resultants."""
    x = sp.symbols("x")
    polynomials = [
        sp.Poly(sum(c * x**i for i, c in enumerate(row)), x, domain=sp.ZZ)
        for row in kernel_rows
    ]

    p: int | None = None
    selected_count = 0

    # The true relations form the visibly short prefix of the reduced basis.
    # Their pairwise resultants all contain the same 311-bit prime.
    for take in range(3, len(polynomials) + 1):
        common = 0
        for i, j in itertools.combinations(range(take), 2):
            resultant = abs(int(sp.resultant(polynomials[i], polynomials[j], x)))
            common = math.gcd(common, resultant)
        candidate = prime_factor_with_bits(common, 311)
        if candidate is not None:
            p = candidate
            selected_count = take
            break

    if p is None:
        raise RuntimeError("311-bit common resultant factor was not found")

    polynomial_gcd = sp.Poly(polynomials[0], modulus=p)
    for poly in polynomials[1:selected_count]:
        polynomial_gcd = sp.gcd(polynomial_gcd, sp.Poly(poly, modulus=p))

    if polynomial_gcd.degree() != 1:
        raise RuntimeError(f"unexpected polynomial gcd degree: {polynomial_gcd.degree()}")

    leading, constant = [int(c) % p for c in polynomial_gcd.all_coeffs()]
    a = (-constant * pow(leading, -1, p)) % p

    good_rows = [
        row
        for row in kernel_rows
        if sum(c * pow(a, i, p) for i, c in enumerate(row)) % p == 0
    ]
    good_rows.sort(key=lambda v: (vector_bits(v), sum(x * x for x in v)))
    if len(good_rows) < 6:
        raise RuntimeError("not enough inner-LCG annihilators after root validation")

    # Six independent relations are enough for the shifted block kernel.
    return p, a, good_rows[:6]


def orthogonal_kernel(relations: list[list[int]]) -> list[list[int]]:
    """Compute the 3-dimensional integer kernel of shifted relations."""
    block_rows: list[list[int]] = []
    for relation in relations:
        block_rows.append(relation + [0])
        block_rows.append([0] + relation)

    dimension = 12
    scale = 1 << 1024
    embedded = IntegerMatrix(dimension, dimension * 2)

    # A vector z is orthogonal to every block row iff the scaled prefix is 0.
    for i in range(dimension):
        for j in range(dimension):
            embedded[i, j] = scale * block_rows[j][i]
        embedded[i, dimension + i] = 1

    LLL.reduction(embedded, delta=0.999)

    vectors: list[list[int]] = []
    for row in range(dimension):
        prefix = [int(embedded[row, j]) for j in range(dimension)]
        if all(x == 0 for x in prefix):
            vectors.append([int(embedded[row, dimension + j]) for j in range(dimension)])

    if len(vectors) != 3:
        raise RuntimeError(f"unexpected shifted-kernel rank: {len(vectors)}")
    return vectors


def nullspace_mod_prime(matrix: list[list[int]], modulus: int) -> list[list[int]]:
    """Reduced-row-echelon nullspace over F_modulus."""
    work = [[x % modulus for x in row] for row in matrix]
    row_count = len(work)
    col_count = len(work[0])
    pivots: list[int] = []
    pivot_row = 0

    for column in range(col_count):
        selected = next(
            (r for r in range(pivot_row, row_count) if work[r][column] != 0),
            None,
        )
        if selected is None:
            continue

        work[pivot_row], work[selected] = work[selected], work[pivot_row]
        inverse = pow(work[pivot_row][column], -1, modulus)
        work[pivot_row] = [(x * inverse) % modulus for x in work[pivot_row]]

        for r in range(row_count):
            if r == pivot_row or work[r][column] == 0:
                continue
            factor = work[r][column]
            work[r] = [
                (work[r][c] - factor * work[pivot_row][c]) % modulus
                for c in range(col_count)
            ]

        pivots.append(column)
        pivot_row += 1

    free_columns = [c for c in range(col_count) if c not in pivots]
    result: list[list[int]] = []
    for free in free_columns:
        vector = [0] * col_count
        vector[free] = 1
        for r, pivot in reversed(list(enumerate(pivots))):
            vector[pivot] = -sum(
                work[r][c] * vector[c] for c in free_columns
            ) % modulus
        result.append(vector)
    return result


def recover_moon_differences(p: int, a: int, relations: list[list[int]]) -> list[list[int]]:
    """Recover signed differences delta_2..delta_13 of the inner LCG."""
    kernel = orthogonal_kernel(relations)

    recurrence_matrix = [
        [
            (kernel[j][i + 1] - a * kernel[j][i]) % p
            for j in range(len(kernel))
        ]
        for i in range(11)
    ]
    coefficient_nullspace = nullspace_mod_prime(recurrence_matrix, p)
    if len(coefficient_nullspace) != 1:
        raise RuntimeError("inner recurrence did not leave a one-dimensional coefficient space")

    coefficient_vector = coefficient_nullspace[0]
    generators = [
        [
            sum(coefficient_vector[j] * kernel[j][i] for j in range(3))
            for i in range(12)
        ]
    ]
    for j in range(3):
        generators.append([p * kernel[j][i] for i in range(12)])

    lattice = IntegerMatrix(len(generators), 12)
    for i, row in enumerate(generators):
        for j, value in enumerate(row):
            lattice[i, j] = value
    LLL.reduction(lattice, delta=0.999)

    candidates: list[list[int]] = []
    seen: set[tuple[int, ...]] = set()
    for row in range(len(generators)):
        vector = [int(lattice[row, i]) for i in range(12)]
        if not any(vector):
            continue
        if max(abs(x) for x in vector) >= p:
            continue
        if not all((vector[i + 1] - a * vector[i]) % p == 0 for i in range(11)):
            continue

        for oriented in (vector, [-x for x in vector]):
            key = tuple(oriented)
            if key not in seen:
                seen.add(key)
                candidates.append(oriented)

    if not candidates:
        raise RuntimeError("no bounded moon-difference vector found")
    return candidates


def candidate_prime_factors(value: int, bits: int) -> list[int]:
    value = abs(value)
    if value <= 1:
        return []
    if value.bit_length() == bits and sp.isprime(value):
        return [value]
    return [
        int(q)
        for q in sp.factorint(value, limit=100_000)
        if int(q).bit_length() == bits and sp.isprime(int(q))
    ]


def interval_for_m2(p: int, delta1: int, later_deltas: list[int]) -> tuple[int, int]:
    """Return [lo, hi) such that all reconstructed moon states are in [0,p)."""
    offsets = [-delta1, 0]  # m1-m2, m2-m2
    cumulative = 0
    for delta in later_deltas:
        cumulative += delta
        offsets.append(cumulative)
    return max(-x for x in offsets), min(p - x for x in offsets)


def try_outer_recovery(
    p: int,
    a: int,
    moon_differences: list[int],
    orbit: list[int],
    ciphertext: bytes,
) -> Recovered | None:
    d = [orbit[i + 1] - orbit[i] for i in range(len(orbit) - 1)]

    # delta_n = d_n - A*d_(n-1) (mod P), n=2..13.
    left = [d[i + 1] - moon_differences[i] for i in range(12)]
    right = d[:12]

    common = 0
    for i, j in itertools.combinations(range(12), 2):
        common = math.gcd(common, abs(left[i] * right[j] - left[j] * right[i]))

    for P in candidate_prime_factors(common, 256):
        if P <= max(orbit):
            continue

        A: int | None = None
        for lhs, rhs in zip(left, right):
            if math.gcd(rhs, P) == 1:
                A = (lhs * pow(rhs, -1, P)) % P
                break
        if A is None or A == 0:
            continue
        if not all((lhs - A * rhs) % P == 0 for lhs, rhs in zip(left, right)):
            continue

        m2_residue = (orbit[1] - A * orbit[0]) % P
        delta1_residue = (pow(a, -1, p) * (moon_differences[0] % p)) % p

        for delta1 in (delta1_residue, delta1_residue - p):
            lo, hi = interval_for_m2(p, delta1, moon_differences)
            k_min = max(0, (lo - m2_residue + P - 1) // P)
            k_max = (hi - 1 - m2_residue) // P
            if k_min > k_max:
                continue

            # Any valid lift gives the same m1 modulo P and therefore the same X.
            m2 = m2_residue + k_min * P
            m1 = m2 - delta1
            moons = [m1, m2]
            for delta in moon_differences:
                moons.append(moons[-1] + delta)

            if len(moons) != 14 or not all(0 <= m < p for m in moons):
                continue

            b = (moons[1] - a * moons[0]) % p
            if not all(moons[i + 1] == (a * moons[i] + b) % p for i in range(13)):
                continue

            m1_mod_P = (m2_residue - delta1) % P
            X = ((orbit[0] - m1_mod_P) * pow(A, -1, P)) % P

            state = X
            regenerated: list[int] = []
            for moon in moons:
                state = (A * state + moon) % P
                regenerated.append(state)
            if regenerated != orbit:
                continue

            try:
                plaintext = unpad(
                    AES.new(X.to_bytes(32, "big"), AES.MODE_ECB).decrypt(ciphertext),
                    16,
                )
            except ValueError:
                continue

            if re.fullmatch(rb"[A-Za-z0-9_]+\{[^\r\n{}]+\}", plaintext) is None:
                continue

            return Recovered(P, p, A, a, b, X, tuple(moons), plaintext)

    return None


def solve(orbit: list[int], ciphertext: bytes) -> Recovered:
    if len(orbit) != 14:
        raise ValueError("the attack expects exactly 14 orbit outputs")

    differences = [orbit[i + 1] - orbit[i] for i in range(13)]
    public_kernel = build_public_kernel(differences)
    p, a, relations = recover_inner_parameters(public_kernel)
    delta_candidates = recover_moon_differences(p, a, relations)

    for candidate in delta_candidates:
        recovered = try_outer_recovery(p, a, candidate, orbit, ciphertext)
        if recovered is not None:
            return recovered
    raise RuntimeError("all recovered moon-difference orientations failed validation")


def main() -> None:
    recovered = solve(ORBIT, STAR)
    print(f"[+] p = {recovered.p}")
    print(f"[+] a = {recovered.a}")
    print(f"[+] P = {recovered.P}")
    print(f"[+] A = {recovered.A}")
    print(f"[+] X = {recovered.X}")
    print("[+] full orbit regeneration: valid")
    print(f"<FLAG>{recovered.flag.decode()}</FLAG>")


if __name__ == "__main__":
    main()
