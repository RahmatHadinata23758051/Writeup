#!/usr/bin/env python3
import json
import hashlib
from itertools import combinations
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

P = 79
V = 4
O = 4
N = 8

def inv(a):
    return pow(a, -1, P)

def mod(x):
    return x % P

def solve_linear(A, b):
    """
    Solve A x = b over GF(P).
    A: m x n
    b: m
    Returns one solution or None.
    """
    m = len(A)
    n = len(A[0])
    aug = [row[:] + [bb % P] for row, bb in zip(A, b)]

    row = 0
    pivots = []

    for col in range(n):
        pivot = None
        for r in range(row, m):
            if aug[r][col] % P != 0:
                pivot = r
                break

        if pivot is None:
            continue

        aug[row], aug[pivot] = aug[pivot], aug[row]

        inv_pivot = inv(aug[row][col])
        for c in range(col, n + 1):
            aug[row][c] = aug[row][c] * inv_pivot % P

        for r in range(m):
            if r != row and aug[r][col] % P != 0:
                factor = aug[r][col]
                for c in range(col, n + 1):
                    aug[r][c] = (aug[r][c] - factor * aug[row][c]) % P

        pivots.append(col)
        row += 1

        if row == m:
            break

    for r in range(row, m):
        if all(aug[r][c] % P == 0 for c in range(n)) and aug[r][n] % P != 0:
            return None

    if len(pivots) < n:
        return None

    x = [0] * n
    for r, col in enumerate(pivots):
        x[col] = aug[r][n] % P

    return x

def split_poly(poly):
    const = poly["const"]
    linear = poly["linear"]

    q_vv = {}
    q_vo = {}

    for i, j, c in poly["quad"]:
        if i < V and j < V:
            q_vv[(i, j)] = c
        elif i < V and j >= V:
            q_vo[(i, j - V)] = c
        else:
            raise ValueError("Unexpected oil-oil term")

    return const, linear, q_vv, q_vo

def build_linear_system(polys, target, vinegar):
    """
    After fixing x0..x3, every equation becomes linear in x4..x7.
    A * oils = b
    """
    A = []
    b = []

    for poly, t in zip(polys, target):
        const, linear, q_vv, q_vo = split_poly(poly)

        value = const

        for i in range(V):
            value += linear[i] * vinegar[i]

        for (i, j), c in q_vv.items():
            value += c * vinegar[i] * vinegar[j]

        value %= P

        row = []

        for oil_idx in range(O):
            coeff = linear[V + oil_idx]

            for i in range(V):
                coeff += q_vo.get((i, oil_idx), 0) * vinegar[i]

            row.append(coeff % P)

        A.append(row)
        b.append((t - value) % P)

    return A, b

def eval_poly(poly, x):
    total = poly["const"]

    for i, c in enumerate(poly["linear"]):
        total += c * x[i]

    for i, j, c in poly["quad"]:
        total += c * x[i] * x[j]

    return total % P

def verify(polys, target, sig):
    return [eval_poly(poly, sig) for poly in polys] == target

def recover_signature(public):
    polys = public["polynomials"]
    target = public["target"]

    rows = list(combinations(range(len(polys)), O))

    for x0 in range(P):
        print(f"[+] Trying x0 = {x0}")

        for x1 in range(P):
            for x2 in range(P):
                for x3 in range(P):
                    vinegar = [x0, x1, x2, x3]
                    A, b = build_linear_system(polys, target, vinegar)

                    for chosen in rows:
                        sub_A = [A[i] for i in chosen]
                        sub_b = [b[i] for i in chosen]

                        oils = solve_linear(sub_A, sub_b)
                        if oils is None:
                            continue

                        sig = vinegar + oils

                        if verify(polys, target, sig):
                            return sig

    return None

def decrypt_flag(encrypted_flag, signature):
    key = hashlib.sha256(bytes(signature)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(bytes.fromhex(encrypted_flag))
    return unpad(pt, 16)

def main():
    with open("public.json", "r") as f:
        public = json.load(f)

    sig = recover_signature(public)

    if sig is None:
        print("[-] Signature not found")
        return

    print("[+] Signature:", sig)

    flag = decrypt_flag(public["encrypted_flag"], sig)
    print("[+] Flag:", flag.decode())

if __name__ == "__main__":
    main()
