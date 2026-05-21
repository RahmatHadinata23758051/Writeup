#!/usr/bin/env python3
import csv
import hashlib
import re
from pathlib import Path
from fpylll import IntegerMatrix, LLL

# P-256 / secp256r1 parameters
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = p - 3
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
)


def inv_mod(x, m):
    return pow(x, -1, m)


def ec_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = ((3 * x1 * x1 + a) * inv_mod(2 * y1 % p, p)) % p
    else:
        lam = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3


def ec_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P)
        P = ec_add(P, P)
        k >>= 1
    return R


def read_public_key(path):
    text = Path(path).read_text()
    qx = int(re.search(r"Qx\s*=\s*([0-9a-fA-F]+)", text).group(1), 16)
    qy = int(re.search(r"Qy\s*=\s*([0-9a-fA-F]+)", text).group(1), 16)
    return qx, qy


def read_trace(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "id": int(row["id"]),
                    "h": int(row["h"], 16),
                    "r": int(row["r"], 16),
                    "s": int(row["s"], 16),
                    "elapsed": int(row["elapsed_ns"]),
                }
            )
    return rows


def leaked_bitlength_upper(rank):
    # Conservative upper bounds from the timing clusters (shorter time => shorter nonce).
    if rank <= 1:
        return 245
    if rank <= 3:
        return 247
    if rank <= 6:
        return 248
    if rank <= 8:
        return 249
    if rank <= 21:
        return 250
    if rank <= 60:
        return 251
    if rank <= 110:
        return 252
    if rank <= 192:
        return 253
    if rank <= 389:
        return 254
    if rank <= 819:
        return 255
    return 256


def lattice_recover_d(rows, public_key, m=60):
    # ECDSA gives k_i = h_i/s_i + d*r_i/s_i (mod n).
    selected = sorted(rows, key=lambda x: x["elapsed"])[:m]
    bitlens = [leaked_bitlength_upper(i + 1) for i in range(m)]
    exps = [b - 1 for b in bitlens]
    max_exp = max(exps)

    A = [(row["r"] * inv_mod(row["s"], n)) % n for row in selected]
    C = [((row["h"] * inv_mod(row["s"], n)) - (1 << (bitlens[i] - 1))) % n for i, row in enumerate(selected)]
    W = [1 << (max_exp - e) for e in exps]
    T = [-(C[i] * W[i]) for i in range(m)]
    M = 1 << max_exp

    inv_last = inv_mod(A[-1], n)
    B = IntegerMatrix(m + 1, m + 1)
    for i in range(m - 1):
        B[i, i] = n * W[i]
    for j in range(m - 1):
        B[m - 1, j] = ((A[j] * inv_last) % n) * W[j]
    B[m - 1, m - 1] = W[-1]
    for j in range(m):
        B[m, j] = -T[j]
    B[m, m] = M

    LLL.reduction(B, delta=0.99, eta=0.501)

    for i in range(m + 1):
        vec = [int(B[i, j]) for j in range(m + 1)]
        if abs(vec[-1]) != M:
            continue
        q = vec[-1] // M
        recovered_scaled = [vec[j] + q * T[j] for j in range(m)]
        ds = []
        ok = True
        for j in range(m):
            if recovered_scaled[j] % W[j] != 0:
                ok = False
                break
            ds.append(((recovered_scaled[j] // W[j]) * inv_mod(A[j], n)) % n)
        if not ok:
            continue
        candidate, count = max(((x, ds.count(x)) for x in set(ds)), key=lambda t: t[1])
        if count >= m - 2 and ec_mul(candidate, G) == public_key:
            return candidate
    raise RuntimeError("private key recovery failed")


def decrypt_flag(d, enc_path):
    ct = bytes.fromhex(Path(enc_path).read_text().strip())
    seed = hashlib.sha256(d.to_bytes(32, "big")).digest()
    stream = b""
    counter = 0
    while len(stream) < len(ct):
        stream += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(x ^ y for x, y in zip(ct, stream))


def main():
    public_key = read_public_key("public_key.txt")
    rows = read_trace("trace.csv")
    d = lattice_recover_d(rows, public_key)
    flag = decrypt_flag(d, "flag.enc").decode()
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
