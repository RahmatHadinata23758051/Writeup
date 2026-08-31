#!/usr/bin/env python3
import json
import hmac
import hashlib
from pathlib import Path

try:
    from Crypto.Cipher import AES
    HAVE_PYCRYPTODOME = True
except Exception:
    HAVE_PYCRYPTODOME = False
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MOD_POLY = 0x13
MUL = [[0] * 16 for _ in range(16)]


def gf_mul(a, b):
    out = 0
    x = a
    y = b
    while y:
        if y & 1:
            out ^= x
        y >>= 1
        x <<= 1
        if x & 0x10:
            x ^= MOD_POLY
        x &= 0xF
    return out


for _a in range(16):
    for _b in range(16):
        MUL[_a][_b] = gf_mul(_a, _b)


def gf_pow(a, e):
    out = 1
    base = a
    while e:
        if e & 1:
            out = gf_mul(out, base)
        base = gf_mul(base, base)
        e >>= 1
    return out


def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError("inverse of zero")
    return gf_pow(a, 14)


def vec_scale(vec, scalar):
    row = MUL[scalar]
    return [row[x] for x in vec]


def vec_add(a, b):
    return [x ^ y for x, y in zip(a, b)]


def row_reduce(rows):
    mat = [row[:] for row in rows if any(row)]
    if not mat:
        return []

    cols = len(mat[0])
    rix = 0
    for cix in range(cols):
        pivot = None
        for row in range(rix, len(mat)):
            if mat[row][cix]:
                pivot = row
                break
        if pivot is None:
            continue

        mat[rix], mat[pivot] = mat[pivot], mat[rix]
        inv = gf_inv(mat[rix][cix])
        mat[rix] = vec_scale(mat[rix], inv)

        for row in range(len(mat)):
            if row != rix and mat[row][cix]:
                mat[row] = vec_add(mat[row], vec_scale(mat[rix], mat[row][cix]))

        rix += 1
        if rix == len(mat):
            break

    return [row for row in mat if any(row)]


def parse_poly(hex_string, n):
    coeffs = [int(ch, 16) for ch in hex_string]
    expected = n * (n + 1) // 2
    if len(coeffs) != expected:
        raise ValueError(f"bad polynomial length: got {len(coeffs)}, expected {expected}")
    return coeffs


def build_monomials(x, n):
    mons = []
    for i in range(n):
        xi = x[i]
        for j in range(i, n):
            xj = x[j]
            mons.append(MUL[xi][xj] if xi and xj else 0)
    return mons


def eval_poly(poly, mons):
    acc = 0
    for coeff, value in zip(poly, mons):
        if coeff and value:
            acc ^= MUL[coeff][value]
    return acc


def is_common_zero(polys, x, n):
    mons = build_monomials(x, n)
    for poly in polys:
        if eval_poly(poly, mons):
            return False
    return True


def hkdf_sha256(material, length, salt, context):
    # Same construction used by PyCryptodome HKDF(material, length, salt, SHA256, context=context).
    prk = hmac.new(salt, material, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + context + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_key(oil_basis, salt):
    rref = row_reduce(oil_basis)
    material = bytes(x for row in rref for x in row)
    return hkdf_sha256(material, 32, salt, b"MARIO")


def decrypt_gcm(key, nonce, ciphertext_and_tag):
    aad = b"MARIO"
    if HAVE_PYCRYPTODOME:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        return cipher.decrypt_and_verify(ciphertext, tag)

    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)


def recover_oil_basis(polys, reports, n, d):
    # Every report has the shape u_i + a_i*g, with u_i in the hidden oil subspace
    # and a_i nonzero. For two reports, one scalar c cancels the g component:
    # report_i + c*report_ref in O. Oil vectors are exactly common zeros of all public forms.
    ref = reports[0]
    oil_vectors = []

    for report in reports[1:]:
        for c in range(1, 16):
            candidate = vec_add(report, vec_scale(ref, c))
            if any(candidate) and is_common_zero(polys, candidate, n):
                oil_vectors.append(candidate)
                oil_vectors = row_reduce(oil_vectors)
                break
        if len(oil_vectors) == d:
            return oil_vectors

    # Fallback in case the fixed reference gives unlucky dependent vectors.
    for i in range(len(reports)):
        for j in range(i + 1, len(reports)):
            for c in range(1, 16):
                candidate = vec_add(reports[i], vec_scale(reports[j], c))
                if any(candidate) and is_common_zero(polys, candidate, n):
                    oil_vectors.append(candidate)
                    oil_vectors = row_reduce(oil_vectors)
                    if len(oil_vectors) == d:
                        return oil_vectors
                    break

    raise RuntimeError(f"only recovered rank {len(oil_vectors)} oil subspace")


def main():
    here = Path(__file__).resolve().parent
    data = json.loads((here / "output.txt").read_text())

    n, m, d, s = data["p"]
    polys = [parse_poly(poly, n) for poly in data["A"]]
    reports = data["B"]
    salt = bytes.fromhex(data["C"][0])
    nonce = bytes.fromhex(data["C"][1])
    ciphertext_and_tag = bytes.fromhex(data["C"][2])

    if len(polys) != m or len(reports) != s:
        raise ValueError("payload parameter mismatch")

    oil_basis = recover_oil_basis(polys, reports, n, d)
    key = derive_key(oil_basis, salt)
    flag = decrypt_gcm(key, nonce, ciphertext_and_tag)
    print(flag.decode())


if __name__ == "__main__":
    main()
