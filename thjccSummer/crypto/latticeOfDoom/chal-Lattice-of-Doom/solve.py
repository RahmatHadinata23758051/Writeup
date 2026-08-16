#!/usr/bin/env python3
import json
import hashlib
from pathlib import Path

try:
    from sympy import Matrix
except ImportError as e:
    raise SystemExit("sympy is required for LLL: pip install sympy") from e

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

NONCE_BYTES = 29
B = 1 << (8 * NONCE_BYTES)   # nonce bound: k < 2^232


def inv_mod(a, m):
    return pow(a, -1, m)


def sha256_int(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * inv_mod(2 * y1 % P, P) % P
    else:
        lam = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, point=G):
    out = None
    addend = point
    while k:
        if k & 1:
            out = ec_add(out, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return out


def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty plaintext")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]


def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    # Prefer pycryptodome on a normal CTF box; fall back to cryptography.
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()


def build_lattice(signatures):
    """
    ECDSA gives: s_i*k_i = z_i + r_i*d mod n.
    So k_i = t_i*d + u_i mod n, where:
      t_i = r_i/s_i mod n
      u_i = z_i/s_i mod n

    Firmware uses 29-byte nonces, so every k_i is below B = 2^232.
    This is a Hidden Number Problem instance. The matrix below is the standard
    embedding/CVP trick, scaled by n to keep everything integral:

      q_i*n + t_i*d + u_i = k_i

    A short lattice vector has coordinates:
      (k_1*n, ..., k_m*n, d*B, B*n)
    """
    m = len(signatures)
    ts, us = [], []
    for sig in signatures:
        r = int(sig["r"], 16)
        s = int(sig["s"], 16)
        z = sha256_int(bytes.fromhex(sig["msg"]))
        si = inv_mod(s, N)
        ts.append((r * si) % N)
        us.append((z * si) % N)

    rows = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = N * N
        rows.append(row)

    rows.append([t * N for t in ts] + [B, 0])
    rows.append([u * N for u in us] + [0, B * N])
    return Matrix(rows), ts, us


def recover_private_key(all_sigs, qx, qy):
    # 12 signatures are enough for this instance; loop makes the solver robust.
    for m in [12] + list(range(13, min(31, len(all_sigs)) + 1)):
        M, ts, us = build_lattice(all_sigs[:m])
        R = M.lll(delta=0.99)

        for vec in R.tolist():
            vec = [int(x) for x in vec]
            if abs(vec[-1]) != B * N:
                continue
            if vec[-2] % B != 0:
                continue

            d = (vec[-2] // B) % N
            nonces = [(t * d + u) % N for t, u in zip(ts, us)]
            if not all(k < B for k in nonces):
                continue
            if ec_mul(d) != (qx, qy):
                continue
            return d, m

    raise RuntimeError("private key not recovered; try increasing the signature range")


def main():
    data = json.loads(Path("output.json").read_text())
    qx = int(data["Qx"], 16)
    qy = int(data["Qy"], 16)

    d, used = recover_private_key(data["signatures"], qx, qy)
    print(f"[+] recovered d using {used} signatures")
    print(f"[+] d = {d:064x}")

    enc = bytes.fromhex(data["flag_enc"])
    iv, ct = enc[:16], enc[16:]
    key = hashlib.sha256(b"wallet-v1|" + d.to_bytes(32, "big")).digest()[:16]
    pt = unpad_pkcs7(aes_cbc_decrypt(key, iv, ct))
    flag = pt.decode()
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()

