#!/usr/bin/env python3
from pathlib import Path
from hashlib import sha256
import random
import sys

N = 624
M = 397
MATRIX_A = 0x9908B0DF
MASK32 = 0xFFFFFFFF


def xor_word(a, b):
    return [x ^ y for x, y in zip(a, b)]


def shr_word(a, n):
    return [a[i + n] if i + n < 32 else 0 for i in range(32)]


def shl_mask_word(a, n, mask):
    return [(a[i - n] if i >= n and ((mask >> i) & 1) else 0) for i in range(32)]


def temper_word(w):
    y = w[:]
    y = xor_word(y, shr_word(y, 11))
    y = xor_word(y, shl_mask_word(y, 7, 0x9D2C5680))
    y = xor_word(y, shl_mask_word(y, 15, 0xEFC60000))
    y = xor_word(y, shr_word(y, 18))
    return y


def twist_one(u, v, add):
    # y = (u & 0x80000000) | (v & 0x7fffffff)
    y = [0] * 32
    for i in range(31):
        y[i] = v[i]
    y[31] = u[31]

    # xA = y >> 1; if y & 1: xA ^= MATRIX_A
    xA = [y[i + 1] if i + 1 < 32 else 0 for i in range(32)]
    lsb = y[0]
    for i in range(32):
        if (MATRIX_A >> i) & 1:
            xA[i] ^= lsb
    return xor_word(add, xA)


def twist_state(mt):
    # Match CPython's in-place MT19937 twist.
    for kk in range(N - M):
        mt[kk] = twist_one(mt[kk], mt[kk + 1], mt[kk + M])
    for kk in range(N - M, N - 1):
        mt[kk] = twist_one(mt[kk], mt[kk + 1], mt[kk + (M - N)])
    mt[N - 1] = twist_one(mt[N - 1], mt[0], mt[M - 1])


def add_equation(row, rhs, basis):
    while row:
        p = row.bit_length() - 1
        if p in basis:
            row ^= basis[p][0]
            rhs ^= basis[p][1]
        else:
            basis[p] = (row, rhs)
            return
    if rhs:
        raise RuntimeError("inconsistent linear system")


def recover_mt_state(leaks):
    # Unknowns: 624 internal MT words at index 0, LSB-first.
    mt = [[1 << (32 * j + i) for i in range(32)] for j in range(N)]
    idx = 0
    basis = {}

    # Each loop consumes 3 tempered MT words:
    #   getrandbits(48) -> full word y[3i] + top16(y[3i+1])
    #   getrandbits(16) -> top16(y[3i+2]), discarded/unknown
    for out_idx in range(3 * len(leaks)):
        if idx >= N:
            twist_state(mt)
            idx = 0

        bits = temper_word(mt[idx])
        idx += 1
        i, r = divmod(out_idx, 3)

        if r == 0:
            observed = leaks[i] & MASK32
            for b in range(32):
                add_equation(bits[b], (observed >> b) & 1, basis)
        elif r == 1:
            observed_hi16 = leaks[i] >> 32
            for b in range(16, 32):
                add_equation(bits[b], (observed_hi16 >> (b - 16)) & 1, basis)

    # Back-substitute with free variables set to zero. Here rank reaches 19968.
    sol = 0
    for p in sorted(basis):
        row, rhs = basis[p]
        bit = rhs ^ ((row & sol).bit_count() & 1)
        if bit:
            sol |= 1 << p

    state = []
    for j in range(N):
        w = 0
        for b in range(32):
            if (sol >> (32 * j + b)) & 1:
                w |= 1 << b
        state.append(w)
    return state


def parse_output(path):
    leaks = []
    enc_flag = None
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Enc flag:"):
            enc_flag = bytes.fromhex(line.split(":", 1)[1].strip())
        else:
            leaks.append(int(line))
    if enc_flag is None:
        raise RuntimeError("missing Enc flag line")
    return leaks, enc_flag


def aes_cbc_decrypt(key, iv, ct):
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    except ModuleNotFoundError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "out.txt"
    leaks, enc_flag = parse_output(path)

    state = recover_mt_state(leaks)

    rng = random.Random()
    rng.setstate((3, tuple(state + [0]), None))

    # Verify all leaked values.
    for i, want in enumerate(leaks):
        got = rng.getrandbits(48)
        rng.getrandbits(16)
        assert got == want, (i, got, want)

    # Match the hidden draws after the leak loop.
    for _ in range(10):
        rng.getrandbits(32)

    key = sha256(str(rng.getrandbits(64)).encode()).digest()
    iv = sha256(str(rng.getrandbits(64)).encode()).digest()[:16]
    pt = aes_cbc_decrypt(key, iv, enc_flag)
    print(pt.decode(errors="replace"))


if __name__ == "__main__":
    main()
