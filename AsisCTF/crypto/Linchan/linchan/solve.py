#!/usr/bin/env python3
import base64
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

N = 32
AAD = b"linchan/v2"


def gf2_rank(rows):
    piv = {}
    for x in rows:
        while x:
            p = x.bit_length() - 1
            if p in piv:
                x ^= piv[p]
            else:
                piv[p] = x
                break
    return len(piv)


def mat_add(A, B):
    return [x ^ y for x, y in zip(A, B)]


def mat_mul(A, B):
    out = []
    for x in A:
        y = 0
        while x:
            b = x & -x
            y ^= B[b.bit_length() - 1]
            x ^= b
        out.append(y)
    return out


def mat_transpose(A):
    R = [0] * N
    for i, x in enumerate(A):
        while x:
            b = x & -x
            R[b.bit_length() - 1] |= 1 << i
            x ^= b
    return R


def mat_inv(A):
    R = [x | (1 << (N + i)) for i, x in enumerate(A)]
    for i in range(N):
        j = next((j for j in range(i, N) if (R[j] >> i) & 1), None)
        if j is None:
            return None
        R[i], R[j] = R[j], R[i]
        for j in range(N):
            if j != i and ((R[j] >> i) & 1):
                R[j] ^= R[i]
    return [x >> N for x in R]


def combine(mask, basis):
    R = [0] * N
    while mask:
        b = mask & -mask
        R = mat_add(R, basis[b.bit_length() - 1])
        mask ^= b
    return R


def pack_matrix(A):
    return b"".join(x.to_bytes(4, "little") for x in A)


def canonical_secret(S):
    T = mat_inv(S)
    if T is None:
        raise ValueError("singular conjugator")
    return min(
        pack_matrix(S),
        pack_matrix(T),
        pack_matrix(mat_transpose(S)),
        pack_matrix(mat_transpose(T)),
    )


def parse_output(path):
    blob = Path(path).read_bytes().strip()
    obj = json.loads(zlib.decompress(base64.b85decode(blob)))
    if obj.get("v") != 2 or obj.get("n") != 32:
        raise ValueError("unexpected Linchan format")

    boxes = []
    encoded_raw = []
    for box in obj["boxes"]:
        m = int(box["m"])
        raw = base64.b85decode(box["x"])
        if len(raw) != m * N * 4:
            raise ValueError("bad box size")
        vals = struct.unpack("<%dI" % (m * N), raw)
        basis = [list(vals[i * N:(i + 1) * N]) for i in range(m)]
        boxes.append((m, basis))
        encoded_raw.append(raw)
    return obj, boxes, encoded_raw


SCANNER_CPP = r'''
#include <bits/stdc++.h>
using namespace std;

static inline int rank_at_most_25(const uint32_t *a) {
    uint32_t piv[32] = {};
    int r = 0;
    for (int rr = 0; rr < 32; ++rr) {
        uint32_t x = a[rr];
        while (x) {
            int p = 31 - __builtin_clz(x);
            if (piv[p]) x ^= piv[p];
            else {
                piv[p] = x;
                if (++r > 25) return r;
                break;
            }
        }
    }
    return r;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 3;

    uint32_t nb = 0;
    if (fread(&nb, 4, 1, fp) != 1) return 4;

    for (uint32_t bi = 0; bi < nb; ++bi) {
        uint32_t m = 0;
        if (fread(&m, 4, 1, fp) != 1) return 5;
        vector<array<uint32_t, 32>> B(m);
        if (fread(B.data(), 32 * 4, m, fp) != m) return 6;

        array<uint32_t, 32> cur{};
        uint32_t prev = 0;
        uint32_t lim = 1u << m;
        vector<uint32_t> hits;

        for (uint32_t k = 1; k < lim; ++k) {
            uint32_t g = k ^ (k >> 1);       // Gray code
            uint32_t diff = g ^ prev;
            prev = g;
            int j = __builtin_ctz(diff);
            for (int r = 0; r < 32; ++r) cur[r] ^= B[j][r];

            int rk = rank_at_most_25(cur.data());
            if (rk <= 25) hits.push_back(g);
        }

        if (hits.size() >= 2) {
            printf("%u %u", bi, m);
            for (uint32_t x : hits) printf(" %u", x);
            putchar('\n');
        }
    }
    fclose(fp);
    return 0;
}
'''


def scan_low_rank(encoded_raw, boxes):
    if shutil.which("g++") is None:
        raise RuntimeError("g++ is required for the fast 2^m MinRank scan")

    with tempfile.TemporaryDirectory(prefix="linchan_") as td:
        td = Path(td)
        bin_path = td / "boxes.bin"
        cpp_path = td / "scan.cpp"
        exe_path = td / "scan"

        with bin_path.open("wb") as f:
            f.write(struct.pack("<I", len(boxes)))
            for (m, _), raw in zip(boxes, encoded_raw):
                f.write(struct.pack("<I", m))
                f.write(raw)

        cpp_path.write_text(SCANNER_CPP)
        subprocess.run(
            ["g++", "-O3", "-march=native", str(cpp_path), "-o", str(exe_path)],
            check=True,
        )
        p = subprocess.run(
            [str(exe_path), str(bin_path)],
            check=True,
            text=True,
            capture_output=True,
        )

    special = {}
    for line in p.stdout.splitlines():
        z = [int(x) for x in line.split()]
        idx, m, masks = z[0], z[1], z[2:]
        # The planted boxes contain the two hidden rank-25 generators.
        # Extra hits are overwhelmingly unlikely, but retaining the first
        # two is enough for this instance construction.
        if len(masks) >= 2:
            special[idx] = masks[:2]

    return special


def conjugacy_equations(A, B):
    """Rows for B*X = X*A, with 1024 GF(2) unknown bits of X."""
    cols = [[] for _ in range(N)]
    for k, row in enumerate(A):
        x = row
        while x:
            b = x & -x
            cols[b.bit_length() - 1].append(k)
            x ^= b

    rows = []
    for i in range(N):
        left = []
        x = B[i]
        while x:
            b = x & -x
            left.append(b.bit_length() - 1)
            x ^= b

        for j in range(N):
            eq = 0
            for k in left:
                eq ^= 1 << (k * N + j)
            for k in cols[j]:
                eq ^= 1 << (i * N + k)
            if eq:
                rows.append(eq)
    return rows


def unique_null_vector(rows):
    """Return unique nonzero kernel vector when nullity == 1."""
    piv = {}
    for x in rows:
        while x:
            p = x.bit_length() - 1
            if p in piv:
                x ^= piv[p]
            else:
                piv[p] = x
                break

    if len(piv) != N * N - 1:
        return None

    free = next(i for i in range(N * N) if i not in piv)
    sol = 1 << free

    # Highest-bit pivots mean each row only references lower variables.
    for p in sorted(piv):
        rest = piv[p] ^ (1 << p)
        if (rest & sol).bit_count() & 1:
            sol |= 1 << p

    return [(sol >> (i * N)) & 0xFFFFFFFF for i in range(N)]


def verify_conjugacy(A, B, X):
    Xi = mat_inv(X)
    return Xi is not None and mat_mul(mat_mul(X, A), Xi) == B


def recover_pair(A2, B2):
    # Each box may independently have been transposed by _o().
    # Also the two rank-25 generators can appear in either order.
    for transpose_A in (False, True):
        AA = [mat_transpose(x) for x in A2] if transpose_A else A2
        for perm in ((0, 1), (1, 0)):
            BB = [B2[perm[0]], B2[perm[1]]]
            rows = conjugacy_equations(AA[0], BB[0])
            rows += conjugacy_equations(AA[1], BB[1])
            X = unique_null_vector(rows)
            if X is None or gf2_rank(X) != N:
                continue
            if verify_conjugacy(AA[0], BB[0], X) and verify_conjugacy(AA[1], BB[1], X):
                return X, transpose_A, perm
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output.txt"
    obj, boxes, encoded_raw = parse_output(path)

    print(f"[+] loaded {len(boxes)} boxes")
    print("[+] scanning all basis combinations for hidden rank-25 matrices...")
    special_masks = scan_low_rank(encoded_raw, boxes)
    special_ids = sorted(special_masks)
    print(f"[+] special boxes: {special_ids}")

    if len(special_ids) != 10:
        raise RuntimeError(f"expected 10 planted boxes, got {len(special_ids)}")

    low = {
        idx: [combine(mask, boxes[idx][1]) for mask in masks]
        for idx, masks in special_masks.items()
    }

    secrets = []
    used = set()

    for m in (16, 17, 18):
        ids = [idx for idx in special_ids if boxes[idx][0] == m]
        candidates = []
        for a, b in itertools.combinations(ids, 2):
            hit = recover_pair(low[a], low[b])
            if hit is not None:
                X, ta, perm = hit
                candidates.append((a, b, X, ta, perm))

        for a, b, X, ta, perm in candidates:
            if a in used or b in used:
                continue
            used.add(a)
            used.add(b)
            secrets.append(X)
            print(f"[+] pair m={m}: box {a} <-> {b}  transpose={int(ta)} perm={perm}")

    if len(secrets) != 5 or len(used) != 10:
        raise RuntimeError("failed to recover a perfect matching of the planted boxes")

    material = b"".join(sorted(canonical_secret(S) for S in secrets))
    key = hashlib.shake_256(b"linchan-v2/key\0" + material).digest(32)

    ct = base64.b85decode(obj["ct"])
    nonce, ciphertext = ct[:12], ct[12:]
    flag = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, AAD)

    print(f"[+] key: {key.hex()}")
    print(f"[+] FLAG: {flag.decode(errors='replace')}")


if __name__ == "__main__":
    main()
