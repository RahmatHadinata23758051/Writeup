#!/usr/bin/env python3
import hashlib
import json
import re
import struct
import sys
import time
import zlib
from itertools import product

import requests

URL_DEFAULT = "http://91.107.152.21:17131"

MAGIC = b"\xd8\x06\x00\x1a"
HEADER = "<4sIIIIIIIIIII"

q, n, ell, m, t, b = 8380417, 64, 1, 70, 16, 65000
committee_size, threshold = 63, 32
secret_bound = 3

FLAG_RE = re.compile(r"[A-Z0-9_]+\{[^}\n\r]+\}")


def _a(x, y):
    return [(u + v) % q for u, v in zip(x, y)]


def _p(x, y):
    z = [0] * n
    for i, u in enumerate(x):
        if u:
            for j, v in enumerate(y):
                if v:
                    k = i + j
                    z[k if k < n else k - n] += v * u if k < n else -v * u
    return [u % q for u in z]


def _b(seed):
    h = hashlib.shake_256(b"SULTAN/challenge" + seed).digest(4096)
    z, seen, i = [0] * n, set(), 0
    while len(seen) < t:
        u = int.from_bytes(h[i:i + 2], "little") % n
        i += 2
        if u not in seen:
            seen.add(u)
            z[u] = 1 if h[i] & 1 else -1
            i += 1
    return z


def _r(seed):
    h = hashlib.shake_256(b"SULTAN/audit" + seed).digest(4 * n * ell)
    return [int.from_bytes(h[4 * i:4 * (i + 1)], "little") % q for i in range(n)]


def coeff_for_seed(seed):
    """coeff[j] = <r(seed), c(seed) * e_j> mod q."""
    c = _b(seed)
    rr = _r(seed)
    coeff = []
    for j in range(n):
        e = [0] * n
        e[j] = 1
        prod_poly = _p(c, e)
        coeff.append(sum(ri * pi for ri, pi in zip(rr, prod_poly)) % q)
    return coeff


def parse_blob(blob):
    raw = zlib.decompress(blob)
    off = 0
    hs = struct.calcsize(HEADER)
    header = struct.unpack(HEADER, raw[off:off + hs])
    off += hs

    magic, version, q0, n0, ell0, m0, t0, b0, sb0, cs0, th0, secret_len = header
    assert magic == MAGIC
    assert (q0, n0, ell0, m0, t0, b0, sb0, cs0, th0) == (q, n, ell, m, t, b, secret_bound, committee_size, threshold)

    nonce = raw[off:off + 24]
    off += 24
    enc = raw[off:off + secret_len]
    off += secret_len
    tag = raw[off:off + 32]
    off += 32

    rows = []
    pub = []
    rec_len = 32 + threshold + 4 + 4 * ell * n

    for _ in range(m):
        rec = raw[off:off + rec_len]
        off += rec_len

        x = rec[:32]
        y = rec[32:32 + threshold]
        seed = x + y
        audit_bucket = struct.unpack("<I", rec[32 + threshold:32 + threshold + 4])[0]
        v = list(struct.unpack("<" + "I" * n, rec[32 + threshold + 4:]))

        rr = _r(seed)
        audit_v = sum(ri * vi for ri, vi in zip(rr, v)) % q

        rows.append(coeff_for_seed(seed))
        pub.append((audit_v - (audit_bucket * b + b // 2)) % q)

    return rows, pub, nonce, enc, tag, secret_len


def try_decrypt(svec, nonce, enc, tag):
    if len(svec) != n or any(x < -3 or x > 3 for x in svec):
        return None

    w = struct.pack("<" + "b" * n, *svec)
    key = hashlib.shake_256(b"SULTAN/key" + w).digest(32)
    good_tag = hashlib.blake2s(b"SULTAN/tag" + nonce + enc, key=key, digest_size=32).digest()
    if good_tag != tag:
        return None

    stream = hashlib.shake_256(b"SULTAN/stream" + key + nonce).digest(len(enc))
    pt = bytes(a ^ c for a, c in zip(enc, stream))
    return pt


def iter_lattice_candidates_fpylll(A, y, W, M):
    from fpylll import IntegerMatrix, LLL, BKZ

    dim = m + n + 1
    basis = []

    for i in range(m):
        row = [0] * dim
        row[i] = q
        basis.append(row)

    for j in range(n):
        row = [A[i][j] for i in range(m)] + [0] * n + [0]
        row[m + j] = W
        basis.append(row)

    basis.append(y[:] + [0] * n + [M])

    B = IntegerMatrix.from_matrix(basis)
    LLL.reduction(B, delta=0.99)

    # BKZ bikin jauh lebih stabil dibanding LLL doang.
    for block in (20, 28, 36):
        try:
            BKZ.reduction(B, BKZ.Param(block_size=block))
        except Exception:
            pass

        for i in range(B.nrows):
            row = [int(B[i, j]) for j in range(B.ncols)]
            last = row[-1]
            if abs(last) != M:
                continue

            a = 1 if last == M else -1
            sec = row[m:m + n]
            if any(v % W for v in sec):
                continue

            cand = [int(-a * (v // W)) for v in sec]
            if all(-3 <= x <= 3 for x in cand):
                yield cand


def iter_lattice_candidates_sage(A, y, W, M):
    from sage.all import ZZ, matrix

    dim = m + n + 1
    basis = []

    for i in range(m):
        row = [0] * dim
        row[i] = q
        basis.append(row)

    for j in range(n):
        row = [A[i][j] for i in range(m)] + [0] * n + [0]
        row[m + j] = W
        basis.append(row)

    basis.append(y[:] + [0] * n + [M])

    B = matrix(ZZ, basis)
    B = B.LLL(delta=0.99)

    try:
        B = B.BKZ(block_size=28)
    except Exception:
        pass

    for row in B.rows():
        row = [int(x) for x in row]
        last = row[-1]
        if abs(last) != M:
            continue

        a = 1 if last == M else -1
        sec = row[m:m + n]
        if any(v % W for v in sec):
            continue

        cand = [int(-a * (v // W)) for v in sec]
        if all(-3 <= x <= 3 for x in cand):
            yield cand


def solve_secret_from_blob(blob, verbose=True):
    A, y, nonce, enc, tag, secret_len = parse_blob(blob)

    # Bobot ini menyeimbangkan error rounding (~32500) dan secret kecil [-3,3].
    params = [
        (9000, 35000),
        (12000, 45000),
        (16000, 55000),
        (7000, 30000),
        (20000, 65000),
    ]

    # Pakai fpylll kalau ada. Kalau run via sage -python, biasanya fpylll tersedia.
    backends = []
    try:
        import fpylll  # noqa: F401
        backends.append(("fpylll", iter_lattice_candidates_fpylll))
    except Exception:
        pass

    try:
        import sage.all  # noqa: F401
        backends.append(("sage", iter_lattice_candidates_sage))
    except Exception:
        pass

    if not backends:
        raise RuntimeError(
            "butuh fpylll/Sage untuk LLL/BKZ. Run: conda activate sage && sage -python solve_sultan.py"
        )

    seen = set()
    for name, backend in backends:
        for W, M in params:
            if verbose:
                print(f"[+] lattice backend={name} W={W} M={M}")
            for cand in backend(A, y, W, M):
                key = tuple(cand)
                if key in seen:
                    continue
                seen.add(key)
                pt = try_decrypt(cand, nonce, enc, tag)
                if pt is not None:
                    return pt.decode("utf-8", "replace"), cand

    raise RuntimeError("gagal recover secret dari transcript ini; coba request sample baru")


def main():
    url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else URL_DEFAULT
    sess = requests.Session()

    # Create/keep same session cookie.
    sess.get(url + "/api/session", timeout=10)

    for attempt in range(1, 8):
        print(f"[+] download sample #{attempt}")
        r = sess.get(url + "/download", timeout=20)
        r.raise_for_status()

        try:
            secret, svec = solve_secret_from_blob(r.content)
        except Exception as e:
            print(f"[!] sample #{attempt} failed: {e}")
            continue

        print(f"[+] recovered secret = {secret!r}")
        vr = sess.post(url + "/api/verify", json={"guess": secret}, timeout=10)
        print(vr.text)

        try:
            data = vr.json()
        except Exception:
            data = {}

        if data.get("success"):
            flag = data.get("flag", "")
            print(f"<FLAG>{flag}</FLAG>")
            return

        mflag = FLAG_RE.search(vr.text)
        if mflag:
            print(f"<FLAG>{mflag.group(0)}</FLAG>")
            return

    raise SystemExit("[-] gagal setelah beberapa sample")


if __name__ == "__main__":
    main()
