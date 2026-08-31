#!/usr/bin/env python3
import hashlib
import os
import pickle
import struct
import sys
import zlib
from collections import Counter

import numpy as np

P, N, K, T, W = 827, 548, 274, 345, 75
REAL, SLOTS, DECOY = 7, 17, 15
MAGIC = b'ASIS117\x04'


def chal(cmt, salt, msg):
    b = hashlib.shake_256(b'c' + cmt + salt + msg).digest(8 * (2 * T + 2))
    a = list(range(T))
    for i in range(T - 1, 0, -1):
        j = int.from_bytes(b[8 * (T - 1 - i):8 * (T - i)], 'big') % (i + 1)
        a[i], a[j] = a[j], a[i]
    out = [0] * T
    for i in a[:W]:
        out[i] = int.from_bytes(b[8 * (T + i):8 * (T + i + 1)], 'big') % REAL + 1
    return out


def token_mask(cmt):
    return int.from_bytes(hashlib.sha256(b'm' + cmt).digest()[:2], 'big') & 1023


def label(cmt, seed):
    return hashlib.sha256(b't' + cmt + seed).digest()[:8]


def take(seed, tag, n, k):
    b = hashlib.shake_256(tag + seed).digest(8 * k)
    a = list(range(n))
    for i in range(k):
        j = i + int.from_bytes(b[8 * i:8 * i + 8], 'big') % (n - i)
        a[i], a[j] = a[j], a[i]
    return a[:k]


def cover_nodes(f):
    z, depth = 1, 0
    while z < T:
        z <<= 1
        depth += 1
    ans = []

    def go(u, lo, hi):
        if lo >= T:
            return
        end = min(hi, T)
        if all(f[i] == 0 for i in range(lo, end)):
            ans.append(u)
            return
        if hi - lo == 1:
            return
        md = (lo + hi) >> 1
        go(u << 1, lo, md)
        go((u << 1) | 1, md, hi)

    go(1, 0, 1 << depth)
    return ans, depth


def node_range(u, depth):
    level = u.bit_length() - 1
    span = 1 << (depth - level)
    lo = (u - (1 << level)) * span
    return lo, lo + span


def derive_leaf(seed, u, target, depth):
    lo, hi = node_range(u, depth)
    while u < (1 << depth):
        md = (lo + hi) >> 1
        if target < md:
            seed = hashlib.sha256(b'l' + seed).digest()
            u <<= 1
            hi = md
        else:
            seed = hashlib.sha256(b'r' + seed).digest()
            u = (u << 1) | 1
            lo = md
    return seed


def bits_to_set(bs):
    x = int.from_bytes(bs, 'little')
    return [i for i in range(N) if (x >> i) & 1]


def load_capture(path):
    raw = open(path, 'rb').read()
    if raw[:len(MAGIC)] != MAGIC:
        raise ValueError('bad magic')
    ln = struct.unpack('>I', raw[8:12])[0]
    return pickle.loads(zlib.decompress(raw[12:12 + ln]))


def extract_hits(records):
    hits = []
    ambiguous = 0

    for rec in records:
        b = chal(rec['cmt'], rec['salt'], rec['msg'])
        f0 = [int(x != 0) for x in b]
        serial = int(rec['msg'][1:])
        target = (37 * serial + 11) % T

        m = token_mask(rec['cmt'])
        rawmap = {tok ^ m: seed for tok, seed in rec['path']}
        rawset = set(rawmap)

        candidates = []
        for flip in (False, True):
            f = f0[:]
            if flip:
                f[target] ^= 1

            nodes, depth = cover_nodes(f)
            cover = set(nodes)
            if not cover.issubset(rawset):
                continue

            extra = rawset - cover
            base = 1 << depth
            if len(extra) <= DECOY and all(base <= u < base + T for u in extra):
                candidates.append((f, nodes, depth))

        # If both interpretations fit, do not use it for the attack.
        # There are enough clean records, and noisy human guessing is how bugs reproduce.
        if len(candidates) != 1:
            ambiguous += 1
            continue

        f, nodes, depth = candidates[0]
        if not (b[target] and not f[target]):
            continue

        cov_node = None
        for u in nodes:
            lo, hi = node_range(u, depth)
            if lo <= target < min(hi, T):
                cov_node = u
                break
        if cov_node is None:
            continue

        leaf = derive_leaf(rawmap[cov_node], cov_node, target, depth)
        lab = label(rec['cmt'], leaf)
        matches = [rsp for rsp in rec['rsp'] if rsp[0] == lab]
        if len(matches) != 1:
            continue

        hits.append((b[target] - 1, take(leaf, b'n', N, K), bits_to_set(matches[0][1]), serial))

    return hits, ambiguous


def exact_recover_perm(hits):
    sig_v = [0] * N
    sig_s = [0] * N

    for t, (_, vset, sset, _) in enumerate(hits):
        bit = 1 << t
        for j in vset:
            sig_v[j] |= bit
        for i in sset:
            sig_s[i] |= bit

    bucket = {}
    for i, s in enumerate(sig_s):
        bucket.setdefault(s, []).append(i)

    q = [None] * N
    for j, s in enumerate(sig_v):
        cand = bucket.get(s, [])
        if len(cand) == 1:
            q[j] = cand[0]

    ok = all(x is not None for x in q) and len(set(q)) == N
    return ok, q


def recover_class_perm(hits):
    ok, q = exact_recover_perm(hits)
    if ok:
        return q, []

    # One response may be intentionally corrupted. Drop one outlier and retry.
    for i in range(len(hits)):
        sub = hits[:i] + hits[i + 1:]
        ok, q = exact_recover_perm(sub)
        if ok:
            return q, [hits[i][3]]

    # Rare fallback: try two corrupt rows.
    for i in range(len(hits)):
        for j in range(i + 1, len(hits)):
            sub = hits[:i] + hits[i + 1:j] + hits[j + 1:]
            ok, q = exact_recover_perm(sub)
            if ok:
                return q, [hits[i][3], hits[j][3]]

    raise RuntimeError('failed to recover permutation')


def inv_mat_mod(A, p=P):
    A = np.array(A, dtype=np.int64) % p
    n = A.shape[0]
    M = np.concatenate([A, np.eye(n, dtype=np.int64)], axis=1)

    for c in range(n):
        pivots = np.nonzero(M[c:, c] % p)[0]
        if len(pivots) == 0:
            raise ValueError('singular matrix')
        r = c + int(pivots[0])
        if r != c:
            M[[c, r]] = M[[r, c]]

        inv_piv = pow(int(M[c, c]), p - 2, p)
        M[c] = (M[c] * inv_piv) % p

        rows = np.nonzero(M[:, c] % p)[0]
        rows = rows[rows != c]
        if len(rows):
            factors = M[rows, c].copy()
            M[rows] = (M[rows] - factors[:, None] * M[c]) % p

    return M[:, n:]


def matmul_mod(A, B):
    return (A @ B) % P


def recover_key_material(data, perms):
    invtab = np.zeros(P, dtype=np.int64)
    for x in range(1, P):
        invtab[x] = pow(x, P - 2, P)

    g = np.array(data['pub']['g'], dtype=np.int64) % P
    pubs = [np.array(x, dtype=np.int64) % P for x in data['pub']['pub']]

    bidx = np.arange(K)
    oidx = np.arange(K, N)

    # Public matrices are row-reduced. Move each public matrix into coordinates
    # of its first K columns once, then test every recovered permutation against it.
    d_pub = []
    for A in pubs:
        d_pub.append(matmul_mod(inv_mat_mod(A[:, bidx]), A[:, oidx]))

    keys = []
    used_slots = []

    for cls, p in enumerate(perms):
        cmat = matmul_mod(inv_mat_mod(g[:, p[:K]]), g[:, p[K:]])

        best = None
        for slot, dmat in enumerate(d_pub):
            cols = np.where((cmat[0] != 0) & (dmat[0] != 0))[0]
            if len(cols) == 0:
                continue

            c0 = int(cols[0])
            e0 = (dmat[:, c0] * invtab[cmat[:, c0]]) % P
            eta = (e0 * invtab[e0[0]]) % P
            alpha = (dmat[0] * invtab[cmat[0]]) % P
            expected = (cmat * alpha[None, :] % P) * eta[:, None] % P
            score = int(np.count_nonzero(expected == dmat))

            if best is None or score > best[0]:
                best = (score, slot, eta, alpha)

        if best is None:
            raise RuntimeError(f'no public match for class {cls}')

        score, slot, eta, alpha = best
        if score != K * (N - K):
            raise RuntimeError(f'weak public match for class {cls}: slot={slot}, score={score}')

        dnorm = [0] * N
        for r in range(K):
            dnorm[r] = int(eta[r])
        for c in range(N - K):
            dnorm[K + c] = int(invtab[alpha[c]])

        if dnorm[0] != 1 or any(x <= 0 or x >= P for x in dnorm):
            raise RuntimeError(f'bad diagonal recovery for class {cls}')

        keys.append((p, dnorm))
        used_slots.append(slot)

    return keys, used_slots


def pack_key(keys):
    out = bytearray()
    for p, d in keys:
        for x in p:
            out.extend(int(x).to_bytes(2, 'little'))
        for x in d:
            out.extend(int(x).to_bytes(2, 'little'))
    return bytes(out)


def locate_capture(argv):
    if len(argv) > 1:
        return argv[1]
    for path in ('flag.enc', 'new_less_is_more/flag.enc'):
        if os.path.exists(path):
            return path
    raise FileNotFoundError('flag.enc not found')


def main():
    path = locate_capture(sys.argv)
    data = load_capture(path)

    hits, ambiguous = extract_hits(data['records'])
    print(f'[+] records: {len(data["records"])}')
    print(f'[+] clean leakage records: {len(hits)} | ambiguous skipped: {ambiguous}')
    print(f'[+] leakage per class: {dict(Counter(x[0] for x in hits))}')

    perms = []
    for cls in range(REAL):
        class_hits = [h for h in hits if h[0] == cls]
        q, dropped = recover_class_perm(class_hits)
        p = [0] * N
        for original_col, perm_pos in enumerate(q):
            p[perm_pos] = original_col
        perms.append(p)
        print(f'[+] class {cls}: recovered permutation from {len(class_hits)} hits, dropped serials={dropped}')

    keys, slots = recover_key_material(data, perms)
    print(f'[+] real public slots: {slots}')

    pad = hashlib.shake_256(b'o' + pack_key(keys)).digest(len(data['sealed']))
    flag = bytes(a ^ b for a, b in zip(data['sealed'], pad))
    print(flag.decode())


if __name__ == '__main__':
    main()
