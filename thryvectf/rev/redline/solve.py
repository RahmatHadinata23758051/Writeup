#!/usr/bin/env python3
import struct
from collections import deque

BIN = 'redline'
BASE = 0x400000
DATA_REL_RO_OFF = 0xA14A0
CIRCUIT_SIZE = 0xB9C0
CHECK_IDX_VA = 0x47EC00
TARGET_BITS_VA = 0x47EF20

# Gate function addresses recovered from disassembly.
G_NOT  = 0x401BB0  # dst = !src
G_XOR  = 0x401BD0  # dst = a ^ b
G_NAND = 0x401C00  # dst = !(a & b)
G_COPY = 0x401C30  # dst1 = src; dst2 = src
G_RND  = 0x401C60  # runtime noise, not used by checked signals

FLAG_LEN = 36
PREFIX = b'ThryveCTF{'
SUFFIX_POS = 35
INNER_ALPHABET = b'abcdefghijklmnopqrstuvwxyz0123456789_'

# Boolean expression representation:
#   (scope, table)
# scope is a tuple of bit variable IDs.
# table bit n is the expression result for assignment n over scope, LSB order.
def const(v):
    return ((), 1 if v else 0)

def var(v):
    return ((v,), 0b10)  # assignment 0 -> 0, assignment 1 -> 1

def simplify(expr):
    scope, table = expr
    if not scope:
        return expr
    k = len(scope)
    if table == 0:
        return ((), 0)
    if table == (1 << (1 << k)) - 1:
        return ((), 1)

    scope = list(scope)
    changed = True
    while changed:
        changed = False
        k = len(scope)
        for rem in range(k):
            new_table = 0
            irrelevant = True
            for small in range(1 << (k - 1)):
                low = small & ((1 << rem) - 1)
                high = small >> rem
                a0 = low | (high << (rem + 1))
                a1 = a0 | (1 << rem)
                v0 = (table >> a0) & 1
                v1 = (table >> a1) & 1
                if v0 != v1:
                    irrelevant = False
                    break
                new_table |= v0 << small
            if irrelevant:
                del scope[rem]
                table = new_table
                changed = True
                break
    return (tuple(scope), table)

def combine(e1, e2, op):
    s1, t1 = e1
    s2, t2 = e2
    if not s1 and not s2:
        return ((), op(t1 & 1, t2 & 1) & 1)

    scope = tuple(sorted(set(s1) | set(s2)))
    pos = {v: i for i, v in enumerate(scope)}
    table = 0
    for ass in range(1 << len(scope)):
        i1 = 0
        for j, v in enumerate(s1):
            i1 |= ((ass >> pos[v]) & 1) << j
        i2 = 0
        for j, v in enumerate(s2):
            i2 |= ((ass >> pos[v]) & 1) << j
        val = op((t1 >> i1) & 1, (t2 >> i2) & 1) & 1
        table |= val << ass
    return simplify((scope, table))

def expr_not(e):
    scope, table = e
    return simplify((scope, ((1 << (1 << len(scope))) - 1) ^ table))

def expr_xor(a, b):
    return combine(a, b, lambda x, y: x ^ y)

def expr_nand(a, b):
    return combine(a, b, lambda x, y: 1 - (x & y))

def build_constraints(blob):
    entries = [struct.unpack_from('<QHHH', blob, DATA_REL_RO_OFF + i * 16)
               for i in range(CIRCUIT_SIZE // 16)]

    expr = [const(0) for _ in range(900)]
    for bit in range(FLAG_LEN * 8):
        expr[bit] = var(bit)

    rnd_var = FLAG_LEN * 8
    for f, a, b, c in entries:
        if f == G_NOT:
            expr[b] = expr_not(expr[a])
        elif f == G_XOR:
            expr[c] = expr_xor(expr[a], expr[b])
        elif f == G_NAND:
            expr[c] = expr_nand(expr[a], expr[b])
        elif f == G_COPY:
            expr[b] = expr[a]
            expr[c] = expr[a]
        elif f == G_RND:
            # The binary XORs a fresh runtime bit into two signals.
            # The checked outputs do not depend on these noise variables,
            # but modelling it keeps the circuit faithful.
            r = var(rnd_var)
            rnd_var += 1
            expr[a] = expr_xor(expr[a], r)
            expr[b] = expr_xor(expr[b], r)
        else:
            raise ValueError(f'unknown gate function {hex(f)}')

    check_idx = list(struct.unpack_from('<' + 'H' * 320, blob, CHECK_IDX_VA - BASE))
    target = blob[TARGET_BITS_VA - BASE:TARGET_BITS_VA - BASE + 40]

    constraints = []
    for i, sig in enumerate(check_idx):
        scope, table = expr[sig]
        want = (target[i // 8] >> (i % 8)) & 1
        allowed = [ass for ass in range(1 << len(scope)) if ((table >> ass) & 1) == want]
        constraints.append((scope, allowed))

    # Input format constraints. The binary requires 36 graphic characters.
    fixed = {i: ch for i, ch in enumerate(PREFIX)}
    fixed[SUFFIX_POS] = ord('}')
    for pos in range(FLAG_LEN):
        scope = tuple(range(pos * 8, pos * 8 + 8))
        if pos in fixed:
            allowed = [fixed[pos]]
        elif len(PREFIX) <= pos < SUFFIX_POS:
            allowed = list(INNER_ALPHABET)
        else:
            allowed = list(range(0x21, 0x7F))
        constraints.append((scope, allowed))

    return constraints, rnd_var

def propagate(domains, constraints, var_to_cons, queue=None):
    if queue is None:
        q = deque(range(len(constraints)))
    else:
        q = deque(queue)

    while q:
        ci = q.popleft()
        scope, allowed = constraints[ci]
        support = [0] * len(scope)
        any_row = False
        for row in allowed:
            ok = True
            for j, v in enumerate(scope):
                bit = (row >> j) & 1
                if not (domains[v] & (1 << bit)):
                    ok = False
                    break
            if ok:
                any_row = True
                for j, v in enumerate(scope):
                    support[j] |= 1 << ((row >> j) & 1)
        if not any_row:
            return False

        for j, v in enumerate(scope):
            nd = domains[v] & support[j]
            if nd != domains[v]:
                if nd == 0:
                    return False
                domains[v] = nd
                for cj in var_to_cons[v]:
                    if cj != ci:
                        q.append(cj)
    return True

def solve_csp(constraints, nvars):
    var_to_cons = [[] for _ in range(nvars)]
    for ci, (scope, _) in enumerate(constraints):
        for v in scope:
            var_to_cons[v].append(ci)

    domains = [0b11] * nvars
    if not propagate(domains, constraints, var_to_cons):
        raise RuntimeError('initial propagation failed')

    def current_candidate(ds):
        out = []
        for pos in range(FLAG_LEN):
            val = 0
            for b in range(8):
                d = ds[pos * 8 + b]
                if d not in (1, 2):
                    return None
                val |= (1 if d == 2 else 0) << b
            out.append(val)
        return bytes(out)

    def rec(ds):
        cand = current_candidate(ds)
        if cand is not None:
            return cand

        # Branch on the byte with the smallest remaining alphabet.
        best = None
        for pos in range(len(PREFIX), SUFFIX_POS):
            if all(ds[pos * 8 + b] in (1, 2) for b in range(8)):
                continue
            vals = []
            for ch in INNER_ALPHABET:
                if all(ds[pos * 8 + b] & (1 << ((ch >> b) & 1)) for b in range(8)):
                    vals.append(ch)
            if not vals:
                return None
            score = len(vals)
            if best is None or score < best[0]:
                best = (score, pos, vals)

        if best is None:
            return None

        _, pos, vals = best
        for ch in vals:
            nd = ds.copy()
            touched = set()
            for b in range(8):
                v = pos * 8 + b
                nd[v] = 1 << ((ch >> b) & 1)
                touched.update(var_to_cons[v])
            if propagate(nd, constraints, var_to_cons, touched):
                got = rec(nd)
                if got is not None:
                    return got
        return None

    return rec(domains)

def main():
    blob = open(BIN, 'rb').read()
    constraints, nvars = build_constraints(blob)
    flag = solve_csp(constraints, nvars)
    if not flag:
        raise SystemExit('no solution')
    print(flag.decode())

if __name__ == '__main__':
    main()
