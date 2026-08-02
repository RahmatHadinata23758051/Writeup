#!/usr/bin/env python3
from pwn import remote, context
import ast
import random
from collections import defaultdict

context.log_level = "info"

HOST = "po1337nomial-revenge.instances.ctf.l3ak.team"
PORT = 1337

N = 1337
MASK = 0xffffffff
MATRIX_A = 0x9908b0df
LOW30 = (1 << 30) - 1


def temper(y):
    y &= MASK
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & MASK


def undo_right(y, shift):
    x = y
    for _ in range(6):
        x = y ^ (x >> shift)
    return x & MASK


def undo_left(y, shift, mask):
    x = y
    for _ in range(6):
        x = y ^ ((x << shift) & mask)
    return x & MASK


def untemper(y):
    y = undo_right(y, 18)
    y = undo_left(y, 15, 0xefc60000)
    y = undo_left(y, 7, 0x9d2c5680)
    y = undo_right(y, 11)
    return y & MASK


def candidate_labels(a, b, valset):
    """
    For MT state sequence u:

        u[i+624] = u[i+397] ^ twist(u[i], u[i+1])

    If a = u[q+396] and b = u[q+623],
    then a ^ b leaks u[q]'s lower 31 bits.

    This function returns possible u[q].
    """
    t = a ^ b
    out = []

    for parity in (0, 1):
        v = t ^ (MATRIX_A if parity else 0)

        # v must be y >> 1, so top bit must be zero
        if v & 0x80000000:
            continue

        low31 = ((v & LOW30) << 1) | parity

        for cand in (low31, low31 | 0x80000000):
            if cand in valset:
                out.append(cand)

    return out


def extract_relations(states):
    vals = list(states)
    valset = set(vals)
    rels = []

    for i, a in enumerate(vals):
        for b in vals[i + 1:]:
            for lab in candidate_labels(a, b, valset):
                rels.append((lab, a, b))

    return rels


def ac_step(domains, rels):
    changed = False

    for lab, a, b in rels:
        dl = domains[lab]
        da = domains[a]
        db = domains[b]

        nl, na, nb = set(), set(), set()

        for pos in dl:
            p1 = pos + 396
            p2 = pos + 623

            if p1 in da and p2 in db:
                nl.add(pos)
                na.add(p1)
                nb.add(p2)

            if p2 in da and p1 in db:
                nl.add(pos)
                na.add(p2)
                nb.add(p1)

        if not nl or not na or not nb:
            return False, False

        if nl != dl:
            domains[lab] = nl
            changed = True
        if na != da:
            domains[a] = na
            changed = True
        if nb != db:
            domains[b] = nb
            changed = True

    return changed, True


def alldiff_step(domains):
    changed = False

    fixed = {}
    for v, d in domains.items():
        if len(d) == 1:
            idx = next(iter(d))
            if idx in fixed and fixed[idx] != v:
                return False, False
            fixed[idx] = v

    for idx, v in fixed.items():
        for w, d in domains.items():
            if w != v and idx in d:
                d.remove(idx)
                changed = True
                if not d:
                    return False, False

    inv = defaultdict(list)
    for v, d in domains.items():
        for idx in d:
            inv[idx].append(v)

    for idx, vs in inv.items():
        if len(vs) == 1:
            v = vs[0]
            if len(domains[v]) > 1:
                domains[v] = {idx}
                changed = True

    return changed, True


def solve_relations(rels):
    nodes = set()
    for lab, a, b in rels:
        nodes.add(lab)
        nodes.add(a)
        nodes.add(b)

    if len(nodes) != N:
        raise RuntimeError(f"nodes={len(nodes)}, expected {N}")

    domains = {v: set(range(N)) for v in nodes}

    # Valid extracted labels are state positions 0..713.
    # Valid endpoints are positions 396..1336.
    label_range = set(range(0, 714))
    endpoint_range = set(range(396, N))

    for lab, a, b in rels:
        domains[lab] &= label_range
        domains[a] &= endpoint_range
        domains[b] &= endpoint_range

    for _ in range(200):
        c1, ok = ac_step(domains, rels)
        if not ok:
            return None

        c2, ok = alldiff_step(domains)
        if not ok:
            return None

        if not c1 and not c2:
            break

    if not all(len(d) == 1 for d in domains.values()):
        return None

    pos = {v: next(iter(d)) for v, d in domains.items()}

    if len(set(pos.values())) != N:
        return None

    for lab, a, b in rels:
        lp = pos[lab]
        if sorted((pos[a], pos[b])) != [lp + 396, lp + 623]:
            return None

    seq = [None] * N
    for v, p in pos.items():
        seq[p] = v

    if any(x is None for x in seq):
        return None

    return seq


def recover_state_sequence(shuffled_coeffs):
    if len(set(shuffled_coeffs)) != len(shuffled_coeffs):
        raise RuntimeError("duplicate 32-bit output, reconnect")

    states = [untemper(x) for x in shuffled_coeffs]
    rels = extract_relations(states)

    print(f"[*] extracted relations: {len(rels)}")

    # Normal case:
    # q = 0..713 gives exactly 714 relations.
    #
    # Rarely, random false relations appear. Easiest practical fix:
    # reconnect and get a new instance.
    if len(rels) != 714:
        raise RuntimeError(f"relations={len(rels)}, expected 714; reconnect")

    seq = solve_relations(rels)
    if seq is None:
        raise RuntimeError("constraint solve failed; reconnect")

    return seq


def solve_once():
    io = remote(HOST, PORT, ssl=True)

    # Only use option 1. Do not use Evaluate.
    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"s: ")

    shuffled_coeffs = ast.literal_eval(io.recvline().decode())
    print("[+] got shuffled coefficients")

    state_seq = recover_state_sequence(shuffled_coeffs)
    coeff_seq = [temper(x) for x in state_seq]

    print("[+] recovered original MT output order")

    # After generating 1337 coefficients:
    #
    # outputs 0..623     = MT block 0
    # outputs 624..1247  = MT block 1
    # outputs 1248..1336 = first 89 outputs of MT block 2
    #
    # Set RNG to block 1, index 624, then consume 89 outputs.
    rng = random.Random()
    rng.setstate((3, tuple(state_seq[624:1248]) + (624,), None))

    for i in range(1248, 1337):
        got = rng.getrandbits(32)
        assert got == coeff_seq[i], f"MT sync failed at {i}"

    print("[+] synced RNG after coefficient generation")

    # Simulate option 1 shuffle to sync with remote state.
    test = coeff_seq.copy()
    rng.shuffle(test)

    if test != shuffled_coeffs:
        raise RuntimeError("shuffle verification failed; reconnect")

    print("[+] shuffle verified, RNG synced before option 3")

    k = rng.randbytes(1337).hex()

    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"k: ", k.encode())

    print(io.recvall(timeout=5).decode(errors="ignore"))


def main():
    while True:
        try:
            solve_once()
            break
        except Exception as e:
            print("[!] failed:", e)
            print("[*] reconnecting...")


if __name__ == "__main__":
    main()
