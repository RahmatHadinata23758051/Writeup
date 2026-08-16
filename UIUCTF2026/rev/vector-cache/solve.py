#!/usr/bin/env python3
from pathlib import Path
from collections import Counter
import subprocess
import sys

MASK = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
XS_FALLBACK = 0xDC1B77AE0BF34DAD
XS_MUL = 0xD1342543DE82EF95
DEC_GOLDEN = 0x9E3779B97F4A7C15

# Exact challenge binary layout (BuildID 717fb54e960ddbacb295a7e12841c0aaa7c7387e)
CHOICE = {0: 3, 1: 1, 2: 2}
PROGRAM = {0: 0x6340, 1: 0x5740, 2: 0x3940}
OPMAP = {0: 0x3240, 1: 0x3140, 2: 0x3040}

# VM argument seeds recovered from the encrypted bytecode structure.
# mode 0 is unkeyed; modes 1/2 unlock after the previous 8-byte chunk.
VM_ARG4 = {
    0: 0x0000000000000000,
    1: 0x2D8835BD73B39859,
    2: 0xF2248118FD0DDA47,
}

EXPECTED_SHA256 = "b515c9c067b1daa690568bc71090f8bea181af09f398f7487269397ae457cd8d"


def rol8(x, n):
    n &= 7
    return ((x << n) | (x >> ((8 - n) & 7))) & 0xFF


def rol64(x, n):
    n &= 63
    return ((x << n) | (x >> ((64 - n) & 63))) & MASK


def ror64(x, n):
    n &= 63
    return ((x >> n) | (x << ((64 - n) & 63))) & MASK


def xorshift64(x):
    x &= MASK
    x ^= (x << 13) & MASK
    x ^= x >> 7
    x ^= (x << 17) & MASK
    return x & MASK


def seed_init(blob, mode, arg4):
    ch = CHOICE[mode]
    eptr = 0x7DC0 + mode * 0x60 + ch * 0x18
    q0 = int.from_bytes(blob[eptr:eptr+8], "little")
    q1 = int.from_bytes(blob[eptr+8:eptr+16], "little")
    q2 = int.from_bytes(blob[eptr+16:eptr+24], "little")

    x = ((mode + 1) * 0xC2B2AE3D27D4EB4F) & MASK
    x ^= arg4
    x ^= ((ch + 3) * 0x165667B19E3779F9) & MASK
    x ^= (0xE7037ED1A0B428DB + q1) & MASK
    x ^= ror64(q2, 11)
    x ^= rol64(0xA0761D6478BD642F ^ q0, 17)
    return x & MASK


def decrypt_program(blob, mode, arg4):
    ctext = blob[PROGRAM[mode]:PROGRAM[mode] + 0x600]
    state = seed_init(blob, mode, arg4)
    prev = (mode * 49 ^ CHOICE[mode] * 23 ^ 0xA5) & 0xFF
    out = bytearray()

    for i, c in enumerate(ctext):
        x = (prev + i * XS_MUL + DEC_GOLDEN + state) & MASK
        state = XS_FALLBACK if x == 0 else xorshift64(x)
        ks = (state >> ((i & 7) * 8)) & 0xFF
        p = rol8(prev, (i % 7) + 1) ^ c ^ ks
        out.append(p)
        prev = c

    return bytes(out)


def shuffle_seed(blob, mode):
    off = 0x7D60 + mode * 24
    q0 = int.from_bytes(blob[off:off+8], "little")
    q1 = int.from_bytes(blob[off+8:off+16], "little")
    q2 = int.from_bytes(blob[off+16:off+24], "little")
    return (
        ror64(q2, 7)
        ^ q1
        ^ rol64(0x8EBC6AF09C88C6E3 ^ q0, 23)
    ) & MASK


def make_sbox(blob, mode):
    # Fisher-Yates exactly as fcn.00002620 does.
    arr = list(range(256))
    state = shuffle_seed(blob, mode)
    for j in range(255, 0, -1):
        x = (j + GOLDEN + state) & MASK
        state = XS_FALLBACK if x == 0 else xorshift64(x)
        k = state % (j + 1)
        arr[j], arr[k] = arr[k], arr[j]
    return arr


def checksum_ok(rec, mode, step):
    p = list(rec)
    ch = CHOICE[mode]
    v = ((mode * 0x2311) & 0xFFFF)
    v ^= (step * 25) & 0xFFFF
    v ^= p[0]
    v ^= (ch * 0x4513) & 0xFFFF
    v ^= 0x6D5A
    v = ((v << 5) | (v >> 11)) & 0xFFFF
    v = (v + p[0] - 0x61C9) & 0xFFFF

    for i in range(1, 12):
        v ^= (p[i] + 0x3D * i) & 0xFF
        v = ((v << 5) | (v >> 11)) & 0xFFFF
        v = (v + p[i] * (1 << (i % 4)) - 0x61C9) & 0xFFFF

    return v == int.from_bytes(rec[12:14], "little")


def vm_result(blob, mode, rec, token, sbox):
    p = list(rec)
    op = blob[OPMAP[mode] + p[0]]
    if op > 6:
        raise ValueError("bad opcode")

    A = token[p[2]]
    B = token[p[1]]
    C = token[p[3]]
    p4, p5, p6, p7, p8, p9 = p[4], p[5], p[6], p[7], p[8], p[9]

    if op == 6:
        r = sbox[(B + p6) & 0xFF] ^ p7
    elif op == 5:
        r = (
            sbox[(rol8(A, p4) + (p6 ^ B)) & 0xFF]
            + ((p8 - rol8(C ^ p7, p5)) & 0xFF)
        ) & 0xFF
    elif op == 4:
        r = (((C + p7) * p9) & 0xFF) ^ p8
        r ^= sbox[(B + p6 + sbox[A]) & 0xFF]
    elif op == 3:
        r = rol8(sbox[(B ^ p6) & 0xFF], p4)
        r ^= (((p9 * A + p7) & 0xFF) ^ (rol8(C, p5) ^ p8))
    elif op == 2:
        r = p8 ^ sbox[(C + p7) & 0xFF] ^ sbox[(B + p6 - A) & 0xFF]
    elif op == 1:
        r = (
            rol8((p7 + C) & 0xFF, p5)
            + p8
            + sbox[(rol8((p6 + A) & 0xFF, p4) ^ B) & 0xFF]
        ) & 0xFF
    else:  # op == 0
        r = rol8(p7 ^ C, p5) ^ p8
        r ^= sbox[(rol8(A, p4) + p6 + B) & 0xFF]

    return r & 0xFF


def parse_records(blob, mode, arg4):
    pt = decrypt_program(blob, mode, arg4)
    records = []
    bound = 8 * (mode + 1)

    for step in range(96):
        rec = pt[step * 16:(step + 1) * 16]
        op = blob[OPMAP[mode] + rec[0]]
        if op > 6:
            raise RuntimeError(f"mode {mode}: invalid decrypted opcode at step {step}")
        if not all(x < bound for x in rec[1:4]):
            raise RuntimeError(f"mode {mode}: invalid index at step {step}")
        if not checksum_ok(rec, mode, step):
            raise RuntimeError(f"mode {mode}: checksum mismatch at step {step}")
        records.append((step, op, (rec[1], rec[2], rec[3]), rec))

    return records


def solve_chunk(blob, mode, known_prefix, arg4):
    records = parse_records(blob, mode, arg4)
    sbox = make_sbox(blob, mode)
    start = mode * 8
    end = start + 8
    unknown = set(range(start, end))
    domains = {i: set(range(256)) for i in unknown}

    # Constraints involving at most two not-yet-known bytes are enough to
    # collapse each 8-byte stage to a unique solution.
    usable = [r for r in records if len(set(r[2]) & unknown) <= 2]

    def sat(info, assign):
        token = list(known_prefix) + [0] * (end - len(known_prefix))
        for idx, val in assign.items():
            token[idx] = val
        rec = info[3]
        return vm_result(blob, mode, rec, token, sbox) == rec[10]

    changed = True
    while changed:
        changed = False
        for info in usable:
            vars_here = sorted(set(info[2]) & unknown)

            if not vars_here:
                if not sat(info, {}):
                    raise RuntimeError(f"mode {mode}: known-prefix constraint failed")
                continue

            if len(vars_here) == 1:
                v = vars_here[0]
                keep = {x for x in domains[v] if sat(info, {v: x})}
                if keep != domains[v]:
                    domains[v] = keep
                    changed = True
            else:
                a, c = vars_here
                support_a = set()
                support_c = set()
                for va in domains[a]:
                    for vc in domains[c]:
                        if sat(info, {a: va, c: vc}):
                            support_a.add(va)
                            support_c.add(vc)
                na = domains[a] & support_a
                nc = domains[c] & support_c
                if na != domains[a]:
                    domains[a] = na
                    changed = True
                if nc != domains[c]:
                    domains[c] = nc
                    changed = True

        if any(not d for d in domains.values()):
            raise RuntimeError(f"mode {mode}: domain became empty")

    if not all(len(domains[i]) == 1 for i in range(start, end)):
        sizes = {i: len(domains[i]) for i in range(start, end)}
        raise RuntimeError(f"mode {mode}: non-unique solution: {sizes}")

    chunk = bytes(next(iter(domains[i])) for i in range(start, end))
    token = known_prefix + chunk

    # Verify all 96 VM equations for this stage.
    for step, _, _, rec in records:
        if vm_result(blob, mode, rec, token, sbox) != rec[10]:
            raise RuntimeError(f"mode {mode}: final verification failed at step {step}")

    return chunk


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "vector-cache")
    if not path.exists():
        # Convenient fallback for the uploaded challenge filename here.
        alt = Path("/mnt/data/vector-cache(1)")
        if alt.exists():
            path = alt
        else:
            raise SystemExit(f"binary not found: {path}")

    blob = path.read_bytes()
    if blob[:4] != b"\x7fELF":
        raise SystemExit("not an ELF binary")

    token = b""
    for mode in range(3):
        chunk = solve_chunk(blob, mode, token, VM_ARG4[mode])
        token += chunk
        print(f"[+] chunk {mode}: {chunk.hex()}")

    flag = f"uiuctf{{{token.hex()}}}"
    print(f"[+] FLAG: {flag}")

    # Optional local proof against the supplied verifier.
    try:
        p = subprocess.run(
            [str(path.resolve())],
            input=(flag + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
        )
        out = p.stdout.decode(errors="replace")
        if "accepted" in out:
            print("[+] verifier: accepted")
        else:
            print("[!] verifier did not say accepted")
            print(out.rstrip())
    except Exception as e:
        print(f"[!] verifier check skipped: {e}")


if __name__ == "__main__":
    main()
