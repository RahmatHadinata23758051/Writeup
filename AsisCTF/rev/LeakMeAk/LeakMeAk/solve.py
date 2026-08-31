#!/usr/bin/env python3
# Solver LeakMeAk
# Reversing notes:
# - Binary accepts len 34, prefix ASIS{ and suffix }.
# - Middle 28 bytes are processed as 7 chunks of 4 bytes.
# - Each chunk produces one uint32 D[i].
# - D[i] must satisfy a chained relation and two final checks.

from string import ascii_lowercase, digits

MASK = 0xffffffff
CONST = 0x9e3779b9

# .rodata constants used by the chained D check
T = [
    0x449f4ab5, 0xbb5e7ac4, 0x91141f33, 0x9caafb86,
    0xd99258f7, 0x2abb0f38, 0x3ff226d0,
]
K = [
    0xa5a5a5a5, 0x5a5a5a5a, 0x3c3c3c3c, 0xc3c3c3c3,
    0x96969696, 0x69696969, 0x1f1f1f1f,
]

CHARSET = (ascii_lowercase + digits + "_").encode()


def ror32(x, n):
    return ((x >> n) | ((x << (32 - n)) & MASK)) & MASK


def rol32(x, n):
    return (((x << n) & MASK) | (x >> (32 - n))) & MASK


def final_hash(D):
    edx = 0
    for v in D:
        edx = (((edx * 0x21) & MASK) ^ v) & MASK

    eax = edx
    for _ in range(64):
        edi = ((eax << 5) + eax) & MASK
        eax = (ror32(eax, 11) ^ edi) & MASK
    return edx, eax


def d_sequence_from_d0(d0):
    """The comparison loop fixes every next D from the previous D."""
    D = [d0]
    for i in range(1, 7):
        need = ((T[i - 1] ^ K[i - 1]) - D[i - 1]) & MASK
        D.append(rol32(need, 13))
    return D


def sequence_is_global_valid(D):
    # wraparound check for i = 7
    wrap = ((ror32(D[0], 13) + D[6]) & MASK) ^ K[6]
    if wrap != T[6]:
        return False
    return final_hash(D) == (0xddaacf25, 0x376a3d36)


def step(state, chunk):
    """Emulates one 4-byte iteration from the stripped binary."""
    S, C, P, Q, R, live_r12 = state
    S, C = list(S), list(C)
    a, b, c, d = chunk

    op = a & 3
    idx_b = b & 7
    idx_c = c & 7
    idx_d = d & 7

    val_c = S[idx_c]
    val_d = S[idx_d]

    ecx = 0
    live_low1 = (live_r12 & 3) == 1
    c_low1 = (val_c & 3) == 1
    d_low1 = (val_d & 3) == 1
    p_low1 = (P & 3) == 1

    # conflict checks; any ecx bit means rejection at the end
    if live_low1 and c_low1 and (((live_r12 ^ val_c) & 0x0c) == 0) and (((live_r12 ^ val_c) & 0x30) != 0):
        ecx |= 1
    else:
        if c_low1 and p_low1 and (((P ^ val_c) & 0x0c) == 0) and (((P ^ val_c) & 0x30) != 0):
            ecx |= 1
        elif live_low1 and d_low1 and (((live_r12 ^ val_d) & 0x0c) == 0) and (((live_r12 ^ val_d) & 0x30) != 0):
            ecx |= 1
        elif p_low1 and d_low1 and (((P ^ val_d) & 0x0c) == 0) and (((P ^ val_d) & 0x30) != 0):
            ecx |= 1

    C[idx_c] = (C[idx_c] + 1) & 0xff
    C[idx_d] = (C[idx_d] + 1) & 0xff
    if c_low1 and C[idx_c] > 1:
        ecx |= 0x10
    if d_low1 and C[idx_d] > 1:
        ecx |= 0x10

    if op == 1:
        new = val_c
    elif op == 0:
        if c_low1 and d_low1:
            if (((val_d ^ val_c) & 0x0c) == 0) and (((val_d ^ val_c) & 0x30) != 0):
                ecx |= 2
            new = val_c
        elif c_low1:
            new = val_c
        elif d_low1:
            new = val_d
        else:
            new = 0
    else:
        new = ((a << 4) & 0x10) | 0x05

    old = S[idx_b]
    if ((old & 3) == 1) and ((new & 3) == 1):
        if (((old ^ new) & 0x0c) == 0) and (((old ^ new) & 0x30) != 0) and d <= 0x59:
            ecx |= 4

    S[idx_b] = new & 0xff
    C[idx_b] = 0

    packed = ((a << 24) | (b << 16) | (c << 8) | d) & MASK
    meta = (((new & 0xff) << 24) ^ ((val_c & 0xff) << 16) ^ ((val_d & 0xff) << 8) ^ idx_b) & MASK
    D = (((packed * CONST) & MASK) ^ meta) & MASK

    # compiler stores these as shifted live bytes for later conflict checks
    next_state = (tuple(S), tuple(C), R, val_c, val_d, Q)
    return next_state, D, ecx


def find_chunk_for_target(state, target_D):
    for a in CHARSET:
        for b in CHARSET:
            for c in CHARSET:
                for d in CHARSET:
                    chunk = bytes((a, b, c, d))
                    next_state, D, ecx = step(state, chunk)
                    if ecx == 0 and D == target_D:
                        return chunk, next_state
    return None, None


def main():
    init_state = (tuple([5, 21, 10, 14, 0, 0, 0, 0]), tuple([0] * 8), 0, 0, 0, 0)

    for a in CHARSET:
        for b in CHARSET:
            for c in CHARSET:
                for d in CHARSET:
                    first = bytes((a, b, c, d))
                    state, d0, ecx = step(init_state, first)
                    if ecx != 0:
                        continue

                    D = d_sequence_from_d0(d0)
                    if not sequence_is_global_valid(D):
                        continue

                    payload = bytearray(first)
                    ok = True
                    for target in D[1:]:
                        chunk, state = find_chunk_for_target(state, target)
                        if chunk is None:
                            ok = False
                            break
                        payload += chunk

                    if not ok:
                        continue

                    # final state checks at 0x1455 and 0x1462
                    S = state[0]
                    if (S[0] & 3) != 1 or (S[1] & 3) != 2:
                        continue

                    flag = b"ASIS{" + bytes(payload) + b"}"
                    print(flag.decode())
                    return

    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()
