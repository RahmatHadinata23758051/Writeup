#!/usr/bin/env python3
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "scouting_report.c"
M = 0xFFFFFFFF
C1, C2, C3, C4, C5, C6 = (
    0x243F6A88,
    0x85A308D3,
    0x7F4A7C15,
    0x9E3779B9,
    0x6A09E667,
    0xBB67AE85,
)
TABLE = [
    0x58670A15157776BC,
    0x91D45908EA83412D,
    0xE6E4A71330A9A77A,
]


def u32(x):
    return x & M


def s32(x):
    x &= M
    return x - 0x100000000 if x & 0x80000000 else x


def rol32(x, r):
    x &= M
    return ((x << r) | (x >> (32 - r))) & M


def ror32(x, r):
    x &= M
    return ((x >> r) | (x << (32 - r))) & M


def extract_sections_from_source():
    """Recover the hidden byte stream and the four embedded sections."""
    hidden = bytearray()
    with SOURCE.open("rb") as f:
        for line in f:
            line = line.rstrip(b"\r\n")
            lead = len(line) - len(line.lstrip(b" "))
            s = line[lead:]
            if not (s.startswith(b"(void)(") and b");/*" in s and s.endswith(b"*/")):
                continue

            expr, rest = s.split(b");/*", 1)
            comment = rest[:-2]
            nw = expr.count(b"w")
            nx = len(comment)
            if not (0 <= lead <= 7 and 1 <= nw <= 8 and nx in (3, 7, 11, 15)):
                raise ValueError("malformed carrier line")

            hidden.append(lead | ((nw - 1) << 3) | (((nx - 3) // 4) << 6))

    if len(hidden) != 334767:
        raise ValueError(f"unexpected hidden stream size: {len(hidden)}")

    magic, version, inner_len = struct.unpack_from("<III", hidden, 0)
    if magic != 0xC47A19E3 or version != 0x2001:
        raise ValueError("bad outer container")
    inner = bytes(hidden[12 : 12 + inner_len])
    if len(inner) != inner_len or struct.unpack_from("<I", inner, 0)[0] != 0xEC31A76D:
        raise ValueError("bad inner container")

    sections = []
    for desc in (0x20, 0x30, 0x40, 0x50):
        off, size = struct.unpack_from("<II", inner, desc)
        sec = inner[off : off + size]
        if len(sec) != size:
            raise ValueError("truncated section")
        sections.append(sec)

    return sections, inner


def inv_final(o):
    A = (o >> 32) & M
    B = ror32(o & M, 17) ^ A
    A = ror32(u32(A - C6), 11) ^ B
    X = ror32(u32(B - (C5 + 7)), 17) ^ A
    Bp = ror32(u32(A - C6), 11) ^ X
    Ap = ror32(u32(X - (C5 + 6)), 17) ^ Bp
    Xp = ror32(u32(Bp - C6), 11) ^ Ap
    B4 = ror32(u32(Ap - (C5 + 5)), 17) ^ Xp
    A3 = ror32(u32(Xp - C6), 11) ^ B4
    X2 = ror32(u32(B4 - (C5 + 4)), 17) ^ A3
    B2 = ror32(u32(A3 - C6), 11) ^ X2
    A1 = ror32(u32(X2 - (C5 + 3)), 17) ^ B2
    X0 = ror32(u32(B2 - C6), 11) ^ A1
    B0 = ror32(u32(A1 - (C5 + 2)), 17) ^ X0
    Am1 = ror32(u32(X0 - C6), 11) ^ B0
    Xm2 = ror32(u32(B0 - (C5 + 1)), 17)
    Ai = Xm2 ^ Am1
    Y = ror32(u32(Am1 - C6), 11)
    return u32(Ai - C5), Y ^ Ai


def inv_hcf(data, out):
    """Invert the checker custom 64-bit hash and recover its seed."""
    x, y = inv_final(out)
    n = len(data)
    words = (n + 3) // 4
    ws = []
    for off in range(0, words * 4, 4):
        ch = data[off : off + 4]
        ws.append(int.from_bytes(ch + b"\0" * (4 - len(ch)), "little"))

    for i in range(words - 1, -1, -1):
        w = ws[i]
        yp = ror32(u32(y - x), 13) ^ u32(w + C3)
        xp = u32(ror32(x ^ yp, 7) - w - u32(i * C4))
        x, y = xp, yp

    return ((((y ^ words ^ C2) & M) << 32) | ((x ^ C1) & M)) ^ n


def decrypt_patch(payload, k):
    """Decrypt a section payload into its WPT1 patch stream."""
    kh = u32((k >> 32) ^ 0xD1B54A32)
    t0 = u32(kh + u32(k ^ 0xD192ED03))
    t2 = rol32(u32(t0 ^ 0x3320646E), 16)
    out = bytearray(payload)

    for block in range((len(out) + 15) // 16):
        a5 = u32((block ^ 0x61707865) + t2)
        a4 = u32(kh ^ a5)
        a1 = rol32(a4, 12)
        a4 = u32(t0 + a1)
        a6 = u32(t2 ^ a4)
        a0 = rol32(a6, 8)
        a5 = u32(a5 + a0)
        a1 = u32(a1 ^ a5)
        a6 = rol32(a1, 7)
        a4 = u32(a4 + a6)
        a1 = u32(a0 ^ a4)
        a0 = rol32(a1, 16)
        a5 = u32(a5 + a0)
        a6 = u32(a6 ^ a5)
        a1 = rol32(a6, 12)
        a4 = u32(a4 + a1)
        a0 = u32(a0 ^ a4)
        a6 = rol32(a0, 8)
        a5 = u32(a5 + a6)
        a1 = u32(a1 ^ a5)
        a0 = rol32(a1, 7)
        a4 = u32(a4 + a0)
        a6 = u32(a6 ^ a4)
        a1 = rol32(a6, 16)
        a5 = u32(a5 + a1)
        a0 = u32(a0 ^ a5)
        a6 = rol32(a0, 12)
        a4 = u32(a4 + a6)
        a1 = u32(a1 ^ a4)
        a0 = rol32(a1, 8)
        a5 = u32(a5 + a0)
        a6 = u32(a6 ^ a5)
        a1 = rol32(a6, 7)
        a4 = u32(a4 + a1)
        a0 = u32(a0 ^ a4)
        a6 = rol32(a0, 16)
        a5 = u32(a5 + a6)
        a1 = u32(a1 ^ a5)
        a0 = rol32(a1, 12)
        a4 = u32(a4 + a0)
        a6 = u32(a6 ^ a4)
        a1 = rol32(a6, 8)
        a5 = u32(a5 + a1)
        a0 = u32(a0 ^ a5)
        a6 = rol32(a0, 7)
        a4 = u32(a4 + a6)
        a1 = u32(a1 ^ a4)
        a0 = rol32(a1, 16)
        a5 = u32(a5 + a0)
        a6 = u32(a6 ^ a5)
        a1 = rol32(a6, 12)
        a4 = u32(a4 + a1)
        a0 = u32(a0 ^ a4)
        a6 = rol32(a0, 8)
        a5 = u32(a5 + a6)
        a1 = u32(a1 ^ a5)
        a0 = rol32(a1, 7)
        a4 = u32(a4 + a0)
        a6 = u32(a6 ^ a4)
        a1 = rol32(a6, 16)
        a5 = u32(a5 + a1)
        a0 = u32(a0 ^ a5)
        a6 = rol32(a0, 12)
        a4 = u32(a4 + a6)
        a1 = u32(a1 ^ a4)
        a0 = rol32(a1, 8)
        a5 = u32(a5 + a0)
        a6 = u32(a6 ^ a5)
        a1 = rol32(a6, 7)

        ks = struct.pack("<IIII", a4, a1, a5, a0)
        for j, b in enumerate(ks):
            p = block * 16 + j
            if p < len(out):
                out[p] ^= b

    return bytes(out)


def read_uleb(buf, p):
    v = 0
    for i in range(5):
        b = buf[p]
        p += 1
        v |= (b & 127) << (7 * i)
        if b < 128:
            return v, p
    raise ValueError("bad ULEB128")


def zigzag(v):
    return (v >> 1) ^ -(v & 1)


def apply_patch(P, buf):
    if buf[:4] != b"WPT1":
        raise ValueError("bad patch magic")
    p = 4
    while True:
        op, p = read_uleb(buf, p)
        if op == 0:
            if p != len(buf):
                raise ValueError("trailing patch data")
            return
        if op == 1:  # memmove
            a, p = read_uleb(buf, p)
            d, p = read_uleb(buf, p)
            c, p = read_uleb(buf, p)
            P[d : d + c] = P[a : a + c]
        elif op in (2, 3):  # xor / add
            a, p = read_uleb(buf, p)
            c, p = read_uleb(buf, p)
            v, p = read_uleb(buf, p)
            v = zigzag(v) & M
            for i in range(a, a + c):
                P[i] = u32(P[i] ^ v) if op == 2 else u32(P[i] + v)
        elif op == 4:  # swap
            a, p = read_uleb(buf, p)
            d, p = read_uleb(buf, p)
            c, p = read_uleb(buf, p)
            for i in range(c):
                P[a + i], P[d + i] = P[d + i], P[a + i]
        elif op == 5:  # literal write
            a, p = read_uleb(buf, p)
            c, p = read_uleb(buf, p)
            for i in range(c):
                v, p = read_uleb(buf, p)
                P[a + i] = zigzag(v) & M
        elif op == 6:  # zero
            a, p = read_uleb(buf, p)
            c, p = read_uleb(buf, p)
            P[a : a + c] = [0] * c
        else:
            raise ValueError(f"bad patch opcode {op}")


def extract_chunks_and_patches(sections):
    chunks = []
    patches = []
    for sec in sections[1:4]:
        idx = sec[4]
        if idx >= len(TABLE):
            raise ValueError("bad section index")
        expected = struct.unpack_from("<Q", sec, 32)[0]
        seed = inv_hcf(sec[:32] + sec[40:], expected)
        key = seed ^ 0x9E3779B97F4A7C15
        q1 = struct.unpack_from("<Q", sec, 16)[0]
        chunks.append((key ^ q1 ^ TABLE[idx]).to_bytes(8, "little")[:7])
        patch = decrypt_patch(sec[40:], key)
        if patch[:4] != b"WPT1":
            raise ValueError("patch decryption failed")
        patches.append(patch)
    return chunks, patches


class VM:
    def __init__(self, P, candidate, secondary):
        self.P = P
        self.candidate = candidate
        self.secondary = secondary

    def resolve(self, op, cp, sp):
        if op >= 0:
            if op >= len(self.P):
                raise ValueError("program operand OOB")
            return s32(self.P[op])
        if op == -8:
            if not 0 <= sp < len(self.secondary):
                raise ValueError("secondary cursor OOB")
            return self.secondary[sp]
        if op == -7:
            return s32(sp)
        if op == -6:
            return len(self.secondary)
        if op in (-5, -4):
            return 0
        if op == -3:
            if not 0 <= cp < len(self.candidate):
                raise ValueError("candidate cursor OOB")
            return self.candidate[cp]
        if op == -2:
            return s32(cp)
        if op == -1:
            return len(self.candidate)
        raise ValueError("bad special operand")

    def decode(self, raw, cp, sp):
        op = s32(raw) >> 1
        if raw & 1:
            op = s32(self.resolve(op, cp, sp))
        if not (-8 <= op < 0 or 0 <= op < len(self.P)):
            raise ValueError("decoded operand OOB")
        return op

    def run(self, maxsteps=500000):
        ip = cp = sp = 0
        out = bytearray()
        steps = 0
        while steps < maxsteps:
            if ip < 0 or ip + 2 >= len(self.P):
                return {"status": "badip", "steps": steps, "ip": ip}
            r0, r1, r2 = self.P[ip : ip + 3]
            try:
                d = self.decode(r0, cp, sp)
                target = self.decode(r1, cp, sp)
                src = self.decode(r2, cp, sp)
                old = self.resolve(d, cp, sp)
                sv = self.resolve(src, cp, sp)
            except ValueError as e:
                return {"status": "error", "steps": steps, "ip": ip, "error": str(e)}

            res = s32(u32(old - sv))
            steps += 1
            if d >= 0:
                self.P[d] = u32(res)
            elif d == -2:
                cp = res
            elif d == -7:
                sp = res
            elif d == -4:
                out.append(res & 255)
            elif d == -5:
                return {
                    "status": "trigger" if res == 1 else "reject",
                    "res": res,
                    "src_value": sv,
                    "steps": steps,
                    "ip": ip,
                    "out": bytes(out),
                    "cp": cp,
                    "sp": sp,
                }
            else:
                return {"status": "baddest", "dest": d, "steps": steps, "ip": ip}

            if res > 0:
                ip += 3
            elif target >= 0:
                ip = target
            else:
                return {
                    "status": "halt",
                    "target": target,
                    "steps": steps,
                    "ip": ip,
                    "out": bytes(out),
                    "cp": cp,
                    "sp": sp,
                }

        return {"status": "maxsteps", "steps": steps}


def build_final_program(prefix, sections, inner, patches):
    if len(sections[0]) != 32768 * 4:
        raise ValueError("unexpected VM program size")
    P = list(struct.unpack("<32768I", sections[0]))
    candidate = bytearray(prefix + b"???????")

    # The checker runs one VM stage, then applies one patch, three times.
    # These executions mutate P, so they must be emulated rather than skipped.
    for stage in range(3):
        r = VM(P, candidate, inner).run()
        if r["status"] != "trigger" or r.get("res") != 1:
            raise ValueError(f"stage {stage} did not validate: {r}")
        apply_patch(P, patches[stage])

    return P


def direct_operand(raw):
    return s32(raw) >> 1


def find_constraint_blocks(P):
    starts = []
    # Stage 3 begins at instruction offset 2913 after its setup code.
    # Every parity block starts by clearing accumulator cell 24565.
    for ip in range(2913, 24549, 3):
        if direct_operand(P[ip]) == 24565 and direct_operand(P[ip + 2]) == 24565:
            starts.append(ip)
    if len(starts) != 56:
        raise ValueError(f"expected 56 parity blocks, found {len(starts)}")

    subsets = []
    for j, st in enumerate(starts):
        en = starts[j + 1] if j + 1 < len(starts) else 24549
        selected = []
        for ip in range(st, en, 3):
            src = direct_operand(P[ip + 2])
            if 24582 <= src <= 24637:
                selected.append(src - 24582)
        subsets.append(selected)
    return starts, subsets


def run_isolated_block(base, inner, prefix, starts, subsets, j, parity_one):
    """Run one final parity block and report its mismatch flag."""
    P = base.copy()
    for k in range(56):
        P[24582 + k] = 0
    if parity_one:
        if not subsets[j]:
            raise ValueError("empty parity subset")
        P[24582 + subsets[j][0]] = 1

    # Scratch/global cells used by the final constraint circuit.
    for k in (24555, 24560, 24561, 24562, 24563, 24564, 24565, 24566):
        P[k] = 0

    vm = VM(P, bytearray(prefix + b"???????"), inner)
    ip = starts[j]
    end = starts[j + 1]
    steps = 0

    while ip != end and steps < 5000:
        r0, r1, r2 = P[ip : ip + 3]
        d = vm.decode(r0, 0, 0)
        target = vm.decode(r1, 0, 0)
        src = vm.decode(r2, 0, 0)
        if d < 0:
            raise ValueError("unexpected special destination inside parity block")
        res = s32(u32(vm.resolve(d, 0, 0) - vm.resolve(src, 0, 0)))
        P[d] = u32(res)
        ip = ip + 3 if res > 0 else target
        steps += 1

    if ip != end:
        raise ValueError(f"isolated block {j} failed to terminate at next block")
    return s32(P[24563])


def gf2_rref(rows, nvars):
    rows = [[mask, rhs] for mask, rhs in rows]
    pivots = []
    rank = 0
    for col in range(nvars):
        pivot = next((r for r in range(rank, len(rows)) if (rows[r][0] >> col) & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        pmask, prhs = rows[rank]
        for r in range(len(rows)):
            if r != rank and ((rows[r][0] >> col) & 1):
                rows[r][0] ^= pmask
                rows[r][1] ^= prhs
        pivots.append(col)
        rank += 1
    return rows, pivots


def bits_to_tail(x):
    out = bytearray(7)
    for j in range(7):
        b = 0
        for k in range(8):
            b |= ((x >> (j * 8 + k)) & 1) << k
        out[j] = b
    return bytes(out)


def solve_tail(base, inner, prefix):
    starts, subsets = find_constraint_blocks(base)

    # Blocks 0..54 reveal their expected parity through the common mismatch flag.
    # Block 55 is the final acceptance block, so we leave one GF(2) variable free
    # and let the real VM select the correct solution.
    rhs = []
    for j in range(55):
        z = run_isolated_block(base, inner, prefix, starts, subsets, j, False)
        o = run_isolated_block(base, inner, prefix, starts, subsets, j, True)
        if z == 0 and o != 0:
            rhs.append(0)
        elif o == 0 and z != 0:
            rhs.append(1)
        else:
            raise ValueError(f"could not infer expected parity for block {j}: {z=}, {o=}")

    rows = []
    for j in range(55):
        mask = 0
        for bit in subsets[j]:
            mask ^= 1 << bit
        rows.append([mask, rhs[j]])

    rr, pivots = gf2_rref(rows, 56)
    if len(pivots) != 55:
        raise ValueError(f"unexpected GF(2) rank: {len(pivots)}")
    free = [i for i in range(56) if i not in pivots]

    for assignment in range(1 << len(free)):
        x = 0
        for i, col in enumerate(free):
            if (assignment >> i) & 1:
                x |= 1 << col

        # Rows are RREF, so solve each pivot from its row.
        for r in range(len(pivots) - 1, -1, -1):
            col = pivots[r]
            mask, want = rr[r]
            rest = mask & ~(1 << col)
            val = want ^ ((rest & x).bit_count() & 1)
            if val:
                x |= 1 << col
            else:
                x &= ~(1 << col)

        tail = bits_to_tail(x)
        candidate = prefix + tail
        result = VM(base.copy(), bytearray(candidate), inner).run()
        if result["status"] == "trigger" and result.get("res") == 1:
            return tail, result, len(pivots), free

    raise ValueError("no final candidate passed the VM")


def main():
    sections, inner = extract_sections_from_source()
    print(f"[+] extracted {len(sections)} hidden sections from scouting_report.c")

    chunks, patches = extract_chunks_and_patches(sections)
    prefix = b"".join(chunks)
    print("[+] recovered first 21 bytes:", prefix.decode())

    base = build_final_program(prefix, sections, inner, patches)
    tail, result, rank, free = solve_tail(base, inner, prefix)
    flag = prefix + tail

    print("[+] final GF(2) rank:", rank, "free bit(s):", free)
    print("[+] recovered final 7 bytes:", tail.decode())
    print("[+] final VM validation:", result["status"], "res=", result["res"], "steps=", result["steps"])
    print(f"<FLAG>{flag.decode()}</FLAG>")


if __name__ == "__main__":
    main()
