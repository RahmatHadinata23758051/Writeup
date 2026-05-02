from z3 import And, BitVec, BitVecVal, Concat, RotateLeft, RotateRight, Solver


TR = bytes.fromhex("b42e08332a0d22dccf6579a0a6f58e1c")
KBF = bytes.fromhex(
    "d267846906e3f29b323359e784a1d94c"
    "69c2e329ed95175545e22618fe0ff7f5"
    "d76f2a75080f338bf014af1e4ebcfc2c"
    "b68887228bb978b24956f8c850687cd0"
    "3f42541cadc6514a1d81bb0c7aff5825"
    "ddf67e79feef40077aa01f66942ad5c1"
)
RTBL = [
    0x14, 0x1E, 0x12, 0x17, 0x0C, 0x13,
    0x13, 0x18, 0x06, 0x19, 0x1B, 0x0B,
    0x0D, 0x15, 0x1A, 0x0C, 0x1E, 0x0A,
    0x0D, 0x17, 0x07, 0x19, 0x16, 0x1C,
]

PRE_XOR = BitVecVal(0xB00B800B, 32)
ROUND_XOR = BitVecVal(0x8008B00B, 32)
MASK32 = BitVecVal(0xFFFFFFFF, 32)
K = [BitVecVal(int.from_bytes(KBF[i:i + 4], "little"), 32) for i in range(0, len(KBF), 4)]
T = [BitVecVal(int.from_bytes(TR[i:i + 4], "little"), 32) for i in range(0, len(TR), 4)]


def rr(state, rot, key):
    return (RotateRight(state, rot) ^ key ^ ROUND_XOR) & MASK32


def rl(state, rot, key):
    return (RotateLeft(state, rot) ^ key ^ ROUND_XOR) & MASK32


def pack32(chunk):
    return Concat(chunk[3], chunk[2], chunk[1], chunk[0])


def main():
    bs = [BitVec(f"b{i}", 8) for i in range(16)]
    s = Solver()

    for b in bs:
        s.add(And(b >= 0x20, b <= 0x7E))

    x0, x1, x2, x3 = [pack32(bs[i:i + 4]) for i in range(0, 16, 4)]

    state = x0 ^ PRE_XOR
    for idx, fn in zip(range(6), [rr, rl, rr, rl, rr, rl]):
        state = fn(state, RTBL[idx], K[idx])
    r8 = state

    x1 ^= r8
    state = x1
    for idx, fn in zip(range(6, 12), [rr, rl, rr, rl, rr, rl]):
        state = fn(state, RTBL[idx], K[idx])
    r4 = state

    x2 ^= r4
    state = x2
    for idx, fn in zip(range(12, 18), [rr, rl, rr, rl, rr, rl]):
        state = fn(state, RTBL[idx], K[idx])
    r5 = state

    x3 ^= r5
    state = x3
    for idx, fn in zip(range(18, 24), [rr, rl, rr, rl, rr, rl]):
        state = fn(state, RTBL[idx], K[idx])
    r0 = state

    s.add(r8 == T[0], r4 == T[1], r5 == T[2], r0 == T[3])

    if s.check().r != 1:
        raise SystemExit("no solution")

    m = s.model()
    inner = bytes(m[b].as_long() for b in bs).decode()
    print(f"CBC{{{inner}}}")


if __name__ == "__main__":
    main()
