#!/usr/bin/env python3

def u32(x):
    return x & 0xFFFFFFFF


def rol32(x, n):
    return u32((x << n) | (x >> (32 - n)))


def derive_seed2(board, moves):
    s = 0xDEADBEEF
    for i in range(9):
        s ^= u32(u32(i - 0x3F001200) * u32(board[i] + 1))
        s = u32(s)
    s ^= u32(moves * 0xCAFEBABE)
    return rol32(s, 7)


def emit(seed):
    ef2 = bytes.fromhex("7c48e11454d3cd0599c3d18dd23cf2dc9e564091c5de")
    x = seed
    out = []
    for i in range(0x16):
        x ^= u32(x << 7)
        x = u32(x)
        x ^= x >> 13
        x = u32(x)
        x ^= u32(x << 3)
        x = u32(x)
        out.append((x ^ ef2[i]) & 0xFF)
    return bytes(out).decode("ascii")


def main():
    # target board encoded in cq2:
    # [2,2,1,
    #  0,1,0,
    #  1,0,0] and moves=5
    board = [2, 2, 1, 0, 1, 0, 1, 0, 0]
    seed = derive_seed2(board, 5)
    secret = emit(seed)
    print(f"uni6CTF{{{secret}}}")


if __name__ == "__main__":
    main()
