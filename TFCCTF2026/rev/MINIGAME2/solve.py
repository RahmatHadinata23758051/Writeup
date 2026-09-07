#!/usr/bin/env python3
from pathlib import Path

MASK = (1 << 64) - 1
MIX = 0xBF58476D1CE4E5B9
OUT_MUL = 0x2545F4914F6CDD1D


def u64(x: int) -> int:
    return x & MASK


def ror64(x: int, n: int) -> int:
    return ((x >> n) | ((x << (64 - n)) & MASK)) & MASK


def absorb(state: int, byte: int, const: int) -> int:
    """Translate the repeated block in 0x11ef760."""
    tmp = u64(byte * const + const)
    mixed = u64(ror64(state, 0x33) * MIX)
    tmp ^= mixed
    return u64((mixed >> 0x1D) ^ tmp)


def derive_seed(key: bytes) -> int:
    # Initial three bytes are handled in a slightly unrolled form in the binary.
    rax = u64(key[0] * 0x9E3779B97F4A7C15 + 0x9E3779B97F4A7C15)
    state = ror64(0x243F6A8885A308D3 ^ rax, 0x33)

    tmp = u64(key[1] * 0x9E3778B97F4A7DA6 + 0x9E3778B97F4A7DA6)
    state = u64(state * MIX)
    tmp ^= state
    state = u64((state >> 0x1D) ^ tmp)

    state = absorb(state, key[2], 0x9E377BB97F4A7F73)

    constants = [
        0x9E377AB97F4A790C, 0x9E377DB97F4A7AD9,
        0x9E377CB97F4A746A, 0x9E377FB97F4A7627,
        0x9E377EB97F4A77F0, 0x9E3771B97F4A718D,
        0x9E3770B97F4A735E, 0x9E3773B97F4A6CEB,
        0x9E3772B97F4A6EA4, 0x9E3775B97F4A6871,
        0x9E3774B97F4A6A02, 0x9E3777B97F4A6BDF,
        0x9E3776B97F4A6568,
    ]
    for b, c in zip(key[3:], constants):
        state = absorb(state, b, c)

    mixed = u64(ror64(state, 0x33) * MIX)
    seed = 0x13198A2E03707344 ^ mixed
    seed ^= mixed >> 0x1D
    return u64(seed)


def next_xorshift(seed: int) -> int:
    seed ^= seed >> 12
    seed = u64(seed ^ (seed << 25))
    seed ^= seed >> 27
    return u64(seed)


def decrypt(binary: bytes) -> bytes:
    # .rodata is loaded at vaddr 0x1000240 with file offset 0x240, so
    # vaddr 0x1000880 -> file offset 0x880, and 0x100f7d5 -> 0xf7d5.
    key = binary[0x880:0x890]
    ciphertext = binary[0xF7D5:0xF7FC]  # 39 bytes

    seed = derive_seed(key)
    out = bytearray()
    for c in ciphertext:
        seed = next_xorshift(seed)
        keystream = (u64(seed * OUT_MUL) >> 56) & 0xFF
        out.append(c ^ keystream)
    return bytes(out)


def main() -> None:
    candidates = [Path("./minigame2"), Path("./minigame2")]
    binary_path = next((p for p in candidates if p.exists()), None)
    if binary_path is None:
        raise SystemExit("binary tidak ditemukan: taruh script di folder yang sama dengan mini_game(2)")

    flag = decrypt(binary_path.read_bytes()).decode()
    print(flag)


if __name__ == "__main__":
    main()

