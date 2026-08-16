#!/usr/bin/env python3
from pathlib import Path
from collections import Counter

MASK = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
MIX_A = 0xBF58476D1CE4E5B9
MIX_B = 0x94D049BB133111EB
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def u64(bs: bytes) -> int:
    return int.from_bytes(bs, "little")


def u32(bs: bytes) -> int:
    return int.from_bytes(bs, "little")


def rol8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    return ((x >> n) | (x << (8 - n))) & 0xFF


def rol64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK


def splitmix_body(x: int) -> int:
    """Same SplitMix64 finalizer shape used twice by the binary."""
    x &= MASK
    x ^= x >> 30
    x = (x * MIX_A) & MASK
    x ^= x >> 27
    x = (x * MIX_B) & MASK
    x ^= x >> 31
    return x & MASK


def invmod_256(a: int) -> int:
    # a is always odd because the binary ORs it with 1.
    for x in range(1, 256, 2):
        if (a * x) & 0xFF == 1:
            return x
    raise ValueError(f"no inverse for {a:#x}")


def load_mist(binary: Path) -> bytes:
    data = binary.read_bytes()
    # readelf shows .mist at file offset 0x2090, size 0xa20.
    mist = data[0x2090:0x2090 + 0xA20]
    if mist[:4] != b"MRR2":
        raise RuntimeError("unexpected .mist header")
    return mist


def build_instruction_stream(mist: bytes):
    seed = u64(mist[8:16])
    fnv = FNV_OFFSET
    ops = []

    ebx = 0x29
    while True:
        # The folded tape visits all 320 qwords in .mist because gcd(0x49, 0x140) == 1.
        idx = ebx % 0x140
        tape_qword = u64(mist[0x10 + idx * 8:0x10 + idx * 8 + 8])

        x = (0xD6E8FEB86659FD93 * idx) & MASK
        x ^= seed
        x ^= 0xA17E5EEDC0DEC0DE
        x = (x + GOLDEN) & MASK
        key = tape_qword ^ splitmix_body(x)
        key_bytes = key.to_bytes(8, "little")

        for b in key_bytes:
            fnv ^= b
            fnv = (fnv * FNV_PRIME) & MASK

        selector = ((((0x1D * idx - 0x59) & 0xFFFFFFFF) ^ u32(key_bytes[:4])) & 0xFF) % 7
        ops.append((idx, selector, key_bytes))

        ebx += 0x49
        if ebx == 0x5B69:
            break

    return seed, fnv, ops


def inverse_transform(final_state: bytes, ops) -> bytes:
    st = bytearray(final_state)

    for idx, selector, key in reversed(ops):
        pos = key[1] & 0x0F
        dl = key[4]
        dh = key[5]
        rot_src = key[3]
        swap_src = key[2]
        dword4 = u32(key[4:8])

        if selector == 0:
            # forward: st[pos] ^= dl
            st[pos] ^= dl

        elif selector == 1:
            # forward: st[pos] += dl
            st[pos] = (st[pos] - dl) & 0xFF

        elif selector == 2:
            # forward: rol8(st[pos], count)
            count = rot_src & 7
            if count == 0:
                count = 1
            st[pos] = ror8(st[pos], count)

        elif selector == 3:
            # swap is self-inverse
            other = swap_src & 0x0F
            st[pos], st[other] = st[other], st[pos]

        elif selector == 4:
            # forward: st[pos] = (odd_mul * st[pos] + dh) mod 256
            mul = dl | 1
            st[pos] = ((st[pos] - dh) * invmod_256(mul)) & 0xFF

        elif selector == 5:
            # Feistel-like half transform.
            # forward: (L, R) -> (R, F(R) ^ L), so invert with R = newL.
            new_l = u64(st[:8])
            new_r = u64(st[8:16])
            old_r = new_l

            t = (dword4 ^ 0xA5C39E71) & 0xFFFFFFFF
            t |= (dword4 << 32) & MASK
            t = (t + idx * FNV_PRIME) & MASK
            t = (t + old_r) & MASK
            t = rol64(t, (rot_src % 63) + 1)

            f = (((pos | 1) * 2) & MASK) ^ 0x9E3779B185EBCA87
            f = (f * old_r) & MASK

            old_l = (new_r ^ f ^ t) & MASK
            st[:8] = old_l.to_bytes(8, "little")
            st[8:16] = old_r.to_bytes(8, "little")

        elif selector == 6:
            # forward: new[i] = old[(shift + i) & 15]
            shift = rot_src & 0x0F
            if shift == 0:
                shift = 1
            new = st[:]
            old = bytearray(16)
            for i in range(16):
                old[(shift + i) & 0x0F] = new[i]
            st = old

        else:
            raise RuntimeError("bad selector")

    return bytes(st)


def forward_transform(initial_state: bytes, ops) -> bytes:
    """Forward emulator used only as a self-check for the recovered body."""
    st = bytearray(initial_state)
    for idx, selector, key in ops:
        pos = key[1] & 0x0F
        dl = key[4]
        dh = key[5]
        rot_src = key[3]
        swap_src = key[2]
        dword4 = u32(key[4:8])

        if selector == 0:
            st[pos] ^= dl
        elif selector == 1:
            st[pos] = (st[pos] + dl) & 0xFF
        elif selector == 2:
            count = rot_src & 7
            if count == 0:
                count = 1
            st[pos] = rol8(st[pos], count)
        elif selector == 3:
            other = swap_src & 0x0F
            st[pos], st[other] = st[other], st[pos]
        elif selector == 4:
            st[pos] = ((dl | 1) * st[pos] + dh) & 0xFF
        elif selector == 5:
            l = u64(st[:8])
            r = u64(st[8:16])
            t = (dword4 ^ 0xA5C39E71) & 0xFFFFFFFF
            t |= (dword4 << 32) & MASK
            t = (t + idx * FNV_PRIME) & MASK
            t = (t + r) & MASK
            t = rol64(t, (rot_src % 63) + 1)
            f = (((pos | 1) * 2) & MASK) ^ 0x9E3779B185EBCA87
            f = (f * r) & MASK
            st[:8] = r.to_bytes(8, "little")
            st[8:16] = (f ^ l ^ t).to_bytes(8, "little")
        elif selector == 6:
            shift = rot_src & 0x0F
            if shift == 0:
                shift = 1
            old = st[:]
            for i in range(16):
                st[i] = old[(shift + i) & 0x0F]
    return bytes(st)


def derive_final_state(mist: bytes, seed: int, fnv: int) -> bytes:
    target = mist[-16:]
    final_key = fnv ^ seed
    final_state = bytearray(16)

    for i, target_byte in enumerate(target):
        x = ((i * GOLDEN) & MASK) ^ final_key
        x = (x + GOLDEN) & MASK
        mask_byte = splitmix_body(x) & 0xFF
        final_state[i] = target_byte ^ mask_byte

    return bytes(final_state)


def main() -> None:
    binary = Path(__file__).with_name("afterimage")
    mist = load_mist(binary)
    seed, fnv, ops = build_instruction_stream(mist)
    final_state = derive_final_state(mist, seed, fnv)
    body = inverse_transform(final_state, ops)

    if forward_transform(body, ops) != final_state:
        raise RuntimeError("forward self-check failed")
    if not all(chr(c).isalnum() for c in body):
        raise RuntimeError(f"recovered body is not alphanumeric: {body!r}")

    print(f"seed       : 0x{seed:016x}")
    print(f"ops        : {len(ops)} {dict(sorted(Counter(op[1] for op in ops).items()))}")
    print(f"fnv        : 0x{fnv:016x}")
    print(f"final state: {final_state.hex()}")
    print(f"body       : {body.decode()}")
    print(f"flag       : 0xV01D{{{body.decode()}}}")


if __name__ == "__main__":
    main()
