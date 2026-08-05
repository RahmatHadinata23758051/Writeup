#!/usr/bin/env python3
from pathlib import Path
import hashlib
import re
import struct

MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
BASE_VADDR = 0x400000
BASE_OFF = 0x10000


def file_off(vaddr: int) -> int:
    return vaddr - BASE_VADDR + BASE_OFF


def u32(x: int) -> int:
    return x & MASK32


def u64(x: int) -> int:
    return x & MASK64


def ror(x: int, n: int, bits: int) -> int:
    mask = (1 << bits) - 1
    n &= bits - 1
    x &= mask
    return ((x >> n) | (x << (bits - n))) & mask


def ror8(x: int, n: int) -> int:
    return ror(x, n, 8)


def ld32(buf: bytearray, off: int) -> int:
    return struct.unpack_from('<I', buf, off)[0]


def ld64(buf: bytearray, off: int) -> int:
    return struct.unpack_from('<Q', buf, off)[0]


def st64(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into('<Q', buf, off, val & MASK64)


def run_seal_vm(blob: bytes) -> tuple[bytearray, bytes]:
    """Reproduce the small custom VM that creates the first 20-char seal."""
    mem = bytearray(0x400)

    # q4 seed and 0x60-byte VM program from .rodata.
    mem[0x280:0x290] = blob[file_off(0x400d90):file_off(0x400d90) + 16]
    mem[0x2b0:0x310] = blob[file_off(0x400da0):file_off(0x400da0) + 0x60]

    w9 = ld32(mem, 0x281)
    x12 = 0xbb67ae8584caa73b
    x8 = 0x9cd7c967f3bcc924 ^ ((w9 << 8) & MASK64)
    x9 = ld64(mem, 0x288)
    st64(mem, 0x310, x8)
    st64(mem, 0x318, x9 ^ x12)
    st64(mem, 0x320, 0x3c6ef372fe94f806)

    x6 = 0xa54ff53a5f1d36f1 ^ (x9 >> 56)
    mul_const = 0xd6e8feb86659fd93
    add_const = 0x9e3779b97f4a7c15
    c2 = 0xff51afd7ed558ccd
    c3 = 0xa24baed4963ee407
    x17 = 0x0101010101010101
    x18 = 0x00000100000001b3
    alphabet = blob[file_off(0x400e88):file_off(0x400e88) + 32]

    # The generated response begins with literal "wing-".
    mem[0x294:0x298] = blob[file_off(0x400e10):file_off(0x400e10) + 4]
    mem[0x298] = ord('-')

    for idx in range(20):
        x6 = u64(x6 + add_const)
        x6 = u64(idx * 0x27 + x6)
        st64(mem, 0x328, x6)

        pc = 0
        while True:
            op = mem[0x2b0 + pc]
            dst = mem[0x2b0 + pc + 1]
            src = mem[0x2b0 + pc + 2]
            imm = mem[0x2b0 + pc + 3]
            kind = op & 7

            if kind == 0:
                val = u64(imm * x17 + ld64(mem, 0x310 + src * 8))
                st64(mem, 0x310 + dst * 8, ld64(mem, 0x310 + dst * 8) ^ val)
            elif kind == 1:
                val = u64(imm * add_const + ror(ld64(mem, 0x310 + src * 8), u32(-imm), 64))
                st64(mem, 0x310 + dst * 8, ld64(mem, 0x310 + dst * 8) + val)
            elif kind == 2:
                val = u64(imm * x18) & 0xfffffffffffe
                val = u64(val ^ mul_const)
                st64(mem, 0x310 + dst * 8, ld64(mem, 0x310 + dst * 8) * val)
            elif kind == 3:
                src_val = ld64(mem, 0x310 + src * 8)
                val = ror(src_val, u32(-imm), 64) ^ ld64(mem, 0x310 + dst * 8)
                st64(mem, 0x310 + dst * 8, ror(val, u32(-(u32(src_val) ^ imm)), 64))
            elif kind == 4:
                val = ld64(mem, 0x310 + dst * 8)
                val = u64(val ^ (val >> 13))
                val = u64(val * c2)
                val = u64(val ^ (val >> 29))
                st64(mem, 0x310 + dst * 8, val)
            elif kind == 5:
                src_val = ld64(mem, 0x310 + src * 8)
                val = u64(ld64(mem, 0x310 + dst * 8) + (src_val ^ u64((imm + 1) * c3)))
                st64(mem, 0x310 + dst * 8, ror(val, u32(-(u32(dst * 11 + imm))), 64))
            elif kind == 6:
                a = ld64(mem, 0x310 + src * 8)
                b = ld64(mem, 0x310 + dst * 8)
                st64(mem, 0x310 + dst * 8, a)
                st64(mem, 0x310 + src * 8, b)
            else:
                rot = u32((dst << 3) - dst) ^ imm
                val = ror(ld64(mem, 0x310 + src * 8) + add_const, u32(-rot), 64)
                st64(mem, 0x310 + dst * 8, val ^ ld64(mem, 0x310 + dst * 8))

            old_pc = pc
            pc += 4
            if old_pc >= 0x5c:
                break

        s0 = ld64(mem, 0x310)
        s1 = ld64(mem, 0x318)
        s2 = ld64(mem, 0x320)
        s3 = ld64(mem, 0x328)
        x6 = s3  # The real register is refreshed from state[3] before the next VM round.

        r = ror(s1, u32(-3 - idx), 64)
        sel = (u32(r) ^ u32(s2) ^ u32(s0) ^ u32(s3)) & 0x1f
        mem[0x299 + idx] = alphabet[sel]
        st64(mem, 0x310, s0 ^ u64((idx + 1) * mul_const))

    return mem, bytes(mem[0x294:0x294 + 25])


def hash32(data: bytes, seed32: int) -> int:
    h = seed32 ^ 0xa5a5a5a5
    acc = 0
    for b in data:
        t = u32(acc + b)
        acc = u32(acc + 0x27)
        h = u32(t ^ h)
        t = u32(h + 0x9e3779b9)
        h = u32(t + (h >> 7))
        h = ror(h, 27, 32)
        h = u32(h ^ (h >> 13))
        h = u32(h * 0x85ebca6b)
    return h


def hash64(data: bytes, seed64: int) -> int:
    h = u64(seed64 ^ 0xfed9afdce08dd8e2)
    acc = 0
    for i, b in enumerate(data):
        h = u64((acc + b) ^ h)
        acc = u64(acc + 0x9d)
        t = u64(h + 0x9e3779b97f4a7c15)
        h = u64(t + (h >> 11))
        rot = i if i < 0x11 else i + 0x2f
        h = ror(h, u32(-3 - rot), 64)
        h = u64(h ^ (h >> 29))
        h = u64(h * 0xbf58476d1ce4e5b9)
    return h


def build_composite(blob: bytes) -> tuple[bytes, bytes]:
    mem, first = run_seal_vm(blob)
    q4 = bytes(mem[0x280:0x290])
    hex_alpha = blob[file_off(0x400ea9):file_off(0x400ea9) + 16]

    seal1 = first
    seal2_val = hash32(seal1, int.from_bytes(q4[:4], 'little'))
    seal2 = bytes(hex_alpha[(seal2_val >> shift) & 0xf] for shift in range(28, -1, -4))

    prefix = seal1 + b':' + seal2
    seal3_val = hash64(prefix, int.from_bytes(q4[8:16], 'little'))
    seal3 = bytes(hex_alpha[(seal3_val >> shift) & 0xf] for shift in range(60, -1, -4))

    return prefix + b':' + seal3, q4


def decrypt_payload(blob: bytes, composite: bytes, q4: bytes) -> bytes:
    d1 = hashlib.md5(composite).digest()
    d2 = hashlib.md5(composite + q4).digest()

    # This reproduces the final MD5 gate. It is a useful sanity check before decrypting.
    keymat = bytearray(44)
    keymat[:32] = d1.hex().encode()
    keymat[32:40] = d2[:8]
    keymat[40] = q4[2] ^ 0x13
    keymat[41] = ((((q4[7] >> 5) & 7) | ((q4[7] << 3) & 0xff)) ^ 0x37) & 0xff
    keymat[42] = 0xa9
    keymat[43] = q4[0] ^ 0x1b
    gate_digest = hashlib.md5(keymat).digest()

    target = bytearray(16)
    ro_e00 = blob[file_off(0x400e00):file_off(0x400e00) + 16]
    j = 3
    for i in range(16):
        target[i] = ro_e00[i] ^ ((i * 0x13) & 0xff) ^ q4[j & 0xf] ^ 0x5a
        j += 5
    if gate_digest != bytes(target):
        raise RuntimeError('MD5 validation gate did not match')

    success_hash = hash32(composite, int.from_bytes(q4[:4], 'little'))
    handler = (success_hash ^ (q4[13] ^ d2[5] ^ d1[9])) & 3

    cipher_off = file_off(0x400eec) + handler * 0x400
    cipher = blob[cipher_off:cipher_off + 0x400]

    plain = bytearray(0x400)
    x12 = 3
    x14 = handler
    x15 = handler
    x10 = handler * 0x37

    # The program overwrites sp+0x130 with q4 immediately before decrypting.
    for i, c in enumerate(cipher):
        b = c ^ (x10 & 0xff) ^ d2[x12 & 0xf] ^ q4[x14 & 0xf]
        rot = (handler + i) & 7
        if rot:
            b = ror8(b, rot)
        b ^= d1[x15 & 0xf]
        plain[i] = b & 0xff

        x15 = u64(x15 + 7)
        x14 = u64(x14 + 5)
        x12 = u64(x12 + 0xb)
        x10 = u64(x10 + 0xd)

    return bytes(plain)


def main() -> None:
    blob = Path('whispering_feather').read_bytes()
    composite, q4 = build_composite(blob)
    payload = decrypt_payload(blob, composite, q4)

    m = re.search(rb'KaliTeam\{[^}\n]+\}', payload)
    if not m:
        raise RuntimeError('flag not found in decrypted payload')

    print(f'Composite response: {composite.decode()}')
    print(m.group(0).decode())


if __name__ == '__main__':
    main()
