#!/usr/bin/env python3
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

BIN = "black_ledger"
BASE = 0x400000
MASK = 0xFFFFFFFF


def ror(x, n):
    n &= 31
    return ((x >> n) | ((x << (32 - n)) & MASK)) & MASK


def rol(x, n):
    n &= 31
    return ((x << n) & MASK) | (x >> (32 - n))


def subw(tbl, x):
    return (
        tbl[x & 0xFF]
        | (tbl[(x >> 8) & 0xFF] << 8)
        | (tbl[(x >> 16) & 0xFF] << 16)
        | (tbl[(x >> 24) & 0xFF] << 24)
    )


def inv_table(tbl):
    inv = [0] * 256
    for i, v in enumerate(tbl):
        inv[v] = i
    return inv


def modinv_odd(a):
    x = 1
    for _ in range(5):
        x = (x * (2 - a * x)) & MASK
    return x


def main():
    data = Path(BIN).read_bytes()
    get = lambda a, n: data[a - BASE : a - BASE + n]

    T0 = list(get(0x4010E0, 0x100))
    T1 = list(get(0x4011E0, 0x100))
    TR = list(get(0x4013C0, 0xA0))
    RB = list(get(0x401460, 0x64))
    TOP4 = list(get(0x4014D0, 0x100))
    TOP11 = list(get(0x4015D0, 0x100))

    C2 = list(struct.unpack("<IIII", get(0x402710, 16)))
    C1 = list(struct.unpack("<IIII", get(0x402720, 16)))
    C0 = list(struct.unpack("<IIII", get(0x402730, 16)))

    def rc(r):
        r0, r1, r2, r3 = struct.unpack("<IIII", bytes(TR[r * 16 : (r + 1) * 16]))
        rb0 = RB[r * 10 : r * 10 + 5]
        rb1 = RB[r * 10 + 5 : r * 10 + 10]
        return r0, r1, r2, r3, rb0, rb1

    def f80(a, b, c, rb):
        t = subw(T0, ror(a ^ b, -rb[0]))
        t = (t + c) & MASK
        u = ror(b, -rb[2]) ^ t ^ ror(t, -rb[1])
        u = subw(T1, u)
        v = (ror(c, -rb[3]) + u) & MASK
        return ror(v, -rb[4]) ^ v

    # Recover first 16 bytes by reversing stage1
    w20_in9, w22_in9, last0, last9 = C2
    r0, r1, r2, r3, rb0, rb1 = rc(9)
    w13_in9 = last0 ^ f80(w20_in9, r1, r3, rb1)
    w12_in9 = last9 ^ f80(w22_in9, r0, r2, rb0)

    w12_post, w13_post, w22_post, w20_post = w12_in9, w13_in9, w22_in9, w20_in9

    for r in range(8, -1, -1):
        r0, r1, r2, r3, rb0, rb1 = rc(r)
        if r % 2 == 0:
            w20_pre = w13_post
            w22_pre = w12_post
            t0 = w20_post
            t9 = w22_post
        else:
            w22_pre = w13_post
            w20_pre = w12_post
            t0 = w22_post
            t9 = w20_post

        w13_pre = t0 ^ f80(w20_pre, r1, r3, rb1)
        w12_pre = t9 ^ f80(w22_pre, r0, r2, rb0)
        w12_post, w13_post, w22_post, w20_post = w12_pre, w13_pre, w22_pre, w20_pre

    first = [w12_post, w13_post, w22_post, w20_post]

    # Extract exact stage2 schedule from real code
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(0, 0x2000000)
    mu.mem_write(BASE, data)
    mu.reg_write(UC_ARM64_REG_SP, 0x900000)
    mu.reg_write(UC_ARM64_REG_X21, 0x500000)
    mu.reg_write(UC_ARM64_REG_X8, 0)
    mu.reg_write(UC_ARM64_REG_X9, 0x4016D0)
    mu.reg_write(UC_ARM64_REG_X11, 0x4010D0)
    mu.reg_write(UC_ARM64_REG_W12, 0x25390348)
    mu.reg_write(UC_ARM64_REG_W10, 0x6D2B79F5)
    for reg, addr in [
        (UC_ARM64_REG_Q27, 0x4026F0),
        (UC_ARM64_REG_Q28, 0x4026F8),
        (UC_ARM64_REG_Q29, 0x402700),
    ]:
        mu.reg_write(reg, int.from_bytes(get(addr, 8) + b"\x00" * 8, "little"))

    ops = []

    def schedule_hook(uc, addr, size, _):
        if addr == 0x4009E8:
            ops.append(
                (
                    uc.reg_read(UC_ARM64_REG_W13) & 0xFF,
                    uc.reg_read(UC_ARM64_REG_W1) & 7,
                    uc.reg_read(UC_ARM64_REG_W14) & 7,
                    uc.reg_read(UC_ARM64_REG_W5) & 0x1F,
                    uc.reg_read(UC_ARM64_REG_W6) & MASK,
                )
            )
        elif addr == 0x400B4C:
            op = uc.reg_read(UC_ARM64_REG_W13) & 0xFF
            if op > 11:
                ops.append((op, 0, 0, 0, uc.reg_read(UC_ARM64_REG_W6) & MASK))

    mu.hook_add(UC_HOOK_CODE, schedule_hook)
    mu.emu_start(0x400968, 0x400B54)

    # Recover second 16 bytes by reversing stage2
    inv4 = inv_table(TOP4)
    inv11 = inv_table(TOP11)
    S = C1 + C0
    if ops and ops[-1][0] == 0xFF:
        ops = ops[:-1]

    for op, i1, i2, rot, w6 in reversed(ops):
        if op == 1:
            S[i1] ^= S[i2]
        elif op == 2:
            S[i1] = (S[i1] - S[i2]) & MASK
        elif op == 3:
            S[i1] = rol(S[i1], (-rot) & 31)
        elif op == 4:
            S[i1] = subw(inv4, S[i1]) ^ w6
        elif op == 5:
            S[i1] = ((S[i1] - w6) & MASK) ^ ror(S[i2], (-rot) & 31)
        elif op == 6:
            S[i1], S[i2] = S[i2], S[i1]
        elif op == 7:
            S[i1] ^= w6
        elif op == 8:
            S[i1] = (S[i1] - w6) & MASK
        elif op == 9:
            S[i1] = (S[i1] * modinv_odd((w6 | 1) & MASK)) & MASK
        elif op == 10:
            sumv = rol(S[i1] ^ w6, (-rot) & 31)
            S[i1] = (sumv - S[i2]) & MASK
        elif op == 11:
            y = ((S[i1] ^ w6) - ror(S[i2], (-rot) & 31)) & MASK
            S[i1] = subw(inv11, y)
        elif op == 0:
            pass
        else:
            S[0] ^= 0x13579BDF
            S[1] = (S[1] - 0x2468ACE0) & MASK

    second = S[:4]
    key = b"".join(struct.pack("<I", x) for x in (first + second))

    # Emulate success path and capture printed flag
    mu2 = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu2.mem_map(0, 0x2000000)
    mu2.mem_write(BASE, data)
    sp = 0x900000
    heap_ptr = 0x1200000
    outputs = []

    mu2.mem_write(sp + 0xB0, key)
    mu2.reg_write(UC_ARM64_REG_SP, sp)
    mu2.reg_write(UC_ARM64_REG_X29, sp)
    mu2.reg_write(UC_ARM64_REG_X19, 0x4010E0)
    mu2.reg_write(UC_ARM64_REG_LR, 0x41414141)

    def read_cstr(addr):
        out = b""
        while True:
            c = mu2.mem_read(addr, 1)
            if c == b"\x00":
                break
            out += c
            addr += 1
        return out

    def run_hook(uc, addr, size, _):
        nonlocal heap_ptr
        if addr == 0x4006F0:  # malloc@plt
            n = uc.reg_read(UC_ARM64_REG_X0)
            p = heap_ptr
            heap_ptr = (heap_ptr + n + 0x10) & ~0xF
            uc.reg_write(UC_ARM64_REG_X0, p)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        elif addr == 0x400740:  # free@plt
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        elif addr == 0x400730:  # puts@plt
            p = uc.reg_read(UC_ARM64_REG_X0)
            outputs.append(read_cstr(p))
            uc.reg_write(UC_ARM64_REG_X0, len(outputs[-1]) + 1)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        elif addr == 0x41414141:
            uc.emu_stop()

    mu2.hook_add(UC_HOOK_CODE, run_hook)
    mu2.emu_start(0x40085C, 0)

    print(key.decode())
    if outputs:
        print(outputs[-1].decode())


if __name__ == "__main__":
    main()
