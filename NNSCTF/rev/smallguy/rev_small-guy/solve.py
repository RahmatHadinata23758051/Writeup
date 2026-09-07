#!/usr/bin/env python3
import struct
import subprocess

MASK = (1 << 64) - 1
BIN = "small-guy"

RODATA_VADDR = 0x401468
RODATA_OFF = 0x1468
OP_TABLE_VADDR = 0x4014D0
QWORD_TABLE_VADDR = 0x4015D0
TARGET_VADDR = 0x401DD0
GOLDEN = 0x9E3779B97F4A7C15

# DWARF CFA expression operations used by the dispatch stubs.
ADD_RBX_0 = 11400714819323198485
ADD_R12_1 = 13787848793156543929
ADD_R13_2 = 10723151780598845931
ADD_R14_3 = 2685821657736338717
ADD_RBX_4 = 15485907386658061715
ADD_R12_5 = 11562461410679940143
ADD_R13_6 = 16646288086500911323
ADD_R14_7 = 10285213230658275043
MUL_RBX_12 = 6364136223846793005
MUL_R12_13 = 2862933555777941757
MUL_R13_14 = 3935559000370003845
MUL_R14_15 = 18397679294719823053
MUL_RBX_C = 14029467366897019727
MUL_R12_C = 1609587929392839161
MUL_R13_C = 9650029242287828579
MUL_R14_C = 11400714785074694791
LCG_RBX_A = 1812433253
LCG_RBX_B = 2567483615
LCG_R13_A = 1103515245
LCG_R13_B = 12345

INV = {
    MUL_RBX_12: pow(MUL_RBX_12, -1, 1 << 64),
    MUL_R12_13: pow(MUL_R12_13, -1, 1 << 64),
    MUL_R13_14: pow(MUL_R13_14, -1, 1 << 64),
    MUL_R14_15: pow(MUL_R14_15, -1, 1 << 64),
    LCG_RBX_A: pow(LCG_RBX_A, -1, 1 << 64),
    LCG_R13_A: pow(LCG_R13_A, -1, 1 << 64),
}


def vaddr_to_off(vaddr: int) -> int:
    return RODATA_OFF + (vaddr - RODATA_VADDR)


def rol64(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & MASK


def inv_lcg(x: int, a: int, b: int, count: int) -> int:
    inv_a = INV[a]
    for _ in range(count):
        x = ((x - b) * inv_a) & MASK
    return x


def inv_op(regs, idx: int, rcx: int):
    rbx, r12, r13, r14 = regs

    if idx == 0:
        rbx = (rbx - ADD_RBX_0) & MASK
    elif idx == 1:
        r12 = (r12 - ADD_R12_1) & MASK
    elif idx == 2:
        r13 = (r13 - ADD_R13_2) & MASK
    elif idx == 3:
        r14 = (r14 - ADD_R14_3) & MASK
    elif idx == 4:
        rbx = (rbx - ADD_RBX_4) & MASK
    elif idx == 5:
        r12 = (r12 - ADD_R12_5) & MASK
    elif idx == 6:
        r13 = (r13 - ADD_R13_6) & MASK
    elif idx == 7:
        r14 = (r14 - ADD_R14_7) & MASK
    elif idx == 8:
        rbx ^= rol64(r12, 7)
    elif idx == 9:
        r12 ^= rol64(r13, 17)
    elif idx == 10:
        r13 ^= rol64(r14, 29)
    elif idx == 11:
        r14 ^= rol64(rbx, 41)
    elif idx == 12:
        rbx = (rbx * INV[MUL_RBX_12]) & MASK
    elif idx == 13:
        r12 = (r12 * INV[MUL_R12_13]) & MASK
    elif idx == 14:
        r13 = (r13 * INV[MUL_R13_14]) & MASK
    elif idx == 15:
        r14 = (r14 * INV[MUL_R14_15]) & MASK
    elif idx == 16:
        rbx ^= rcx
    elif idx == 17:
        r12 ^= rcx
    elif idx == 18:
        r13 ^= rcx
    elif idx == 19:
        r14 ^= rcx
    elif idx == 20:
        rbx = (rbx - rcx * MUL_RBX_C) & MASK
    elif idx == 21:
        r12 = (r12 - rcx * MUL_R12_C) & MASK
    elif idx == 22:
        r13 = (r13 - rcx * MUL_R13_C) & MASK
    elif idx == 23:
        r14 = (r14 - rcx * MUL_R14_C) & MASK
    elif idx == 24:
        rbx ^= rol64(r13, 11)
    elif idx == 25:
        r12 ^= rol64(r14, 23)
    elif idx == 26:
        r13 ^= rol64(rbx, 37)
    elif idx == 27:
        r14 ^= rol64(r12, 53)
    elif idx == 28:
        rbx, r13 = r13, rbx
    elif idx == 29:
        r12, r14 = r14, r12
    elif idx == 30:
        rbx = inv_lcg(rbx, LCG_RBX_A, LCG_RBX_B, (rcx & 3) + 1)
    elif idx == 31:
        r13 = inv_lcg(r13, LCG_R13_A, LCG_R13_B, (rcx & 3) + 1)
    else:
        raise ValueError(f"bad op index: {idx}")

    return [rbx & MASK, r12 & MASK, r13 & MASK, r14 & MASK]


def is_printable(bs: bytes) -> bool:
    return all(32 <= b < 127 for b in bs)


def solve():
    blob = open(BIN, "rb").read()
    op_table = blob[vaddr_to_off(OP_TABLE_VADDR):vaddr_to_off(OP_TABLE_VADDR) + 256]
    qtab = [
        struct.unpack_from("<Q", blob, vaddr_to_off(QWORD_TABLE_VADDR) + i * 8)[0]
        for i in range(256)
    ]
    target = blob[vaddr_to_off(TARGET_VADDR):vaddr_to_off(TARGET_VADDR) + 32]
    target_regs = list(struct.unpack("<4Q", target))

    for key in range(1 << 16):
        key_mix = (key * GOLDEN) & MASK
        regs = target_regs[:]

        # Forward unwinding applies frames 255 -> 0.
        # Reverse it from frame 0 -> 255.
        for i in range(256):
            idx = (op_table[i] + (key >> (i & 7))) & 31

            # rcx used by frame i is restored by the inner frame i+1.
            # The deepest frame starts with rcx = 0.
            rcx = 0 if i == 255 else (qtab[i + 1] ^ key_mix) & MASK
            regs = inv_op(regs, idx, rcx)

        candidate = struct.pack("<4Q", *regs)
        if struct.unpack_from("<H", candidate)[0] == key and is_printable(candidate):
            return b"NNS{" + candidate + b"}"

    raise RuntimeError("flag not found")


def main():
    flag = solve()
    print(f"<FLAG>{flag.decode()}</FLAG>")

    # Local validation against the original binary.
    result = subprocess.run([f"./{BIN}", flag.decode()], text=True, capture_output=True, check=False)
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
