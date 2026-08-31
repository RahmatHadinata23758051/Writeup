#!/usr/bin/env python3
from pathlib import Path
import struct

ROM_PATH = Path('challenge.rom')
EMU_PATH = Path('qemu-asisarch')
NWORDS = 22
MASK = 0xffff

def rol(x, n, bits):
    n %= bits
    m = (1 << bits) - 1
    return ((x << n) & m) | ((x & m) >> (bits - n))

def u16(buf, off):
    return buf[off] | (buf[off + 1] << 8)

def sbox16(sbox, x):
    return (sbox[(x >> 8) & 0xff] << 8) | sbox[x & 0xff]

def invsbox16(inv, x):
    return (inv[(x >> 8) & 0xff] << 8) | inv[x & 0xff]

def mix_f(x):
    return x ^ rol(x, 5, 16) ^ rol(x, 11, 16)

def load_tables():
    qemu = EMU_PATH.read_bytes()
    # Dua tabel ini diambil dari .rodata emulator:
    # 0x2140 = permutation table fetch instruksi, 0x2160 = S-box 256 byte.
    perms = [qemu[0x2140 + 4*i:0x2140 + 4*i + 4] for i in range(4)]
    sbox = qemu[0x2160:0x2160 + 256]
    if len(sbox) != 256 or sorted(sbox) != list(range(256)):
        raise SystemExit('S-box tidak valid / offset emulator beda')
    inv = [0] * 256
    for i, b in enumerate(sbox):
        inv[b] = i
    return perms, sbox, inv

def load_rom():
    rom = ROM_PATH.read_bytes()
    if rom[:4] != b'AARQ' or rom[4] != 2:
        raise SystemExit('ROM header bukan AARQ v2')
    body = rom[0x20:]

    chk = 0x31415926
    for c in body:
        chk = (rol(chk & 0xffff, 3, 16) ^ c ^ (chk >> 16) ^ 0x9e37) & 0xffffffff
    hdr_chk = struct.unpack_from('<I', rom, 0x0c)[0]
    if chk != hdr_chk:
        raise SystemExit('ROM checksum mismatch')

    mem = bytearray(body) + bytearray(0x10000 - len(body))
    return mem

def decode(mem, pc, perms):
    # Decoder instruksi hasil reverse dari qemu-asisarch.
    key = (((pc ^ 0x9e37) * 0x1039 + 0x79b9) & MASK)
    pidx = (key >> 14) & 3
    key = rol(key, 5, 16)
    p = perms[pidx]

    b0 = mem[pc + p[0]]
    b1 = mem[pc + p[1]]
    b2 = mem[pc + p[2]]
    b3 = mem[pc + p[3]]

    op = rol(((0x5d * pc) ^ key ^ b2) & 0xff, key >> 5, 8) ^ 0x6d
    lo = rol((b1 ^ (key & 0xff)) & 0xff, 4, 8)
    hi = rol((b3 ^ ((key >> 8) & 0xff)) & 0xff, 4, 8)
    imm = rol(((hi << 8) | lo) & MASK, 5, 16)
    return op, imm

def extract_rounds_and_target(mem, perms):
    rounds = []
    pc = 0x24

    for _round in range(10):
        const = []

        # 22 blok: ld16 -> sbox -> xor const -> st16
        for _ in range(NWORDS):
            op, imm = decode(mem, pc + 3 * 4, perms)  # movi r1, const
            assert op == 0x15
            const.append(imm)
            pc += 6 * 4

        # 22 blok prefix-add: w[i] += w[i-1] + 0x5a5a
        pc += NWORDS * 7 * 4

        # 22 blok mix; semua blok dalam satu round pakai rotasi sama.
        rots = []
        for _ in range(NWORDS):
            op, rot = decode(mem, pc + 16 * 4, perms)  # roli r0, rot
            assert op == 0x44
            rots.append(rot)
            pc += 22 * 4

        assert len(set(rots)) == 1
        rounds.append((const, rots[0]))

    assert pc == 0x7874

    # Checker akhir hanya menjumlahkan semua selisih XOR.
    # Target per-word disimpan sebagai dua word yang di-XOR di area data 0x7cdb+offset.
    target = []
    pc = 0x7874 + 4  # skip movi r5, 0
    for _ in range(NWORDS):
        op, off = decode(mem, pc + 3 * 4, perms)  # addi r1, offset
        assert op == 0x21
        a = 0x7cdb + off
        target.append(u16(mem, a) ^ u16(mem, a + 2))
        pc += 10 * 4

    return rounds, target

def invert_transform(rounds, target, sbox, inv):
    w = target[:]

    for const, rot in reversed(rounds):
        # Undo mix in-place. Forward jalan i=0..21, jadi inverse jalan mundur.
        for i in reversed(range(NWORDS)):
            w[i] ^= mix_f(w[(i + 1) % NWORDS]) ^ rol(mix_f(w[(i + 2) % NWORDS]), rot, 16)
            w[i] &= MASK

        # Undo prefix-add circular: w[i] = w[i] + w[i-1] + 0x5a5a.
        for i in reversed(range(NWORDS)):
            prev = NWORDS - 1 if i == 0 else i - 1
            w[i] = (w[i] - w[prev] - 0x5a5a) & MASK

        # Undo S-box per-byte lalu XOR konstanta round.
        for i, c in enumerate(const):
            w[i] = invsbox16(inv, w[i] ^ c)

    return w

def forward_check(words, rounds, sbox):
    w = words[:]
    for const, rot in rounds:
        for i, c in enumerate(const):
            w[i] = sbox16(sbox, w[i]) ^ c
        for i in range(NWORDS):
            prev = NWORDS - 1 if i == 0 else i - 1
            w[i] = (w[i] + w[prev] + 0x5a5a) & MASK
        for i in range(NWORDS):
            w[i] ^= mix_f(w[(i + 1) % NWORDS]) ^ rol(mix_f(w[(i + 2) % NWORDS]), rot, 16)
            w[i] &= MASK
    return w

def main():
    perms, sbox, inv = load_tables()
    mem = load_rom()
    rounds, target = extract_rounds_and_target(mem, perms)
    words = invert_transform(rounds, target, sbox, inv)
    assert forward_check(words, rounds, sbox) == target

    flag = b''.join(x.to_bytes(2, 'little') for x in words).decode()
    print(flag)

if __name__ == '__main__':
    main()
