#!/usr/bin/env python3
import os
import struct
import subprocess

MASK64 = (1 << 64) - 1
INIT_SEED = 0x6A09E667F3BCC909
GOLDEN = 0x9E3779B97F4A7C15
MIX_MUL = 0xBF58476D1CE4E5B9
XORSHIFT_MUL = 0x2545F4914F6CDD1D


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def build_checker():
    if os.path.exists("checker"):
        return
    subprocess.run(
        ["./tcc", "-B./runtime", "checker.c", "-o", "checker"],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def read_sections(elf):
    shoff = u64(elf, 0x28)
    shentsize = u16(elf, 0x3A)
    shnum = u16(elf, 0x3C)
    shstrndx = u16(elf, 0x3E)

    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        sections.append(
            {
                "idx": i,
                "name_off": u32(elf, off),
                "type": u32(elf, off + 4),
                "flags": u64(elf, off + 8),
                "addr": u64(elf, off + 16),
                "off": u64(elf, off + 24),
                "size": u64(elf, off + 32),
            }
        )

    shstr = sections[shstrndx]
    names = elf[shstr["off"] : shstr["off"] + shstr["size"]]
    for sec in sections:
        end = names.find(b"\x00", sec["name_off"])
        sec["name"] = names[sec["name_off"] : end].decode()
    return sections


def rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK64


def xorshift64star(state):
    state ^= state >> 12
    state &= MASK64
    state ^= (state << 25) & MASK64
    state &= MASK64
    state ^= state >> 27
    state &= MASK64
    return (state * XORSHIFT_MUL) & MASK64, state


def compute_seed(elf, sections):
    state = INIT_SEED
    for sec in sections:
        if sec["type"] != 4:  # SHT_RELA
            continue
        for j in range(sec["size"] // 24):
            pos = sec["off"] + j * 24
            r_info = u64(elf, pos + 8)
            r_addend = u64(elf, pos + 16)
            state ^= (r_info + GOLDEN + (sec["idx"] << 32) + j) & MASK64
            state = (rol64(state, 17) * MIX_MUL) & MASK64
            state ^= r_addend
    return state


def decrypt_vm(elf, sections, seed):
    data_sec = next(sec for sec in sections if sec["name"] == ".data")
    encrypted = elf[data_sec["off"] + 4 : data_sec["off"] + 4 + 0x200]

    state = seed
    vm = bytearray()
    for byte in encrypted:
        rnd, state = xorshift64star(state)
        vm.append(byte ^ (rnd >> 56))
    return bytes(vm)


def rol32(x, r):
    x &= 0xFFFFFFFF
    r &= 31
    if r == 0:
        return x
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def recover_flag(vm):
    length = vm[0] | (vm[1] << 8)
    if vm[2] != 0x51:
        raise ValueError("bad VM magic")

    pc = 3
    checksum = 0xC0DEC0DE
    out = []

    for i in range(length):
        op = vm[pc]
        pc += 1
        add_key = vm[pc]
        pc += 1
        rotate = vm[pc] & 31
        pc += 1
        expected = u32(vm, pc)
        pc += 4

        if op != 0xA7:
            raise ValueError(f"bad opcode at index {i}: {op:#x}")

        candidates = []
        for ch in range(1, 256):
            cur = rol32(checksum ^ ((ch + add_key) & 0xFFFFFFFF), rotate)
            cur = (cur + (((i * 0x45D9F3B) & 0xFFFFFFFF) ^ 0x9E3779B9)) & 0xFFFFFFFF
            if cur == expected:
                candidates.append(ch)

        if len(candidates) != 1:
            raise ValueError(f"ambiguous byte {i}: {candidates}")

        out.append(candidates[0])
        checksum = expected

    if vm[pc] != 0:
        raise ValueError("decoded input is not null-terminated")
    return bytes(out).decode()


def main():
    build_checker()
    elf = open("checker", "rb").read()
    sections = read_sections(elf)
    seed = compute_seed(elf, sections)
    vm = decrypt_vm(elf, sections, seed)
    flag = recover_flag(vm)
    print(flag)


if __name__ == "__main__":
    main()
