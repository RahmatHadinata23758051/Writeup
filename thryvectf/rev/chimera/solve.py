#!/usr/bin/env python3
from pathlib import Path
import struct
import subprocess

BIN = Path("./chimera_mirror")
MASK = 0xFFFFFFFF


def u32(x):
    return x & MASK


def xs32(x):
    x = u32(x)
    x ^= u32(x << 13)
    x ^= x >> 17
    x ^= u32(x << 5)
    return u32(x)


def rol(x, n):
    n &= 31
    x = u32(x)
    return x if n == 0 else u32((x << n) | (x >> (32 - n)))


def ror(x, n):
    n &= 31
    x = u32(x)
    return x if n == 0 else u32((x >> n) | (x << (32 - n)))


blob = BIN.read_bytes()

# .rodata is mapped with file offset == virtual address in this PIE.
MAIN_ENC_OFF = 0x20C0
MAIN_LEN = 0x720
SUB_ENC_OFF = 0x2BC0
TABLE_U32_OFF = 0x27E0
SUB_SIZE_OFF = 0x29C0
SUB_OFF_OFF = 0x2AC0
CONST_A_OFF = 0x53F0
CONST_B_OFF = 0x5400
NUM_MIRRORS = 0x74


def decrypt_main_bytecode():
    state = 0x7B3A7BD4
    add_key = 0x61
    out = bytearray()
    enc = blob[MAIN_ENC_OFF : MAIN_ENC_OFF + MAIN_LEN]

    for i, b in enumerate(enc):
        state = xs32(i * 3 - 0x5A5A5A5B + state)
        stream_byte = (state >> ((i & 3) * 8)) & 0xFF
        out.append(b ^ (add_key & 0xFF) ^ stream_byte)
        add_key = u32(add_key + 0x1D)

    return bytes(out)


sub_sizes = [struct.unpack_from("<H", blob, SUB_SIZE_OFF + i * 2)[0] for i in range(NUM_MIRRORS)]
sub_offsets = [struct.unpack_from("<H", blob, SUB_OFF_OFF + i * 2)[0] for i in range(NUM_MIRRORS)]
sub_seeds = [struct.unpack_from("<I", blob, TABLE_U32_OFF + i * 4)[0] for i in range(NUM_MIRRORS)]
const_a = [struct.unpack_from("<I", blob, CONST_A_OFF + i * 4)[0] for i in range(4)]
const_b = [struct.unpack_from("<I", blob, CONST_B_OFF + i * 4)[0] for i in range(4)]
main_code = decrypt_main_bytecode()


def decrypt_sub_bytecode(idx):
    off = sub_offsets[idx]
    size = sub_sizes[idx]

    seed = (
        u32((idx + 1) * 0x45D9F3B)
        ^ u32((idx + 1) * 0x9E3779B9)
        ^ sub_seeds[idx]
        ^ rol(0x7B805A1F, (idx * 7) % 31)
    )
    rolling = u32(idx * 0x11 + 0x7F4A7C15)
    add_key = u32(-125 * idx)

    out = bytearray()
    enc = blob[SUB_ENC_OFF + off : SUB_ENC_OFF + off + size]
    for i, b in enumerate(enc):
        seed = xs32(seed + rolling + i)
        stream_byte = (seed >> ((i & 3) * 8)) & 0xFF
        out.append(b ^ (add_key & 0xFF) ^ stream_byte)
        add_key = u32(add_key + 0x11)

    return bytes(out)


def run_mirror(idx, user_input, source_reg_value=1, anti_debug_salt=0):
    """Emulate nested mirror VM predicate. It returns 1 on success, 0 on fail."""
    if idx >= NUM_MIRRORS:
        return 0

    off = sub_offsets[idx]
    size = sub_sizes[idx]
    if off + size > 0x27D8 or size > 0x100 or (size & 7):
        return 0

    # Local VM registers are derived from index + caller source register.
    mix = u32(anti_debug_salt ^ source_reg_value ^ idx)
    base = u32(mix + idx)
    regs = [0] * 8
    for i in range(4):
        regs[i] = xs32(const_a[i] + base)
        regs[i + 4] = xs32(const_b[i] + base)

    code = decrypt_sub_bytecode(idx)
    for pc in range(0, len(code), 8):
        op, b1, b2, b3 = code[pc : pc + 4]
        imm = struct.unpack_from("<I", code, pc + 4)[0]
        r1, r2, r3 = b1 & 7, b2 & 7, b3 & 7

        if op == 0x0A:          # set register immediate
            regs[r1] = imm
        elif op == 0x0F:        # add immediate
            regs[r1] = u32(regs[r1] + imm)
        elif op == 0x21:        # predicate success
            return 1
        elif op == 0x26:        # xor three registers with immediate
            regs[r1] = u32(imm ^ regs[r1] ^ regs[r2] ^ regs[r3])
        elif op == 0x30:        # load input byte at imm offset
            if imm >= len(user_input):
                return 0
            regs[r1] = user_input[imm]
        elif op == 0x59:        # add two regs + imm, then rol
            regs[r1] = rol(regs[r2] + regs[r1] + imm, b3)
        elif op == 0x71:
            regs[r1] = rol(regs[r1], r2)
        elif op == 0x76:        # xorshift mix using caller-derived value
            regs[r1] = xs32(regs[r2] + regs[r1] + mix + imm)
        elif op == 0x7D:        # compare register with immediate
            if regs[r1] != imm:
                return 0
        elif op == 0x93:
            regs[r1] = u32(regs[r1] - imm)
        elif op == 0xA7:
            regs[r1] = ror(regs[r1], r2)
        elif op == 0xAB:
            regs[r1] = u32(regs[r1] ^ imm)
        elif op == 0xD2:
            regs[r1] = u32(regs[r1] * (imm | 1))
        else:
            return 0

    return 0


def run_full_vm(user_input, anti_debug_salt=0):
    regs = [
        1,
        0,
        0x12345678,
        0x9ABCDEF0,
        0x0BADC0DE,
        0x13371337,
        0xFEEDFACE,
        anti_debug_salt,
    ]

    for pc in range(0, len(main_code), 8):
        op, b1, b2, b3 = main_code[pc : pc + 4]
        imm = struct.unpack_from("<I", main_code, pc + 4)[0]
        r1, r2 = b1 & 7, b2 & 7

        if op == 0xBF:
            regs[r1] = imm
        elif op == 0xEF:
            regs[r1] = 1 if len(user_input) == imm else 0
        elif op == 0x91:
            regs[r1] = 1 if (regs[r1] & regs[r2]) != 0 else 0
        elif op == 0x95:
            regs[r1] = rol((regs[r1] ^ regs[r2]) + anti_debug_salt + imm, b3)
        elif op == 0xB7:
            regs[r1] = xs32(regs[r2] + regs[r1] + imm)
        elif op == 0xCD:
            regs[r1] = run_mirror(imm, user_input, regs[r2], anti_debug_salt)
        elif op == 0xDC:
            h = u32(imm ^ len(user_input) ^ 0x846CA68B)
            ctr = 0
            for ch in user_input[: min(len(user_input), 32)]:
                h = xs32(ch + ctr + h)
                ctr = u32(ctr + 0x9E37)
            regs[r1] = u32(regs[r1] ^ ((h >> 31) & 1))
        elif op == 0xA3:
            return regs[r1] & 1
        else:
            return 0

    return 0


def recover_flag():
    # Main VM checks length 0x30. Mirror programs 0..47 each constrain one byte.
    flag = bytearray(b"?" * 0x30)
    for pos in range(0x30):
        candidates = []
        for c in range(256):
            test = bytearray(b"A" * 0x30)
            test[pos] = c
            if run_mirror(pos, bytes(test), source_reg_value=1, anti_debug_salt=0):
                candidates.append(c)

        if len(candidates) != 1:
            raise RuntimeError(f"position {pos}: expected 1 candidate, got {candidates}")
        flag[pos] = candidates[0]

    return bytes(flag)


def main():
    flag = recover_flag()
    print(flag.decode())

    if run_full_vm(flag) != 1:
        raise RuntimeError("recovered flag did not satisfy the full VM")
    print("[+] full VM validation passed")

    # Optional proof against the original binary.
    try:
        out = subprocess.check_output(["./" + BIN.name, flag.decode()], stderr=subprocess.STDOUT)
        print("[+] binary output:", out.decode().strip())
    except Exception as exc:
        print(f"[!] skipped binary proof: {exc}")


if __name__ == "__main__":
    main()
