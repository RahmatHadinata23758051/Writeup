#!/usr/bin/env python3
import itertools
import os
import string
import struct
import subprocess
from pathlib import Path

BIN = Path(__file__).with_name("parallax")
CODE_OFF = 0x20C0
CODE_LEN = 0x2C7C
SBOX_OFF = 0x4D40
TABLE_OFF = 0x4EA0
SEED = 0xDD44D5BAE067208D
HASH_CHECK = 0x60B315E5
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

# Fast alphabet first; if a constraint is not solved, the script falls back to all printable ASCII.
FAST_ALPHABET = (string.ascii_letters + string.digits + "_{}?").encode()
PRINTABLE = bytes(range(0x20, 0x7F))


def decrypt_vm(blob: bytes) -> bytes:
    enc = blob[CODE_OFF:CODE_OFF + CODE_LEN]
    x = SEED
    key = b"\x00" * 8
    out = bytearray(len(enc))
    for i, b in enumerate(enc):
        if (i & 7) == 0:
            x ^= (x << 13) & MASK64
            x ^= x >> 7
            x ^= (x << 17) & MASK64
            key = x.to_bytes(8, "little")
        out[i] = b ^ key[i & 7]
    return bytes(out)


def hash_probe(code: bytes) -> int:
    # Binary compares the last (byte ^ previous_hash) value, not the final FNV hash.
    h = 0x811C9DC5
    last = 0
    for b in code:
        last = (b ^ h) & MASK32
        h = (last * 0x1000193) & MASK32
    return last


def rol32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> ((32 - n) & 31))) & MASK32


def avalanche(x: int) -> int:
    x &= MASK32
    x ^= x >> 16
    x = (x * 0x7FEB352D) & MASK32
    x ^= x >> 15
    x = (x * 0x846CA68B) & MASK32
    x ^= x >> 16
    return x & MASK32


class State:
    def __init__(self):
        self.regs = [0] * 8
        self.deps = [set() for _ in range(8)]
        self.pc = 0
        self.mode = 0
        self.err = 0
        self.cmps = []
        self.steps = 0
        self.reason = None
        self.last_mode_deps = set()

    def clone(self):
        s = State()
        s.regs = self.regs.copy()
        s.deps = [d.copy() for d in self.deps]
        s.pc = self.pc
        s.mode = self.mode
        s.err = self.err
        s.cmps = self.cmps.copy()
        s.steps = self.steps
        s.reason = self.reason
        s.last_mode_deps = self.last_mode_deps.copy()
        return s


class VM:
    def __init__(self, blob: bytes):
        self.code = decrypt_vm(blob)
        check = hash_probe(self.code)
        if check != HASH_CHECK:
            raise RuntimeError(f"VM decrypt/hash check mismatch: {check:#x}")
        self.sbox = blob[SBOX_OFF:SBOX_OFF + 0x100]
        self.tables = [blob[TABLE_OFF + i * 16:TABLE_OFF + (i + 1) * 16] for i in range(4)]

    def sbox32(self, x: int) -> int:
        s = self.sbox
        return (s[x & 0xFF]
                | (s[(x >> 8) & 0xFF] << 8)
                | (s[(x >> 16) & 0xFF] << 16)
                | (s[(x >> 24) & 0xFF] << 24)) & MASK32

    def fail(self, st: State, flag: int, info):
        st.err |= flag
        if st.reason is None:
            st.reason = info

    def step(self, st: State, inp: bytes) -> bool:
        pc0 = st.pc
        op_byte = self.code[st.pc]
        st.pc += 1
        if op_byte > 15:
            self.fail(st, 0x40000000, ("bad opcode byte", pc0, op_byte, st.mode, st.last_mode_deps.copy()))
            return False

        op = self.tables[st.mode][op_byte]
        if op > 15:
            self.fail(st, 0x10000000, ("bad translated opcode", pc0, op_byte, st.mode, op))
            return False

        code = self.code
        if op == 0:  # halt
            st.pc = len(code)
        elif op == 1:  # mov reg, imm32
            r = code[st.pc]
            imm = struct.unpack_from("<I", code, st.pc + 1)[0]
            st.pc += 5
            if r > 7:
                self.fail(st, 1, ("bad register", pc0, r))
            else:
                st.regs[r] = imm
                st.deps[r] = set()
        elif op == 2:  # mov reg, input[index]
            r = code[st.pc]
            idx = code[st.pc + 1]
            st.pc += 2
            if r > 7 or idx >= len(inp):
                self.fail(st, 1, ("bad input load", pc0, r, idx))
            else:
                st.regs[r] = inp[idx]
                st.deps[r] = {idx}
        elif op in (3, 4, 7, 13):  # xor/add/sub/swap reg, reg
            a = code[st.pc]
            b = code[st.pc + 1]
            st.pc += 2
            if (a | b) > 7:
                self.fail(st, 1, ("bad register pair", pc0, a, b))
            elif op == 3:
                st.regs[a] = (st.regs[a] ^ st.regs[b]) & MASK32
                st.deps[a] |= st.deps[b]
            elif op == 4:
                st.regs[a] = (st.regs[a] + st.regs[b]) & MASK32
                st.deps[a] |= st.deps[b]
            elif op == 7:
                st.regs[a] = (st.regs[a] - st.regs[b]) & MASK32
                st.deps[a] |= st.deps[b]
            else:
                st.regs[a], st.regs[b] = st.regs[b], st.regs[a]
                st.deps[a], st.deps[b] = st.deps[b], st.deps[a]
        elif op in (5, 9, 11, 12):  # mul/hash/xor/add reg, imm32
            r = code[st.pc]
            imm = struct.unpack_from("<I", code, st.pc + 1)[0]
            st.pc += 5
            if r > 7:
                self.fail(st, 1, ("bad register", pc0, r))
            elif op == 5:
                st.regs[r] = (st.regs[r] * imm) & MASK32
            elif op == 9:
                st.regs[r] = avalanche(st.regs[r] ^ imm)
            elif op == 11:
                st.regs[r] = (st.regs[r] ^ imm) & MASK32
            else:
                st.regs[r] = (st.regs[r] + imm) & MASK32
        elif op == 6:  # rol reg, imm8
            r = code[st.pc]
            sh = code[st.pc + 1]
            st.pc += 2
            if r > 7:
                self.fail(st, 1, ("bad register", pc0, r))
            else:
                st.regs[r] = rol32(st.regs[r], sh)
        elif op == 8:  # sbox each byte of reg
            r = code[st.pc]
            st.pc += 1
            if r > 7:
                self.fail(st, 1, ("bad register", pc0, r))
            else:
                st.regs[r] = self.sbox32(st.regs[r])
        elif op == 10:  # cmp reg, imm32; mismatch sets VM error flag
            r = code[st.pc]
            imm = struct.unpack_from("<I", code, st.pc + 1)[0]
            st.pc += 5
            val = st.regs[r] if r < 8 else None
            dep = st.deps[r].copy() if r < 8 else set()
            st.cmps.append((pc0, r, val, imm, dep))
            if r > 7:
                self.fail(st, 1, ("bad register", pc0, r))
            elif val != imm:
                self.fail(st, 1, ("cmp", pc0, r, val, imm, dep))
        elif op == 14:  # nop
            pass
        elif op == 15:  # trap
            self.fail(st, 0x20000000, ("trap", pc0))

        # The active instruction table changes after every instruction.
        st.last_mode_deps = st.deps[0] | st.deps[3]
        st.mode = (((st.regs[0] ^ st.regs[3] ^ st.pc) & 3) + st.mode + (op & 1)) & 3
        st.steps += 1
        return True

    def run(self, inp: bytes, start=None, stop_cmp_pc=None):
        st = start.clone() if start else State()
        last_good = None
        while st.steps < 0x30D41:
            if st.pc > len(self.code) - 1:
                st.reason = ("end", st.pc)
                break
            before = len(st.cmps)
            ok = self.step(st, inp)
            if len(st.cmps) > before:
                pc0, _r, val, imm, _dep = st.cmps[-1]
                if val == imm and st.err == 0:
                    last_good = st.clone()
                if stop_cmp_pc is not None and pc0 == stop_cmp_pc:
                    break
            if not ok or st.err:
                break
        return st, last_good


def build_input(known: dict[int, int], fill: int = ord("A")) -> bytes:
    arr = bytearray([fill] * 45)
    for i, v in known.items():
        arr[i] = v
    return bytes(arr)


def solve(vm: VM) -> str:
    prefix = b"Thryve{"
    known = {i: b for i, b in enumerate(prefix)}
    known[44] = ord("}")

    for _round in range(100):
        st, last_good = vm.run(build_input(known))
        if st.err == 0:
            return build_input(known).decode()
        if not st.reason or st.reason[0] != "cmp":
            raise RuntimeError(f"unexpected VM failure: {st.reason}")

        _tag, pc0, _reg, _val, _imm, deps = st.reason
        unknown = sorted(i for i in deps if i not in known)
        if not unknown:
            raise RuntimeError(f"known bytes contradict cmp at pc {pc0}")

        candidates = []
        for alphabet in (FAST_ALPHABET, PRINTABLE):
            candidates.clear()
            for vals in itertools.product(alphabet, repeat=len(unknown)):
                trial = known.copy()
                trial.update(dict(zip(unknown, vals)))
                rr, _ = vm.run(build_input(trial), start=last_good, stop_cmp_pc=pc0)
                passed_target = any(c[0] == pc0 and c[2] == c[3] for c in rr.cmps)
                failed_target = rr.reason and rr.reason[0] == "cmp" and rr.reason[1] == pc0
                if passed_target and not failed_target:
                    candidates.append(vals)
            if candidates:
                break

        if len(candidates) != 1:
            raise RuntimeError(f"ambiguous/no candidates at pc {pc0}: {candidates[:5]}")
        known.update(dict(zip(unknown, candidates[0])))

    raise RuntimeError("solver iteration limit reached")


def main():
    blob = BIN.read_bytes()
    vm = VM(blob)
    flag = solve(vm)
    print(flag)

    os.chmod(BIN, os.stat(BIN).st_mode | 0o111)
    proc = subprocess.run([str(BIN)], input=flag + "\n", text=True, capture_output=True, check=False)
    print("[+] binary output:", proc.stdout.strip())
    if "synchronization achieved" not in proc.stdout:
        raise SystemExit("[-] binary did not accept the recovered flag")


if __name__ == "__main__":
    main()
