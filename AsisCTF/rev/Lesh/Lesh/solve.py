#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

# Lesh is a 32-bit Windows shellcode blob with one intentional jmp-$ trap.
# The real flag is transient: it is assembled on the stack, then later overwritten.
# This small emulator follows the reachable path, skips the jmp-$ trap, and records
# the dword writes used to build the transient ASIS{...} string.

BIN = Path('lesh.bin')
HEX = Path('lesh.hex')

if not BIN.exists():
    BIN.write_bytes(bytes.fromhex(HEX.read_text().strip()))


def disassemble(start=0, stop=None):
    if stop is None:
        stop = BIN.stat().st_size
    out = subprocess.check_output([
        'objdump', '-D', '-b', 'binary', '-m', 'i386', '-M', 'intel',
        f'--start-address=0x{start:x}', f'--stop-address=0x{stop:x}', str(BIN)
    ], text=True)
    parsed = {}
    for line in out.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )+|(?:[0-9a-f]{2}\s)+)\s*(.*)$', line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2))
        rest = m.group(3).strip()
        if not rest:
            continue
        parts = rest.split(None, 1)
        parsed[addr] = (addr, raw, parts[0], parts[1] if len(parts) > 1 else '', rest)
    return parsed

insns = disassemble()
REG32 = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
ALIASES = {
    'ax': ('eax', 0, 16), 'bx': ('ebx', 0, 16), 'cx': ('ecx', 0, 16), 'dx': ('edx', 0, 16),
    'si': ('esi', 0, 16), 'di': ('edi', 0, 16), 'bp': ('ebp', 0, 16), 'sp': ('esp', 0, 16),
    'al': ('eax', 0, 8), 'ah': ('eax', 8, 8), 'bl': ('ebx', 0, 8), 'bh': ('ebx', 8, 8),
    'cl': ('ecx', 0, 8), 'ch': ('ecx', 8, 8), 'dl': ('edx', 0, 8), 'dh': ('edx', 8, 8),
}

def mask(bits):
    return (1 << bits) - 1

def parity8(x):
    return bin(x & 0xff).count('1') % 2 == 0

class CPU:
    def __init__(self):
        self.r = {name: 0 for name in REG32}
        self.r['esp'] = 0x800000
        self.f = {'CF': 0, 'ZF': 0, 'SF': 0, 'OF': 0, 'PF': 0}
        self.mem = {}
        self.eip = 0x55      # after the initial Sleep resolver/call
        self.trace = []
        self.fs30 = 0x900000 # fake PEB, non-debugged
        self.write_mem(self.fs30 + 2, 0, 1)
        self.write_mem(self.fs30 + 0x68, 0, 4)

    def get_insn(self, addr):
        if addr not in insns:
            insns.update(disassemble(addr, addr + 24))
        return insns[addr]

    def read_mem(self, addr, n):
        return sum(self.mem.get((addr + i) & 0xffffffff, 0) << (8 * i) for i in range(n))

    def write_mem(self, addr, val, n):
        for i in range(n):
            self.mem[(addr + i) & 0xffffffff] = (val >> (8 * i)) & 0xff

    def bits(self, op):
        op = op.strip()
        if op.startswith('BYTE PTR'):
            return 8
        if op.startswith('WORD PTR'):
            return 16
        if op.startswith('DWORD PTR'):
            return 32
        op = self.clean(op).lower()
        if op in REG32:
            return 32
        if op in ALIASES:
            return ALIASES[op][2]
        return 32

    def clean(self, op):
        op = op.strip().replace('ds:', '')
        return re.sub(r'^(BYTE|WORD|DWORD) PTR\s+', '', op).strip()

    def get_reg(self, name):
        name = name.lower()
        if name in REG32:
            return self.r[name]
        base, shift, bits = ALIASES[name]
        return (self.r[base] >> shift) & mask(bits)

    def set_reg(self, name, val):
        name = name.lower()
        if name in REG32:
            self.r[name] = val & 0xffffffff
            return
        base, shift, bits = ALIASES[name]
        m = mask(bits) << shift
        self.r[base] = (self.r[base] & ~m) | ((val & mask(bits)) << shift)
        self.r[base] &= 0xffffffff

    def split_ops(self, ops):
        out, cur, depth = [], '', 0
        for ch in ops:
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
            if ch == ',' and depth == 0:
                out.append(cur.strip())
                cur = ''
            else:
                cur += ch
        if cur.strip():
            out.append(cur.strip())
        return out

    def addr(self, expr):
        expr = expr.strip()
        if expr == 'fs:0x30':
            return self.fs30
        if expr.startswith('fs:['):
            expr = expr[3:]
        assert expr.startswith('[') and expr.endswith(']'), expr
        total = 0
        for part in expr[1:-1].replace(' ', '').replace('-', '+-').split('+'):
            if not part:
                continue
            if '*' in part:
                reg, scale = part.split('*')
                total += self.get_reg(reg) * int(scale, 0)
            elif part.lower() in REG32:
                total += self.get_reg(part)
            else:
                total += int(part, 0)
        return total & 0xffffffff

    def read(self, op, bits=None):
        bits = bits or self.bits(op)
        op = self.clean(op)
        lo = op.lower()
        if lo in REG32 or lo in ALIASES:
            return self.get_reg(lo)
        if lo == 'fs:0x30':
            return self.fs30
        if op.startswith('[') or op.startswith('fs:['):
            return self.read_mem(self.addr(op), bits // 8)
        return int(op, 0) & mask(bits)

    def write(self, op, val, bits=None):
        bits = bits or self.bits(op)
        op = self.clean(op)
        lo = op.lower()
        if lo in REG32 or lo in ALIASES:
            self.set_reg(lo, val)
            return
        addr = self.addr(op)
        self.write_mem(addr, val, bits // 8)
        # Capture the transient dword writes that spell the flag.
        if bits == 32 and '[esp+0xc]' in op:
            self.trace.append(val & 0xffffffff)

    def logic_flags(self, res, bits):
        res &= mask(bits)
        self.f.update(CF=0, OF=0, ZF=int(res == 0), SF=int((res >> (bits - 1)) & 1), PF=int(parity8(res)))

    def add_flags(self, a, b, res, bits):
        m, sign = mask(bits), 1 << (bits - 1)
        r = res & m
        self.f['CF'] = int(res > m)
        self.f['ZF'] = int(r == 0)
        self.f['SF'] = int(bool(r & sign))
        self.f['PF'] = int(parity8(r))
        self.f['OF'] = int(((~(a ^ b) & (a ^ r)) & sign) != 0)

    def sub_flags(self, a, b, res, bits):
        m, sign = mask(bits), 1 << (bits - 1)
        r = res & m
        self.f['CF'] = int((a & m) < (b & m))
        self.f['ZF'] = int(r == 0)
        self.f['SF'] = int(bool(r & sign))
        self.f['PF'] = int(parity8(r))
        self.f['OF'] = int((((a ^ b) & (a ^ r)) & sign) != 0)

    def cond(self, mn):
        f = self.f
        table = {
            'je': f['ZF'] == 1, 'jz': f['ZF'] == 1, 'jne': f['ZF'] == 0, 'jnz': f['ZF'] == 0,
            'jg': f['ZF'] == 0 and f['SF'] == f['OF'], 'jge': f['SF'] == f['OF'],
            'jl': f['SF'] != f['OF'], 'jle': f['ZF'] == 1 or f['SF'] != f['OF'],
            'ja': f['CF'] == 0 and f['ZF'] == 0, 'jae': f['CF'] == 0,
            'jb': f['CF'] == 1, 'jbe': f['CF'] == 1 or f['ZF'] == 1,
            'jo': f['OF'] == 1, 'jno': f['OF'] == 0, 'js': f['SF'] == 1, 'jns': f['SF'] == 0,
            'jp': f['PF'] == 1, 'jpe': f['PF'] == 1, 'jnp': f['PF'] == 0, 'jpo': f['PF'] == 0,
            'jmp': True,
        }
        return table[mn]

    def step(self):
        addr, raw, mn, ops, rest = self.get_insn(self.eip)
        op = self.split_ops(ops)
        neip = (addr + len(raw)) & 0xffffffff
        if mn in ('nop', 'addr16', 'cld', 'std', 'fnop'):
            pass
        elif mn == 'stc': self.f['CF'] = 1
        elif mn == 'clc': self.f['CF'] = 0
        elif mn == 'cmc': self.f['CF'] ^= 1
        elif mn == 'rdtsc': self.r['eax'], self.r['edx'] = 0, 0
        elif mn == 'cdq': self.r['edx'] = 0xffffffff if self.r['eax'] & 0x80000000 else 0
        elif mn == 'xlat': self.set_reg('al', self.read_mem((self.r['ebx'] + self.get_reg('al')) & 0xffffffff, 1))
        elif mn == 'push':
            self.r['esp'] = (self.r['esp'] - 4) & 0xffffffff
            self.write_mem(self.r['esp'], self.read(op[0], 32), 4)
        elif mn == 'pop':
            val = self.read_mem(self.r['esp'], 4)
            self.r['esp'] = (self.r['esp'] + 4) & 0xffffffff
            self.write(op[0], val, self.bits(op[0]))
        elif mn == 'mov': self.write(op[0], self.read(op[1], self.bits(op[0])), self.bits(op[0]))
        elif mn == 'lea': self.write(op[0], self.addr(self.clean(op[1])), self.bits(op[0]))
        elif mn in ('add', 'sub', 'sbb', 'xor', 'or', 'and'):
            bits = self.bits(op[0]); a = self.read(op[0], bits); b = self.read(op[1], bits)
            if mn == 'add': res = a + b; self.add_flags(a, b, res, bits)
            elif mn == 'sub': res = a - b; self.sub_flags(a, b, res, bits)
            elif mn == 'sbb': b += self.f['CF']; res = a - b; self.sub_flags(a, b, res, bits)
            elif mn == 'xor': res = a ^ b; self.logic_flags(res, bits)
            elif mn == 'or': res = a | b; self.logic_flags(res, bits)
            else: res = a & b; self.logic_flags(res, bits)
            self.write(op[0], res, bits)
        elif mn == 'cmp':
            bits = self.bits(op[0]); a = self.read(op[0], bits); b = self.read(op[1], bits)
            self.sub_flags(a, b, a - b, bits)
        elif mn == 'test':
            bits = self.bits(op[0]); self.logic_flags(self.read(op[0], bits) & self.read(op[1], bits), bits)
        elif mn in ('inc', 'dec'):
            bits = self.bits(op[0]); a = self.read(op[0], bits); cf = self.f['CF']
            res = a + 1 if mn == 'inc' else a - 1
            (self.add_flags if mn == 'inc' else self.sub_flags)(a, 1, res, bits)
            self.f['CF'] = cf
            self.write(op[0], res, bits)
        elif mn in ('not', 'neg'):
            bits = self.bits(op[0]); a = self.read(op[0], bits)
            if mn == 'not': self.write(op[0], ~a, bits)
            else: self.sub_flags(0, a, -a, bits); self.write(op[0], -a, bits)
        elif mn in ('rol', 'ror', 'shl', 'shr', 'sar'):
            # Count is often 0 mod operand size here. Updating the value is enough for this shellcode path.
            bits = self.bits(op[0]); val = self.read(op[0], bits); cnt = self.read(op[1], 8) & 0x1f
            res = val & mask(bits)
            if cnt:
                if mn == 'rol': res = ((res << (cnt % bits)) | (res >> (bits - (cnt % bits)))) & mask(bits)
                elif mn == 'ror': res = ((res >> (cnt % bits)) | (res << (bits - (cnt % bits)))) & mask(bits)
                elif mn == 'shl': res = (res << cnt) & mask(bits)
                elif mn == 'shr': res = (res >> cnt) & mask(bits)
                elif mn == 'sar': res = ((res | (~mask(bits))) >> cnt) & mask(bits) if res & (1 << (bits - 1)) else res >> cnt
                self.logic_flags(res, bits)
            self.write(op[0], res, bits)
        elif mn == 'xchg':
            bits = self.bits(op[0]); a, b = self.read(op[0], bits), self.read(op[1], bits)
            self.write(op[0], b, bits); self.write(op[1], a, bits)
        elif mn.startswith('j'):
            if self.cond(mn):
                target = int(op[0], 16)
                # The challenge's incomplete shellcode contains a single jmp $ trap.
                neip = neip if target == addr else target
        elif mn == 'int':
            pass
        else:
            raise RuntimeError(f'unsupported at 0x{addr:x}: {rest}')
        self.eip = neip


def main():
    cpu = CPU()
    steps = 0
    while cpu.eip < 0x1b9d and steps < 50000:
        cpu.step(); steps += 1
    blob = b''.join(x.to_bytes(4, 'little') for x in cpu.trace)
    m = re.search(rb'ASIS\{[^}]+\}', blob)
    if not m:
        raise SystemExit('flag not found')
    print(m.group(0).decode())

if __name__ == '__main__':
    main()
