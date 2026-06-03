import re, base64
from pathlib import Path

SRC = Path('n00t.lua') if Path('n00t.lua').exists() else Path('/mnt/data/n00t.lua')
text = SRC.read_text()
blob_src = text.split('local blob = table.concat({', 1)[1].split('},', 1)[0]
blob = ''.join(re.findall(r"'([^']*)'", blob_src))
key = [81,252,82,94,56,237,57,243,230,28,165,73,217,51,81,187,
       41,202,186,168,43,247,251,143,33,171,105,95,101,247,112,25]
payload = bytes(b ^ key[i % len(key)] for i, b in enumerate(base64.b64decode(blob)))

# Minimal Lua 5.1 chunk parser: enough to read constants/code and rebuild the VM matrix.
import struct
class R:
    def __init__(self, b):
        assert b[:4] == b'\x1bLua'
        self.b = b; self.p = 6
        self.endian = b[self.p]; self.p += 1
        self.sz_int = b[self.p]; self.p += 1
        self.sz_size = b[self.p]; self.p += 1
        self.sz_inst = b[self.p]; self.p += 1
        self.sz_num = b[self.p]; self.p += 1
        self.integral = b[self.p]; self.p += 1
        self.pref = '<' if self.endian == 1 else '>'
    def read(self, n):
        x = self.b[self.p:self.p+n]; self.p += n; return x
    def u8(self): return self.read(1)[0]
    def int(self): return struct.unpack(self.pref + {4:'I',8:'Q'}[self.sz_int], self.read(self.sz_int))[0]
    def size_t(self): return struct.unpack(self.pref + {4:'I',8:'Q'}[self.sz_size], self.read(self.sz_size))[0]
    def num(self): return struct.unpack(self.pref + {8:'d',4:'f'}[self.sz_num], self.read(self.sz_num))[0]
    def string(self):
        n = self.size_t()
        if n == 0: return None
        s = self.read(n)
        return s[:-1] if s and s[-1] == 0 else s
    def proto(self):
        self.string(); self.int(); self.int(); self.u8(); self.u8(); self.u8(); self.u8()
        code = [struct.unpack(self.pref+'I', self.read(4))[0] for _ in range(self.int())]
        const = []
        for _ in range(self.int()):
            t = self.u8()
            if t == 0: v = None
            elif t == 1: v = bool(self.u8())
            elif t == 3: v = self.num()
            elif t == 4: v = self.string()
            const.append(v)
        protos = [self.proto() for _ in range(self.int())]
        for _ in range(self.int()): self.int()
        loc = [(self.string(), self.int(), self.int()) for _ in range(self.int())]
        upn = [self.string() for _ in range(self.int())]
        return {'code': code, 'const': const, 'protos': protos, 'loc': loc, 'upn': upn}

def dec(i):
    return i & 0x3f, (i >> 6) & 0xff, (i >> 23) & 0x1ff, (i >> 14) & 0x1ff, (i >> 14) & 0x3ffff

p = R(payload).proto()
K = p['const']
# Arrays are constructed with LOADK ... SETLIST in the main proto:
# R6 = encrypted 37x37 matrix, R7 = encrypted targets.
regs = [None] * 80
arrays = {}
for ins in p['code'][:1453]:
    op, A, B, C, Bx = dec(ins)
    if op == 1:       # LOADK
        regs[A] = K[Bx]
    elif op == 10:    # NEWTABLE
        regs[A] = {}
    elif op == 34:    # SETLIST
        n = B or 0
        block = C
        if isinstance(regs[A], dict):
            for i in range(1, n + 1):
                regs[A][(block - 1) * 50 + i] = regs[A + i]
        arrays[A] = regs[A]

enc_matrix = [int(arrays[6][i]) for i in range(1, 1369 + 1)]
enc_target = [int(arrays[7][i]) for i in range(1, 37 + 1)]
MOD = 257
# These are the two loadstring-generated decoder lambdas in the Lua bytecode.
def dmat(v, i): return ((v - 91) - i) * 121 % MOD
def dtgt(v, i): return ((v - 91) - i * 3) * 121 % MOD

A = []
b = []
for r in range(37):
    A.append([dmat(enc_matrix[r * 37 + c], c) for c in range(37)])
    b.append(dtgt(enc_target[r], r))

# Gaussian elimination over GF(257).
M = [row[:] + [rhs] for row, rhs in zip(A, b)]
rank = 0
where = [-1] * 37
for col in range(37):
    pivot = next((i for i in range(rank, 37) if M[i][col] % MOD), None)
    if pivot is None: continue
    M[rank], M[pivot] = M[pivot], M[rank]
    inv = pow(M[rank][col] % MOD, -1, MOD)
    M[rank] = [(x * inv) % MOD for x in M[rank]]
    for i in range(37):
        if i != rank and M[i][col] % MOD:
            f = M[i][col] % MOD
            M[i] = [(M[i][j] - f * M[rank][j]) % MOD for j in range(38)]
    where[col] = rank
    rank += 1

core = ''.join(chr(M[where[i]][37]) for i in range(37))
print(f'THEM?!CTF{{{core}}}')
