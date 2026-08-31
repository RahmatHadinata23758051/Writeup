#!/usr/bin/env python3
import socket, re, random, sys
from sage.all import matrix, ZZ

HOST = sys.argv[1] if len(sys.argv) > 1 else "34.2.147.230"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3002

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
BND = 1 << 128
CENTER = 1 << 127


class IO:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.s.settimeout(8)
        self.buf = b""

    def recv_until(self, token):
        while token not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        i = self.buf.find(token)
        if i == -1:
            out, self.buf = self.buf, b""
            return out
        i += len(token)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def sendline(self, x):
        if isinstance(x, str):
            x = x.encode()
        self.s.sendall(x + b"\n")

    def recvall(self):
        out = self.buf
        self.buf = b""
        self.s.settimeout(2)
        while True:
            try:
                c = self.s.recv(4096)
                if not c:
                    break
                out += c
            except socket.timeout:
                break
        return out


def inv_mod(x, m):
    return pow(int(x), -1, int(m))


def ec_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if P1 == P2:
        lam = (3 * x1 * x1 + A) * inv_mod(2 * y1 % P, P) % P
    else:
        lam = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def ec_mul(k, pt):
    k %= N
    if k == 0 or pt is None:
        return None

    R = None
    Q = pt
    while k:
        if k & 1:
            R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        k >>= 1
    return R


def rol32(x, r):
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK32


def ror32(x, r):
    r &= 31
    return ((x >> r) | (x << (32 - r))) & MASK32


def rol64(x, r):
    r &= 63
    return ((x << r) | (x >> (64 - r))) & MASK64


def panel_inv(out, pos):
    salt = (0xA5A5A5A5 + pos * 0x6D2B79F5) & MASK32
    bump = (0x9E3779B9 ^ (pos * 0x85EBCA6B)) & MASK32
    y = (out - bump) & MASK32
    return ror32(y, pos * 7 + 3) ^ salt


def undo_right(y, sh):
    x = y
    for _ in range(6):
        x = y ^ (x >> sh)
    return x & MASK32


def undo_left(y, sh, mask):
    x = y
    for _ in range(6):
        x = y ^ ((x << sh) & mask)
    return x & MASK32


def untemper(y):
    y = undo_right(y, 18)
    y = undo_left(y, 15, 0xEFC60000)
    y = undo_left(y, 7, 0x9D2C5680)
    y = undo_right(y, 11)
    return y & MASK32


def fold_piece(x, pos, lane):
    x ^= ((pos + 1) * 0xD6E8FEB86659FD93 + lane * 0xA0761D6478BD642F) & MASK64
    x = rol64(x, 17 + pos * 9 + lane * 23)
    x = (x * 0x9E6C63D0676A9A99 + 0xD1B54A32D192ED03) & MASK64
    return x


def make_piece(a, b, pos):
    return (fold_piece(a, pos, 0) << 64) | fold_piece(b, pos, 1)


def parse_pubs(out):
    s = out.decode(errors="ignore")
    pubs = {}
    pat = r"Unit #(\d+):\s+X = 0x([0-9a-f]+)\s+Y = 0x([0-9a-f]+)"
    for i, x, y in re.findall(pat, s, re.S):
        pubs[int(i)] = (int(x, 16), int(y, 16))
    return pubs


def parse_entries(out):
    s = out.decode(errors="ignore")
    return [(int(pos), int(v, 16)) for pos, v in re.findall(r"entry_(\d+) = 0x([0-9a-f]{8})", s)]


def parse_sig(out):
    s = out.decode(errors="ignore")
    m = re.search(r"z = (\d+).*?r = (\d+).*?s = (\d+)", s, re.S)
    if not m:
        print(s)
        raise RuntimeError("signature parse gagal")
    return tuple(map(int, m.groups()))


def recover_key(sigs, pub=None):
    m = len(sigs)
    p = m - 1

    aa, bb = [], []
    for z, r, s, K in sigs:
        rinv = inv_mod(r, N)
        aa.append(((s * K - z) * rinv) % N)
        bb.append((s * rinv) % N)

    Aeq, ceq = [], []
    for i in range(1, m):
        row = [0] * m
        row[0] = (-bb[0]) % N
        row[i] = bb[i] % N

        c = (aa[0] - aa[i] - sum(row[j] * CENTER for j in range(m))) % N
        Aeq.append(row)
        ceq.append(c)

    for wbits in (150, 155, 160):
        W = 1 << wbits
        EMB = CENTER
        dim = m + p + 1
        basis = []

        for i in range(m):
            row = [0] * dim
            row[i] = 1
            for j in range(p):
                row[m + j] = Aeq[j][i] * W
            basis.append(row)

        for j in range(p):
            row = [0] * dim
            row[m + j] = N * W
            basis.append(row)

        row = [0] * dim
        for j in range(p):
            row[m + j] = ceq[j] * W
        row[-1] = EMB
        basis.append(row)

        L = matrix(ZZ, basis).LLL()

        for v in L.rows():
            v = [int(x) for x in v]

            if abs(v[-1]) != EMB:
                continue
            if any(v[m + j] != 0 for j in range(p)):
                continue

            xs = v[:m] if v[-1] < 0 else [-x for x in v[:m]]
            es = [x + CENTER for x in xs]

            if not all(0 <= e < BND for e in es):
                continue

            z, r, s, K = sigs[0]
            d = ((s * ((K + es[0]) % N) - z) * inv_mod(r, N)) % N

            ok = True
            for (z, r, s, K), e in zip(sigs, es):
                if (s * ((K + e) % N) - z - r * d) % N != 0:
                    ok = False
                    break

            if ok and pub is not None and ec_mul(d, (Gx, Gy)) != pub:
                ok = False

            if ok:
                return d

    raise RuntimeError("LLL gagal recover key")


io = IO(HOST, PORT)
io.recv_until(b"menu> ")

print("[*] ambil public records")
io.sendline("1")
out = io.recv_until(b"menu> ")
pubs = parse_pubs(out)
pub0 = pubs.get(0)
print("[+] pub unit0 parsed")

print("[*] leak 624 output MT dari data panel")
outs = [None] * 624

for _ in range(8):
    io.sendline("5")
    out = io.recv_until(b"menu> ")
    for pos, val in parse_entries(out):
        if pos < 624:
            outs[pos] = panel_inv(val, pos)

if any(x is None for x in outs):
    raise RuntimeError("output panel kurang dari 624")

state = [untemper(x) for x in outs]
rng = random.Random()
rng.setstate((3, tuple(state + [624]), None))
print("[+] MT cloned")

print("[*] request 4 signature unit0 + prediksi nonce high")
sigs = []

for t in range(4):
    a = rng.getrandbits(64)
    b = rng.getrandbits(64)
    chunk_a = make_piece(a, b, t)
    K = (chunk_a << 128) % N

    io.sendline("3")
    io.recv_until(b": ")
    io.sendline("0")
    io.recv_until(b": ")
    io.sendline(f"piyak-{t}")

    out = io.recv_until(b"menu> ")
    z, r, s = parse_sig(out)
    sigs.append((z, r, s, K))
    print(f"[+] sig {t} ok")

print("[*] recover private key via lattice")
d = recover_key(sigs, pub0)
print(f"[+] secret = {d}")

print("[*] submit code")
io.sendline("6")
io.recv_until(b": ")
io.sendline(str(d))

final = io.recvall().decode(errors="ignore")
print(final)
