#!/usr/bin/env sage-python
from sage.all import *
import socket, ssl, re, time, statistics, itertools, math

HOST = "tcp-01kz0vs295e0e5sckqywc13bnz.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

# Low bits untuk Coppersmith.
LOW = 300

# High bits cuma untuk estimasi rasio k/G, bukan langsung k.
HIGH = 80

# Jangan terlalu besar biar tidak habis waktu instance.
REFINE = 70

# Branch low-bit timing error.
LOW_AMB_COUNT = 18
LOW_MAX_FLIPS = 3

# Branch high-bit timing error untuk estimasi rasio k/G.
HIGH_AMB_COUNT = 10
HIGH_MAX_FLIPS = 2

R_MARGIN = 128

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data

def connect():
    raw = socket.create_connection((HOST, PORT), timeout=20)
    ctx = ssl._create_unverified_context()
    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    sock.settimeout(120)
    return sock

sock = connect()
banner = recv_until(sock, b"command> ")

e = int(re.search(rb"e = (\d+)", banner).group(1))
n = int(re.search(rb"n = (\d+)", banner).group(1))
ct = int(re.search(rb"ciphertext = ([0-9a-fA-F]+)", banner).group(1), 16)

BITS = n.bit_length()
K = BITS + 32
M = 1 << K
MASK = M - 1
INV_M = pow(M % n, -1, n)
BASE = 2

print("[+] bits =", BITS)

def craft(mask, base=BASE):
    # Cari x negatif sehingga:
    # x % n == base
    # x low K bits == mask
    t = ((base - mask) * INV_M) % n
    x = mask + M * t
    x -= M * n

    assert x < 0
    assert x % n == base
    assert (x & MASK) == mask

    return x

def hx(x):
    if x < 0:
        return ("-" + format(-x, "x")).encode()
    return format(x, "x").encode()

def relay_mask(mask):
    x = craft(mask)
    t0 = time.perf_counter()

    sock.sendall(b"relay " + hx(x) + b"\n")
    data = recv_until(sock, b"command> ")

    if b"rejected" in data:
        print(data.decode(errors="ignore"))
        raise SystemExit("relay rejected")

    return time.perf_counter() - t0

def diff_bit(i, reps=1):
    arr = []

    for r in range(reps):
        if r & 1:
            b = relay_mask(1 << i)
            a = relay_mask(0)
        else:
            a = relay_mask(0)
            b = relay_mask(1 << i)

        arr.append(b - a)

    return statistics.median(arr)

def robust_threshold(values):
    vals = sorted(float(x) for x in values)

    # Trim outlier besar karena network jitter.
    if len(vals) > 50:
        cut = max(2, len(vals) // 20)
        vals = vals[cut:-cut]

    mid = len(vals) // 2
    lo = vals[:mid]
    hi = vals[mid:]

    c0 = statistics.median(lo)
    c1 = statistics.median(hi)

    if c0 > c1:
        c0, c1 = c1, c0

    return (c0 + c1) / 2, c0, c1

# Warmup.
for _ in range(8):
    relay_mask(0)

need = set(range(LOW))
need.update(range(max(0, BITS - HIGH), BITS))
need = sorted(need)

diffs = {}

print("[+] measuring", len(need), "bits")
for idx, bit in enumerate(need):
    diffs[bit] = diff_bit(bit, 1)

    if idx % 50 == 0:
        print("[+] measured", idx, "/", len(need))

th, c0, c1 = robust_threshold(diffs.values())
print("[+] threshold1 =", th, "clusters =", c0, c1)

# Private exponent d pasti ganjil, jadi bit 0 = 1.
# Jangan paksa bit 1, karena d bisa inverse modulo lambda(n).
diffs[0] = max(diffs.values()) + abs(max(diffs.values())) + 1.0

ambiguous = sorted(need, key=lambda i: abs(float(diffs[i]) - th))

print("[+] refining", REFINE, "ambiguous bits")
for idx, bit in enumerate(ambiguous[:REFINE]):
    old = diffs[bit]
    diffs[bit] = statistics.median([old, diff_bit(bit, 1), diff_bit(bit, 1)])

    if idx % 20 == 0:
        print("[+] refined", idx, "/", REFINE)

th, c0, c1 = robust_threshold(diffs.values())
print("[+] threshold2 =", th, "clusters =", c0, c1)

def guess(bit):
    return 1 if float(diffs[bit]) > th else 0

def build_dlow(flips=()):
    dlow = 0

    for i in range(LOW):
        if guess(i):
            dlow |= 1 << i

    dlow |= 1

    for b in flips:
        dlow ^= 1 << b

    return int(dlow)

def build_dtop(flips=()):
    high_start = max(0, BITS - HIGH)
    dtop = 0

    for i in range(high_start, BITS):
        if guess(i):
            dtop |= 1 << (i - high_start)

    for b in flips:
        dtop ^= 1 << (b - high_start)

    return int(dtop)

base_dlow = build_dlow()
print("[+] base dlow popcount =", base_dlow.bit_count())
print("[+] base dlow hex =", hex(base_dlow))

if base_dlow.bit_count() < 70:
    print("[-] dlow too sparse, timing threshold bad")
    raise SystemExit

high_start = max(0, BITS - HIGH)

low_amb = [i for i in ambiguous if 1 <= i < LOW][:LOW_AMB_COUNT]
high_amb = [i for i in ambiguous if high_start <= i < BITS][:HIGH_AMB_COUNT]

print("[+] low ambiguous =", low_amb)
print("[+] high ambiguous =", high_amb)

def subsets(items, max_w):
    out = [()]

    for w in range(1, max_w + 1):
        out.extend(itertools.combinations(items, w))

    return out

low_flip_sets = subsets(low_amb, LOW_MAX_FLIPS)
high_flip_sets = subsets(high_amb, HIGH_MAX_FLIPS)

print("[+] low variants =", len(low_flip_sets))
print("[+] high variants =", len(high_flip_sets))

# Dari high bits d, estimasi rasio R = k/G, karena:
# e*d - 1 = k*lambda(n)
# lambda(n) = phi(n)/G
# maka e*d ~= (k/G)*n
ratio_candidates = set()

sqrt_n = math.isqrt(n)

for flips in high_flip_sets:
    dtop = build_dtop(flips)
    lo_d = dtop << high_start
    hi_d = ((dtop + 1) << high_start) - 1

    rmin = int((e * lo_d) // n) - R_MARGIN
    rmax = int((e * hi_d) // max(1, n - 4 * sqrt_n)) + R_MARGIN

    rmin = max(1, rmin)
    rmax = min(e - 1, rmax)

    for r in range(rmin, rmax + 1):
        ratio_candidates.add(r)

ratio_candidates = sorted(ratio_candidates)
print("[+] ratio candidates count =", len(ratio_candidates))
print("[+] ratio range =", ratio_candidates[:5], "...", ratio_candidates[-5:])

if not ratio_candidates:
    print("[-] no ratio candidates")
    raise SystemExit

min_r = max(1, min(ratio_candidates))
max_G = min(256, (e - 1) // min_r + 8)
max_G = max(max_G, 2)

print("[+] trying G up to", max_G)

pair_candidates = set()

rlo = min(ratio_candidates)
rhi = max(ratio_candidates)

for G in range(1, max_G + 1):
    # k/G berada sekitar rlo..rhi
    klo = max(1, (rlo - 2) * G)
    khi = min(e - 1, (rhi + 2) * G)

    for k in range(klo, khi + 1):
        pair_candidates.add((k, G))

pair_candidates = sorted(pair_candidates)
print("[+] (k,G) pairs =", len(pair_candidates))

def v2(x):
    c = 0
    while x % 2 == 0:
        c += 1
        x //= 2
    return c

def roots_sum_mod_power2(S, bits):
    # cari p mod 2^bits dari:
    # p + q = S mod 2^bits
    # p*q = n mod 2^bits
    roots = [1]

    for m in range(1, bits):
        mod = 1 << (m + 1)
        new = []

        for r in roots:
            for b in (0, 1):
                rr = r | (b << m)
                if (rr * ((S - rr) % mod) - n) % mod == 0:
                    new.append(rr)

        roots = list(set(new))

        if not roots:
            return []

        # Safety, biasanya cuma sedikit root.
        if len(roots) > 32:
            roots = roots[:32]

    return roots

def try_coppersmith(plow, known_bits):
    # p = plow + 2^known_bits * x
    # x kecil karena p sekitar 512 bit.
    R = PolynomialRing(Zmod(n), "x")
    x = R.gen()

    step = 1 << known_bits
    inv_step = inverse_mod(step, n)

    # Monic polynomial modulo n.
    f = x + Zmod(n)(plow) * Zmod(n)(inv_step)

    xbits = max(1, (BITS + 1) // 2 - known_bits + 8)
    X = 1 << xbits

    try:
        roots = f.small_roots(X=X, beta=0.49, epsilon=0.02)
    except Exception:
        roots = []

    for root in roots:
        p = int(plow + step * int(root))

        if p > 1 and n % p == 0:
            return p

    return None

def try_factor_from_dlow(dlow):
    # Coba beberapa panjang known bits.
    # Ini membantu kalau bit 290-an salah, tapi 270-an awal benar.
    use_bits_list = [300, 296, 292, 288, 284, 280, 276, 272, 268]

    for use_bits in use_bits_list:
        dpart = int(dlow & ((1 << use_bits) - 1))
        full_mod = 1 << use_bits

        print("[+] trying known bits", use_bits)

        for idx, (k, G) in enumerate(pair_candidates):
            if idx % 3000 == 0 and idx:
                print("[+] pair", idx, "/", len(pair_candidates), "use_bits", use_bits)

            s = v2(k)
            bits = use_bits - s

            if bits < 260:
                continue

            rhs = (G * (e * dpart - 1)) % full_mod

            if rhs % (1 << s) != 0:
                continue

            mod = 1 << bits
            kk = k >> s

            try:
                invk = pow(kk, -1, mod)
            except ValueError:
                continue

            phi_low = ((rhs >> s) * invk) % mod
            S_low = (n + 1 - phi_low) % mod

            roots = roots_sum_mod_power2(S_low, bits)

            if not roots:
                continue

            for plow in roots:
                p = try_coppersmith(int(plow), bits)

                if p:
                    print("[+] found with k =", k, "G =", G, "bits =", bits)
                    return int(p)

    return None

p_found = None

for vi, flips in enumerate(low_flip_sets):
    dlow = build_dlow(flips)

    if vi % 25 == 0:
        print("[+] low variant", vi, "/", len(low_flip_sets), "flips", flips)

    p_found = try_factor_from_dlow(dlow)

    if p_found:
        break

if not p_found:
    print("[-] failed to factor")
    with open("timing_bits.txt", "w") as f:
        for i in need:
            f.write(f"{i} {diffs[i]} {guess(i)}\n")
    print("[+] saved timing_bits.txt")
    raise SystemExit

p = int(p_found)
q = n // p

print("[+] p =", p)
print("[+] q =", q)

phi = (p - 1) * (q - 1)
d_phi = pow(e, -1, phi)

pt = pow(ct, d_phi, n)
pt_hex = hex(pt)[2:]

print("[+] plaintext hex =", pt_hex)

sock.sendall(b"release " + pt_hex.encode() + b"\n")

try:
    print(sock.recv(4096).decode(errors="ignore"))
    print(sock.recv(4096).decode(errors="ignore"))
except Exception:
    pass
