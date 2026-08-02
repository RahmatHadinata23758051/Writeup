#!/usr/bin/env python3

from math import isqrt
from Crypto.Util.number import long_to_bytes

N = 3646154850295011369707131011438711095400799139943170490872585628683549034362552065955809589514611470241298944167703929337528884908857116141935206466329730159085752668345654509936331954688615906022854023944431613697568688287347119236246668637626142345227229770764648063010195138432756035056498879142322827510772511775252426866445166513402587

e = 65537

c = 780130031328740731381241557377666116541606927063190613432095157294666504313173452612933931946256744751393203553303107662811734383338538890681670111946446558821571739189651457249936740715582882116998037215610749746023669674781060263244524001085422362588029607510686099014625329616764965784356054346294224270468618614209000880981745855992958

P_BOUND = 1 << 607
Q_BOUND = 1 << 521

# N = (2^607 - x)(2^521 - y)
delta = P_BOUND * Q_BOUND - N

# delta ≡ -xy (mod 2^521)
xy = (-delta) % Q_BOUND

print(f"[+] xy = {xy}")

p = None
q = None

# Cari seluruh pasangan faktor xy.
for divisor in range(1, isqrt(xy) + 1):
    if xy % divisor != 0:
        continue

    factor_pairs = [
        (divisor, xy // divisor),
        (xy // divisor, divisor),
    ]

    for x, y in factor_pairs:
        candidate_p = P_BOUND - x
        candidate_q = Q_BOUND - y

        if candidate_p * candidate_q == N:
            p = candidate_p
            q = candidate_q

            print(f"[+] x = {x}")
            print(f"[+] y = {y}")
            break

    if p is not None:
        break

if p is None or q is None:
    raise ValueError("Faktor N tidak ditemukan")

assert p.bit_length() == 607
assert q.bit_length() == 521
assert p * q == N

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

m = pow(c, d, N)
flag = long_to_bytes(m)

print(f"[+] p = {p}")
print(f"[+] q = {q}")
print(f"[+] flag = {flag.decode()}")
