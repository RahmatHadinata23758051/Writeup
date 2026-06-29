import sys
from math import gcd, isqrt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import random

# Data dari output.txt
n = 14884800451955950069113725819582523452585625680964352925405287702945124871438012573975746640883842103042984750487942943421571681652252352348393111535120212824144300409490952092961805337273025660675021221223760281669849366431560452175211927388902210616902198236233541611572685032003626072414569507837860098262478925981342654902998086422642563797070782607595233706836044689489106803015979
e = 65537
c = bytes.fromhex("25fed2dac3d3562dc8824679a10693b6fef217da7eff6148837c4e5cf26ad9a7a5bb61de9cf0acbc260fb217cfd41d3b106b5c60de887e46645f2d8ab209e13ed9fdb2e1775353772976a8741da05b11931c881a763b6ac41e5516e323fd2db3001a1a4c0fe55bd31071cd9f81e830b49a80846a7c859b669cfdbfe41951fe46fdf529b3dc6924f949264641cc0b9429f423c2d2a8334a5dbb879f32c918a87b")

def primes_upto(limit):
    sieve = [True] * (limit + 1)
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            for i in range(p * p, limit + 1, p):
                sieve[i] = False
    return [p for p in range(2, limit + 1) if sieve[p]]

def ec_add(P, Q, n):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and y1 == y2:
        num = (3 * x1 * x1) % n
        den = (2 * y1) % n
    elif x1 == x2:
        return None
    else:
        num = (y2 - y1) % n
        den = (x2 - x1) % n

    g = gcd(den, n)
    if 1 < g < n:
        raise ValueError(g)  # Zero-divisor ditemukan, faktor didapatkan!
    if g == n:
        return None

    inv_den = pow(den, -1, n)
    lam = (num * inv_den) % n
    x3 = (lam * lam - x1 - x2) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3)

def ec_mul(P, k, n):
    R = None
    for bit in bin(k)[2:]:
        R = ec_add(R, R, n)
        if bit == '1':
            R = ec_add(R, P, n)
    return R

# Membangun skalar K (faktor dari bilangan prima <= batas smooth)
SMOOTH_BOUND = 2**15
multipliers = []
for p in primes_upto(SMOOTH_BOUND):
    q = p
    while q * p <= SMOOTH_BOUND:
        q *= p
    multipliers.append(q)

print("[*] Memulai eksploitasi custom ECM pada y^2 = x^3 + B ...")
p_factor = None
attempts = 0

while not p_factor:
    attempts += 1
    # Memilih titik kurva eliptik secara acak (memilih B secara implisit)
    x = random.randrange(1, n)
    y = random.randrange(1, n)
    P = (x, y)
    print(f"[-] Mencoba twist acak (Percobaan ke-{attempts})...")
    
    try:
        for q in multipliers:
            P = ec_mul(P, q, n)
            if P is None:
                break
    except ValueError as err:
        p_factor = err.args[0]
        print(f"[+] JACKPOT! Faktor p ditemukan: {p_factor}")
        break

# Mendekripsi RSA
q_factor = n // p_factor
phi = (p_factor - 1) * (q_factor - 1)
d = pow(e, -1, phi)

key = RSA.construct((n, e, d, p_factor, q_factor))
cipher = PKCS1_OAEP.new(key)
flag = cipher.decrypt(c)

print("\n[+] FLAG:", flag.decode(errors='ignore'))
