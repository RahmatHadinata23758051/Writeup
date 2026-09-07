import math
import re
from Crypto.Util.number import isPrime, long_to_bytes


def crt(remainders, moduli):
    total = 0
    prod = math.prod(moduli)
    for r_i, m_i in zip(remainders, moduli):
        p = prod // m_i
        inv = pow(p, -1, m_i)
        total += r_i * p * inv
    return total % prod, prod


with open("output.txt", "r") as f:
    content = f.read()

N = int(re.search(r"N\s*=\s*(\d+)", content).group(1))
e = int(re.search(r"e\s*=\s*(\d+)", content).group(1))
ct = int(re.search(r"ct\s*=\s*(\d+)", content).group(1))

print("[*] Mencari faktor prima kecil (p < 2^24)...")

small_primes = []
temp_N = N

# Modulus awal dibangun dari prima 24-bit (2^23 <= p < 2^24)
LIMIT = 1 << 24
for p in range(2, 1000):
    if temp_N % p == 0:
        small_primes.append(p)
        while temp_N % p == 0:
            temp_N //= p

# Sieve atau trial division prima ganjil
# Karena getPrime(24), nilainya berada pada interval 2^23 s.d. 2^24
current = 1 << 23
if current % 2 == 0:
    current += 1

total_bits = 1
while total_bits <= 256 and current < LIMIT:
    if temp_N % current == 0:
        small_primes.append(current)
        temp_N //= current
        total_bits = math.prod(small_primes).bit_length()
        print(f"    [+] Menemukan prima: {current} (Akumulasi: {total_bits} bits)")
    current += 2

print(f"[*] Total faktor kecil terkumpul: {len(small_primes)}")

# Rekonstruksi m via CRT
remainders = []
for p in small_primes:
    d = pow(e, -1, p - 1)
    m_p = pow(ct % p, d, p)
    remainders.append(m_p)

m, modulus_prod = crt(remainders, small_primes)

flag = long_to_bytes(m)
print(f"[+] Flag: {flag.decode(errors='ignore')}")
