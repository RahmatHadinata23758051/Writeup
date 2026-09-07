import math
import re
from Crypto.Util.number import long_to_bytes

# 1. Baca data dari output.txt
with open("output.txt", "r") as f:
    content = f.read()

N1 = int(re.search(r"N1\s*=\s*(\d+)", content).group(1))
N2 = int(re.search(r"N2\s*=\s*(\d+)", content).group(1))
c1 = int(re.search(r"c1\s*=\s*(\d+)", content).group(1))

e = 0x10001

# 2. Cari faktor prima bersama (q) via GCD
q = math.gcd(N1, N2)
assert q > 1, "GCD gagal menemukan faktor prima!"

# 3. Hitung p dan phi(N1)
p = N1 // q
phi = (p - 1) * (q - 1)

# 4. Hitung private exponent d dan dekripsi c1
d = pow(e, -1, phi)
flag_int = pow(c1, d, N1)

# 5. Konversi ke teks bytes
flag = long_to_bytes(flag_int)
print(f"[+] Flag: {flag.decode(errors='ignore')}")
