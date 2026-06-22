# SiebersecCTF - Crypto - 67

## Vulnerability Analysis
1. **Smooth Order Modulus ($p-1$)**: Komentar `#my p is a smooth criminal` menandakan bahwa $p-1$ memiliki faktor prima yang sangat kecil (*B-smooth*). Hal ini membuat *Discrete Logarithm Problem* (DLP) rentan terhadap algoritma Pohlig-Hellman. Kita bisa mencari nilai logaritma diskret parsial pada *subgroup* kecil tanpa perlu memecahkan seluruh nilai $x \pmod{p-1}$.
2. **Low-Density Subset Sum (Knapsack)**: Struktur string eksponen $x$ dikonstruksi per bit dari kunci AES berukuran 128-bit. Setiap bit direpresentasikan oleh blok 200 karakter angka `6` atau `7`. Masalah ini dapat dimodelkan sebagai *Subset Sum Problem* dengan densitas sangat rendah, yang sangat optimal diselesaikan menggunakan reduksi basis *lattice* melalui algoritma LLL (Lenstra–Lenstra–Lovász).

## Exploit Strategy
1. Gunakan SageMath untuk memfaktorkan $p-1$ dan kumpulkan faktor prima kecil di bawah $5 \times 10^9$.
2. Hitung logaritma diskret parsial pada *subgroup* tersebut menggunakan algoritma Pohlig-Hellman untuk mendapatkan nilai eksponen parsial $T_{partial}$ terhadap modulus gabungan $M_{partial}$. Target modulus yang dikumpulkan dibuat $> 2^{600}$ untuk menurunkan densitas *Subset Sum* menjadi $\approx 0.21$.
3. Susun matriks *lattice* berdasarkan hubungan linear antara bit kunci AES dengan bobot pergeseran angka desimal $10^{200 \times (127 - i)}$.
4. Jalankan reduksi LLL pada matriks tersebut untuk mengekstrak vektor bit asli.
5. Rekonstruksi bit menjadi kunci AES dan lakukan dekripsi ECB untuk mendapatkan flag.

## Exploit Script
```python
# solve.sage
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import sys

sys.set_int_max_str_digits(30000)

g = 2
p = 420730... # Salin dari chall.py
y = 177939... # Salin dari output
ct = bytes.fromhex('fd4bbb20d0a3f7a1133a60c4c5780bc6e2108857d76194fdac090d5895b2621e70b05c0ec9cf04def73493c58aad362d70b05c0ec9cf04def73493c58aad362d3fb7ea4b1bbd3d19fb24dea3874c9181')

p_minus_1 = p - 1
F_factors = factor(p_minus_1)

rems, mods = [], []
M_partial = 1
F_mod = Zmod(p)
g_mod, y_mod = F_mod(g), F_mod(y)

for q, e in F_factors:
    sub_order = q**e
    if sub_order > 5 * 10**9: continue
    power = p_minus_1 // sub_order
    x_q = discrete_log(y_mod**power, g_mod**power, ord=sub_order)
    rems.append(x_q)
    mods.append(sub_order)
    M_partial *= sub_order
    if M_partial > 2**600: break

T_partial = crt(rems, mods)
X_base = int("6" * (128 * 200))
S = (T_partial - X_base) % M_partial
w = [pow(10, 200 * (127 - i), M_partial) for i in range(128)]

n = 128
N = 2**512
M = Matrix(ZZ, n + 2, n + 1)
for i in range(n):
    M[i, i] = 2
    M[i, n] = 2 * N * w[i]
M[n, n] = 2 * N * M_partial
for i in range(n): M[n+1, i] = -1
M[n+1, n] = -2 * N * S

L = M.LLL()
for row in L:
    if all(abs(val) == 1 for val in row[:n]) and row[n] == 0:
        bits = [ (val + 1) // 2 for val in row[:n] ]
        key_bin = "".join(str(b) for b in bits)
        try:
            cipher = AES.new(long_to_bytes(int(key_bin, 2)), AES.MODE_ECB)
            from Crypto.Util.Padding import unpad
            print(unpad(cipher.decrypt(ct), 16).decode())
            break
        except: continue
