Writeup CTF: HexTrap (Kriptografi)

Kategori: Kriptografi

Konsep: RSA, Eisenstein Integers, Complex Multiplication, Lenstra's Elliptic Curve Factorization (ECM)

Flag: v1t{six_twists_one_smooth_order}

1. Pendahuluan

Challenge ini memberikan kita sebuah skrip implementasi enkripsi RSA standar (PKCS1_OAEP), tetapi dengan satu keanehan besar: cara salah satu bilangan prima pendukungnya, yaitu $p$, di-generate. Alih-alih di-generate secara acak penuh, $p$ dibentuk menggunakan operasi-operasi aneh yang dinamakan hnorm (Hexagonal Norm) dan hmul.

Sistem ini menyembunyikan "pintu belakang" (trapdoor) matematika yang memungkinkan kita memfaktorkan modulus RSA $N$ menggunakan metode kurva eliptik.

2. Analisis Source Code

Mari kita bedah fungsi-fungsi utama dalam chall.py:

hnorm(z) dan hmul(z, w):
Fungsi ini merepresentasikan operasi pada Eisenstein Integers ($\mathbb{Z}[\omega]$), yaitu himpunan bilangan kompleks dengan bentuk $a + b\omega$, di mana $\omega = e^{2\pi i/3}$ (akar pangkat tiga dari 1).

Norm dari bilangan ini adalah: $N(x + y\omega) = x^2 - xy + y^2$.

Fungsi hmul adalah perkalian standar antara dua bilangan Eisenstein.

smooth_hex(bits, bag):
Fungsi ini membangun sebuah bilangan Eisenstein $z = x + y\omega$ dengan mengalikan bilangan-bilangan prima kecil (di bawah batas $2^{15}$). Karena sifat multiplikatif dari norm ($N(a \cdot b) = N(a) \cdot N(b)$), ini memastikan bahwa norm akhir $N(z) = m$ adalah bilangan yang sangat smooth (hanya memiliki faktor prima kecil).

special_prime(bits, bound):
Ini adalah inti dari jebakan tersebut.

Membangun $z = x + y\omega$ sehingga $N(z) = m$ (dimana $m$ adalah bilangan smooth).

Menghitung $p = N(z - 1) = (x-1)^2 - (x-1)y + y^2$.

Jika $p$ adalah bilangan prima, maka ia digunakan sebagai faktor untuk modulus RSA $n = p \times q$.

3. Landasan Matematika (The Math Walkthrough)

Mengapa pembentukan $p = N(z-1)$ sangat berbahaya? Ini berhubungan dengan Kurva Eliptik di medan berhingga $\mathbb{F}_p$.

Jika kita meninjau sebuah kurva eliptik $E$ dengan persamaan $y^2 = x^3 + B \pmod p$, kurva ini memiliki sesuatu yang disebut Complex Multiplication (CM) oleh $\mathbb{Z}[\omega]$. Kurva jenis ini (dengan j-invariant = 0) memiliki persis 6 kemungkinan twist (kelas isomorfisma) di atas $\mathbb{F}_p$, yang berkorespondensi dengan 6 unit dalam $\mathbb{Z}[\omega]$ (yaitu $\pm 1, \pm \omega, \pm \omega^2$).

Berdasarkan teori Complex Multiplication, karena $p = N(z-1)$, kita dapat menuliskan $p = \pi \bar{\pi}$ di mana $\pi = 1 - z$ adalah Frobenius endomorphism dari salah satu dari 6 twist kurva tersebut.

Banyaknya titik (ordo) pada kurva eliptik ini, yang disimbolkan dengan $N_E$, dihitung dengan rumus:


$$N_E = N(1 - \pi)$$

Substitusikan $\pi = 1 - z$ ke dalam rumus tersebut:


$$N_E = N(1 - (1 - z)) = N(z) = m$$

Kesimpulan Fatal: Salah satu dari 6 twist kurva $y^2 = x^3 + B \pmod p$ akan memiliki jumlah titik persis sebanyak $m$. Karena kita tahu dari fungsi smooth_hex bahwa $m$ sengaja dibuat $2^{15}$-smooth, maka kurva ini sangat rentan terhadap Lenstra's Elliptic Curve Factorization (ECM).

4. Skenario Serangan (Walkthrough Eksploitasi)

ECM standar bekerja dengan memilih kurva eliptik acak dan berharap jumlah titiknya adalah bilangan smooth. Tapi di sini, kita sudah tahu pasti ada kurva yang ordonya smooth.

Pilih Kurva Acak dari Keluarga $y^2 = x^3 + B$:
Kita tidak perlu menebak $B$. Kita cukup memilih titik acak $(x, y) \pmod n$ dan secara implisit ini mendefinisikan sebuah kurva $y^2 = x^3 + B \pmod n$.

Siapkan Skalar $K$:
$K$ adalah kelipatan persekutuan terkecil (KPK) dari semua bilangan prima pangkat $k$ di bawah $2^{15}$. $K$ ini dijamin merupakan kelipatan dari $m$.

Lakukan Perkalian Titik (Point Multiplication):
Kita kalikan titik acak kita dengan $K$ di kurva tersebut, yaitu $P' = K \times P \pmod n$.

Hukum Peluang 1/6:
Peluang titik $(x, y)$ yang kita pilih berada di twist yang benar (yang memiliki ordo $m$) adalah $1/6$. Jika kita memilih twist yang salah, perkalian tidak akan menghasilkan apa-apa dan kita ulangi dengan titik baru.

Faktorisasi Terjadi:
Jika kita berada di twist yang benar, karena $K$ adalah kelipatan dari ordo $m$, maka perhitungan $K \times P \pmod p$ akan mengarah ke "titik tak hingga" (Point at Infinity).
Dalam algoritma penjumlahan kurva eliptik, ini berarti penyebut pada perhitungan kemiringan (slope/gradien) akan menjadi kelipatan $p$. Saat kita melakukan gcd(penyebut, n), alih-alih mendapatkan 1, kita akan mendapatkan $p$! Modulus $n$ berhasil difaktorkan.

5. Script Exploit

Berikut adalah skrip lengkap yang merangkum skenario serangan di atas untuk mendapatkan flag.

import sys
from math import gcd, isqrt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import random

# Parameter dari challenge
n = 14884800451955950069113725819582523452585625680964352925405287702945124871438012573975746640883842103042984750487942943421571681652252352348393111535120212824144300409490952092961805337273025660675021221223760281669849366431560452175211927388902210616902198236233541611572685032003626072414569507837860098262478925981342654902998086422642563797070782607595233706836044689489106803015979
e = 65537
c = bytes.fromhex("25fed2dac3d3562dc8824679a10693b6fef217da7eff6148837c4e5cf26ad9a7a5bb61de9cf0acbc260fb217cfd41d3b106b5c60de887e46645f2d8ab209e13ed9fdb2e1775353772976a8741da05b11931c881a763b6ac41e5516e323fd2db3001a1a4c0fe55bd31071cd9f81e830b49a80846a7c859b669cfdbfe41951fe46fdf529b3dc6924f949264641cc0b9429f423c2d2a8334a5dbb879f32c918a87b")
SMOOTH_BOUND = 2**15

# 1. Menyiapkan Skalar Pengali K (Multipliers)
def primes_upto(limit):
    sieve = [True] * (limit + 1)
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            for i in range(p * p, limit + 1, p):
                sieve[i] = False
    return [p for p in range(2, limit + 1) if sieve[p]]

multipliers = []
for prime in primes_upto(SMOOTH_BOUND):
    q = prime
    while q * prime <= SMOOTH_BOUND:
        q *= prime
    multipliers.append(q)

# 2. Implementasi Kurva Eliptik Modulo n
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

    # KUNCI EKSPLOITASI: 
    # Jika gcd(den, n) tidak 1 dan bukan n, kita menemukan faktor n!
    g = gcd(den, n)
    if 1 < g < n:
        raise ValueError(g) 
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

# 3. Looping Lenstra's ECM mencari twist yang tepat (peluang 1/6)
print("[*] Menjalankan custom ECM...")
p_factor = None
attempts = 0

while not p_factor:
    attempts += 1
    # Memilih kurva secara implisit melalui pemilihan titik (x, y) acak
    P = (random.randrange(1, n), random.randrange(1, n))
    
    try:
        for q in multipliers:
            P = ec_mul(P, q, n)
            if P is None:
                break
    except ValueError as err:
        p_factor = err.args[0]
        print(f"[+] JACKPOT! Twist yang benar ditemukan pada percobaan ke-{attempts}")
        print(f"[+] p = {p_factor}")
        break

# 4. Mendekripsi Ciphertext
q_factor = n // p_factor
phi = (p_factor - 1) * (q_factor - 1)
d = pow(e, -1, phi)

key = RSA.construct((n, e, d, p_factor, q_factor))
cipher = PKCS1_OAEP.new(key)
flag = cipher.decrypt(c)

print(f"\n[+] Flag: {flag.decode()}")
