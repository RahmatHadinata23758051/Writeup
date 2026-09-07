Berikut isi raw .md yang bisa langsung kamu simpan sebagai writeup.md:

# Writeup CTF: Beginner RSA

**Kategori:** Kriptografi  
**Tingkat Kesulitan:** Mudah (Beginner)  
**Artefak:** `chall.py`, `output.txt`  
**Flag:** `NSS{n3v3r_3v3r_r3u53_4_pr1m3!}`

---

## 1. Deskripsi Tantangan

Diberikan sebuah skrip Python `chall.py` yang mengimplementasikan kriptosistem RSA untuk mengenkripsi dua pesan yang berbeda ke dalam dua ciphertext (`c1` dan `c2`) menggunakan dua modulus yang berbeda (`N1` dan `N2`).

Skrip tersebut mengekspor nilai `N1`, `N2`, `c1`, dan `c2` ke dalam berkas `output.txt`.

Target dari tantangan ini adalah merekonstruksi teks asal (*plaintext*) dari `c1`, yang memuat flag kompetisi.

---

## 2. Analisis Kode Sumber

Berikut adalah implementasi pembangkitan kunci dan enkripsi pada `chall.py`:

```python
from Crypto.Util.number import getPrime, bytes_to_long

flag = bytes_to_long(b"NSS{?????????????????????????}")
notflag = bytes_to_long(b"welcome to NNS ctf 2026!")

p = getPrime(512)
q = getPrime(512)

N1 = p * q
N2 = q * getPrime(512)

e = 0x10001

c1 = pow(flag, e, N1)
c2 = pow(notflag, e, N2)

print(f"N1 = {N1}")
print(f"N2 = {N2}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")


Dari peninjauan kode di atas, parameter sistem dibentuk sebagai berikut:

Variabel p dan q masing-masing adalah bilangan prima 512-bit.
Modulus pertama dibentuk dari:

𝑁
1
=
𝑝
×
𝑞

Modulus kedua dibentuk dengan mengalikan bilangan prima q yang sama dengan bilangan prima 512-bit baru, misalkan r:

𝑁
2
=
𝑞
×
𝑟

Eksponen publik yang digunakan adalah:

𝑒
=
65537
=
0x10001

Ciphertext c1 dibentuk melalui operasi modular exponentiation:

𝑐
1
≡
𝑚
1
𝑒
(
m
o
d
𝑁
1
)

di mana $m_1$ merepresentasikan byte flag.

Celah Keamanan

Celah keamanan fatal terletak pada penggunaan ulang faktor prima q pada kedua modulus publik N1 dan N2.

Dengan kata lain:

𝑁
1
=
𝑝
×
𝑞

sedangkan:

𝑁
2
=
𝑞
×
𝑟

Karena kedua modulus memiliki faktor prima yang sama, kita dapat memperoleh q secara langsung menggunakan operasi GCD.

3. Landasan Teori
3.1. Keamanan Standar RSA dan Masalah Faktorisasi

Keamanan skema enkripsi RSA bertumpu pada kesulitan komputasi dari masalah faktorisasi bilangan bulat (Integer Factorization Problem).

Diberikan modulus komposit:

𝑁
=
𝑝
⋅
𝑞

di mana p dan q adalah bilangan prima besar yang dirahasiakan, penyerang tidak dapat dengan mudah menurunkan fungsi totient Euler:

𝜙
(
𝑁
)
=
(
𝑝
−
1
)
(
𝑞
−
1
)

Tanpa mengetahui $\phi(N)$, penyerang tidak dapat menghitung eksponen privat $d$, yang didefinisikan sebagai invers perkalian modular dari $e$:

𝑑
≡
𝑒
−
1
(
m
o
d
𝜙
(
𝑁
)
)

Untuk RSA dengan modulus 1024-bit, melakukan faktorisasi langsung bukanlah pendekatan yang praktis untuk tantangan beginner.

3.2. Kerentanan Common Prime Factor (Shared Factor Attack)

Ketika dua modulus RSA berbagi satu faktor prima yang sama:

𝑁
1
=
𝑝
⋅
𝑞

𝑁
2
=
𝑞
⋅
𝑟

dengan asumsi $\gcd(p,r)=1$, maka:

gcd
⁡
(
𝑁
1
,
𝑁
2
)
	
=
gcd
⁡
(
𝑝
𝑞
,
𝑞
𝑟
)


	
=
𝑞
⋅
gcd
⁡
(
𝑝
,
𝑟
)


	
=
𝑞

Dengan demikian, faktor prima q dapat diperoleh dengan sangat mudah:

𝑞
=
gcd
⁡
(
𝑁
1
,
𝑁
2
)

Hal inilah yang membuat sistem RSA pada tantangan ini dapat diserang tanpa perlu melakukan faktorisasi 1024-bit secara langsung.

3.3. Algoritma Euclidean

GCD dapat dihitung secara efisien menggunakan Algoritma Euclidean.

Algoritma tersebut memanfaatkan relasi:

gcd
⁡
(
𝐴
,
𝐵
)
=
gcd
⁡
(
𝐵
,
𝐴
 
mod
 
𝐵
)

Proses pembagian dilakukan secara berulang sampai sisa pembagian bernilai nol.

Untuk bilangan berukuran 1024-bit, perhitungan GCD sangat cepat dibandingkan dengan proses faktorisasi modulus RSA.

Dalam Python, operasi tersebut dapat dilakukan menggunakan:

import math

q = math.gcd(N1, N2)

4. Alur Rekonstruksi Kunci dan Eksploitasi

Setelah faktor bersama q diperoleh melalui GCD, plaintext dapat dipulihkan melalui beberapa langkah.

Langkah 1 — Mencari Faktor Bersama

Hitung:

𝑞
=
gcd
⁡
(
𝑁
1
,
𝑁
2
)

Karena q digunakan pada kedua modulus, hasil GCD adalah faktor prima yang sama.

Langkah 2 — Mendapatkan Faktor p

Setelah memperoleh q, kita dapat menghitung:

𝑝
=
𝑁
1
𝑞

Dengan demikian, faktorisasi N1 telah berhasil dilakukan:

𝑁
1
=
𝑝
×
𝑞

Langkah 3 — Menghitung Totient Euler

Setelah mengetahui p dan q, kita dapat menghitung:

𝜙
(
𝑁
1
)
=
(
𝑝
−
1
)
(
𝑞
−
1
)

Langkah 4 — Menghitung Private Exponent

Private exponent d merupakan invers modular dari e terhadap $\phi(N_1)$:

𝑑
≡
𝑒
−
1
(
m
o
d
𝜙
(
𝑁
1
)
)

Dalam Python, hal tersebut dapat dilakukan menggunakan:

d = pow(e, -1, phi1)

Langkah 5 — Dekripsi Ciphertext

Dengan private exponent d, ciphertext c1 dapat didekripsi:

𝑚
1
≡
𝑐
1
𝑑
(
m
o
d
𝑁
1
)

Sehingga diperoleh kembali plaintext dalam bentuk integer.

Langkah 6 — Konversi ke Byte

Integer hasil dekripsi kemudian dikonversi kembali menjadi bytes ASCII menggunakan long_to_bytes().

5. Skrip Solver

Skrip berikut membaca nilai numerik langsung dari output.txt menggunakan regular expression (regex), melakukan serangan GCD, kemudian mendekripsi ciphertext c1.

#!/usr/bin/env python3

import math
import re
from Crypto.Util.number import long_to_bytes


def solve():
    # 1. Parsing parameter dari berkas output
    with open("output.txt", "r") as f:
        data = f.read()

    n1_match = re.search(r"N1\s*=\s*(\d+)", data)
    n2_match = re.search(r"N2\s*=\s*(\d+)", data)
    c1_match = re.search(r"c1\s*=\s*(\d+)", data)

    if not (n1_match and n2_match and c1_match):
        raise ValueError(
            "Gagal mengekstrak parameter dari output.txt"
        )

    N1 = int(n1_match.group(1))
    N2 = int(n2_match.group(1))
    c1 = int(c1_match.group(1))

    e = 0x10001

    # 2. Hitung faktor persekutuan terbesar via GCD
    q = math.gcd(N1, N2)

    if q == 1:
        raise ValueError(
            "Modulus N1 dan N2 adalah coprime "
            "(relatif prima). Serangan gagal."
        )

    # 3. Hitung faktor p dan fungsi totient Euler
    p = N1 // q
    phi1 = (p - 1) * (q - 1)

    # 4. Hitung kunci privat d
    d = pow(e, -1, phi1)

    # 5. Dekripsi ciphertext menjadi plaintext integer
    flag_int = pow(c1, d, N1)

    # 6. Konversi ke representasi bytes ASCII
    flag_bytes = long_to_bytes(flag_int)

    print(
        f"[+] Flag berhasil didekripsi: "
        f"{flag_bytes.decode('utf-8')}"
    )


if __name__ == "__main__":
    solve()

6. Eksekusi dan Hasil

Jalankan solver pada terminal:

(ctf_env) nata@Nattt crypto_beginnersa
❯ python3 solve.py
[+] Flag berhasil didekripsi: NSS{n3v3r_3v3r_r3u53_4_pr1m3!}


Flag yang berhasil diperoleh adalah:

NSS{n3v3r_3v3r_r3u53_4_pr1m3!}

7. Kesimpulan

Kerentanan pada challenge ini bukan berasal dari kelemahan algoritma RSA itu sendiri, melainkan dari kesalahan implementasi dalam pembangkitan modulus.

Faktor prima q digunakan kembali pada dua modulus:

𝑁
1
=
𝑝
×
𝑞

𝑁
2
=
𝑞
×
𝑟

Akibatnya, attacker dapat memperoleh q hanya dengan menghitung:

𝑞
=
gcd
⁡
(
𝑁
1
,
𝑁
2
)

Setelah q diketahui, faktor p dapat diperoleh dari N1, sehingga private key RSA dapat dihitung dan c1 dapat didekripsi.

Inti Eksploitasi
N1 = p × q
N2 = q × r
     ↓
gcd(N1, N2)
     ↓
     q
     ↓
p = N1 / q
     ↓
φ(N1) = (p-1)(q-1)
     ↓
d = e⁻¹ mod φ(N1)
     ↓
m = c1ᵈ mod N1
     ↓
bytes → plaintext
     ↓
NSS{n3v3r_3v3r_r3u53_4_pr1m3!}


Pelajaran utama: Dalam RSA, faktor prima tidak boleh digunakan kembali pada modulus yang berbeda.

Never ever reuse a prime!

Flag
NSS{n3v3r_3v3r_r3u53_4_pr1m3!}
