# orbital-strike

**CTF:** SEKAI CTF 2026  
**Category:** Crypto  
**Flag:** `SEKAI{orbital_strike_like_miku_miku_beam!!!}`

## Ringkasan

`X` dipakai langsung sebagai key AES-256-ECB, tetapi tidak pernah dicetak. Nilai yang tersedia hanya 14 output dari LCG luar:

```text
moon_i = (a * moon_(i-1) + b) mod p
orbit_i = (A * orbit_(i-1) + moon_i) mod P
```

Modulusnya berbeda ukuran:

```text
P = prime 256 bit
p = prime 311 bit
```

Serangannya tidak menebak parameter LCG. Selisih output `orbit` dimasukkan ke lattice untuk mencari relasi linear pendek. Resultant dari relasi tersebut membocorkan `p`, lalu akar polinomial bersama membocorkan `a`. Setelah selisih state LCG dalam pulih, `P`, `A`, dan akhirnya `X` dapat dihitung.

## 1. Selisih output

Misalkan output yang diketahui adalah `y_1, ..., y_14` dan:

```text
d_i = y_(i+1) - y_i
```

Dibuat lattice dengan 11 baris:

```text
[ 2^512*d_i | 2^512*d_(i+1) | 2^512*d_(i+2) | e_i ]
```

`e_i` adalah basis identitas berdimensi 11. Setelah LLL, beberapa baris mempunyai tiga koordinat awal bernilai nol. Bagian sisanya memberi koefisien pendek `l_0, ..., l_10` yang memenuhi:

```text
sum(l_i * d_i)     = 0
sum(l_i * d_(i+1)) = 0
sum(l_i * d_(i+2)) = 0
```

Pada data challenge, enam relasi terpendek adalah relasi asli dari LCG dalam.

## 2. Memulihkan `p` dan `a`

Untuk state bulan `m_i`, definisikan:

```text
delta_i = m_(i+1) - m_i
```

Karena state bulan berasal dari LCG:

```text
delta_(i+1) = a * delta_i mod p
```

Jika relasi lattice ditulis sebagai polinomial:

```text
L(x) = l_0 + l_1*x + ... + l_10*x^10
```

maka relasi yang benar memenuhi:

```text
L(a) = 0 mod p
```

Dua polinomial yang memiliki akar bersama modulo `p` mempunyai resultant yang habis dibagi `p`. GCD beberapa pairwise resultant menghasilkan:

```text
p = 2119096224402128550561050349492003417568127991233001696898308326778843265234138716328133390083
```

Setelah semua polinomial direduksi modulo `p`, polynomial GCD-nya linear:

```text
x - 473937279736743736290187607660206983132197528611913456183244937782250543933330432430667382472
```

Jadi:

```text
a = 473937279736743736290187607660206983132197528611913456183244937782250543933330432430667382472
```

## 3. Memulihkan selisih state bulan

Enam relasi yang valid ditempatkan pada dua offset:

```text
[l_0 ... l_10 0]
[0 l_0 ... l_10]
```

Matriks blok ini mempunyai integer kernel berdimensi tiga. Basis kernel direduksi dengan LLL, lalu koefisien kombinasinya dipaksa memenuhi:

```text
z_(i+1) = a * z_i mod p
```

Constraint modular tersebut menyisakan satu dimensi. LLL kedua menghasilkan vektor bertanda:

```text
z = (delta_2, delta_3, ..., delta_13)
```

Setiap elemennya berada pada interval `(-p, p)` dan merepresentasikan selisih state bulan sebagai integer biasa, bukan hanya residue modulo `p`.

## 4. Memulihkan `P` dan `A`

Dari LCG luar:

```text
m_i = y_i - A*y_(i-1) mod P
```

Kurangi dua persamaan berurutan:

```text
delta_i = d_i - A*d_(i-1) mod P
```

atau:

```text
d_i - delta_i = A*d_(i-1) mod P
```

Eliminasi `A` dari dua indeks `i` dan `j`:

```text
C_(i,j) = (d_i - delta_i)*d_(j-1)
          - (d_j - delta_j)*d_(i-1)
```

Semua `C_(i,j)` habis dibagi modulus luar `P`. GCD seluruh cross-product memberi:

```text
P = 103573749400542433237883834812514303610954103088001803652849939821268982618643
```

Multiplier luar dihitung dari salah satu persamaan modular:

```text
A = (d_i - delta_i) * inverse(d_(i-1), P) mod P
```

Hasilnya:

```text
A = 33784146643021166140318155504781147780203373158604074880336518331154690684019
```

## 5. Memulihkan `X`

State bulan kedua diketahui modulo `P`:

```text
m_2 = y_2 - A*y_1 mod P
```

Selisih sebelumnya diperoleh dengan membalik recurrence:

```text
delta_1 = inverse(a, p) * delta_2 mod p
```

Ada dua representasi bertanda, yaitu `r` atau `r-p`. Hanya satu yang memungkinkan seluruh state `m_1, ..., m_14` tetap berada pada interval `[0, p)`.

Setelah `m_1 mod P` diketahui:

```text
X = (y_1 - m_1) * inverse(A, P) mod P
```

Nilainya:

```text
X = 84574168440666239348773411022631922002703257743984610464324202424526141097033
```

## 6. Dekripsi

Ciphertext dienkripsi memakai AES-256-ECB dan PKCS#7 padding:

```python
plaintext = unpad(
    AES.new(X.to_bytes(32, "big"), AES.MODE_ECB).decrypt(bytes.fromhex(star)),
    16,
)
```

Hasil dekripsi:

```text
SEKAI{orbital_strike_like_miku_miku_beam!!!}
```

Solver juga meregenerasi seluruh 14 output `orbit` sebelum menerima flag, sehingga parameter hasil recovery tidak hanya lolos padding AES.

## Menjalankan solver

```bash
source /home/nata/ctf_env/bin/activate
pip install pycryptodome sympy fpylll cysignals
python3 solve.py
```

Output:

```text
[+] p = 2119096224402128550561050349492003417568127991233001696898308326778843265234138716328133390083
[+] a = 473937279736743736290187607660206983132197528611913456183244937782250543933330432430667382472
[+] P = 103573749400542433237883834812514303610954103088001803652849939821268982618643
[+] A = 33784146643021166140318155504781147780203373158604074880336518331154690684019
[+] X = 84574168440666239348773411022631922002703257743984610464324202424526141097033
[+] full orbit regeneration: valid
<FLAG>SEKAI{orbital_strike_like_miku_miku_beam!!!}</FLAG>
```
