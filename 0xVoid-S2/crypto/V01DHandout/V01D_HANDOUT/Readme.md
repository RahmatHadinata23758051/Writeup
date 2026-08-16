# V01D Handout

## Ringkasan

Challenge ini punya tiga lapis seal. Output `transmission.txt` berisi semua data publik, sedangkan `voidlock.py` menjelaskan cara penyegelan.

Alurnya:

1. Seal I memakai RSA `e = 5` dengan dua plaintext yang berjarak tetap `delta`.
2. Hasil Seal I berisi capsule. Enam belas byte terakhir capsule adalah `PRIME_P` untuk LCG Seal II.
3. Seal II membocorkan 32 bit atas dari 8 state LCG. State asli direcover memakai lattice karena 96 bit bawah tiap state hilang.
4. Seed hasil Seal II dipakai untuk derive taps LFSR Seal III.
5. Seal III memakai tiga LFSR dengan combiner nonlinear. Known plaintext header cukup untuk correlation attack pada register 19-bit dan 23-bit, lalu register 21-bit diselesaikan sebagai sistem linear GF(2).
6. Keystream dibuat ulang dan ciphertext didekripsi.

Flag:

```
0xV0ID{W0W_Y0U_4C7U4LLY_F0UND_M3!!}
```

## File Challenge

File yang dipakai:

```
transmission.txt
voidlock.py
```

`transmission.txt` menyimpan nilai publik untuk tiga seal:

```
SEAL I   : n, e, delta, c1, c2
SEAL II  : a, b, leak
SEAL III : ct
```

`voidlock.py` memperlihatkan algoritma penyegelan, termasuk format capsule, LCG, derive taps, LFSR, header, dan footer plaintext.

## Analisis Awal

Dari `voidlock.py`, Seal I membuat:

```python
m1 = int.from_bytes(capsule, "big")
m2 = m1 + DELTA
c1 = pow(m1, 5, n)
c2 = pow(m2, 5, n)
```

Ini pola Franklin-Reiter related-message attack. Dua pesan RSA punya hubungan linear:

```
m2 = m1 + delta
```

Karena exponent kecil dan modulus sama, `m1` bisa diambil dari gcd polynomial:

```
gcd(x^5 - c1, (x + delta)^5 - c2) mod n
```

GCD tersebut menghasilkan polynomial linear `x - m1`.

## Analisis Static

Capsule dari Seal I punya struktur:

```python
CAPSULE_MAGIC = b"0xV0ID//SEAL-I//"
CAPSULE_NOISE = 208
capsule = CAPSULE_MAGIC + NOISE + PRIME_P.to_bytes(16, "big")
```

Setelah `m1` direcover, capsule valid karena diawali magic:

```
0xV0ID//SEAL-I//
```

Enam belas byte terakhir capsule menghasilkan prime LCG:

```
PRIME_P = 0xd8e6960ff5ed04c81cfbe022e774e809
```

Seal II memakai LCG:

```python
x = x0 % p
for _ in range(8):
    leak.append(x >> 96)
    x = (a * x + b) % p
```

Leak hanya 32 bit atas. Sisanya 96 bit bawah tidak diketahui.

## Analisis Dynamic

Tidak perlu menjalankan binary atau service. Semua komponen cryptographic diberikan di `voidlock.py`, jadi solve cukup direproduksi secara lokal.

Validasi dilakukan lewat struktur plaintext Seal III:

```python
HEADER = b"[0xV0ID // SECURE TRANSMISSION]\n...PAYLOAD: "
FOOTER = b"\n[EOT]\n"
```

Plaintext hasil decrypt harus diawali `HEADER` dan diakhiri `FOOTER`.

## Algoritma Validasi atau Encoding

### Seal I

Recover `m1` dengan Franklin-Reiter:

```
f(x) = x^5 - c1
g(x) = (x + delta)^5 - c2
```

GCD polynomial modulo `n` menghasilkan root `m1`.

### Seal II

Misal:

```
x_i = leak_i * 2^96 + u_i
0 <= u_i < 2^96
```

LCG bisa ditulis sebagai:

```
x_i = A_i * x_0 + C_i mod p
```

Karena `x_0 = leak_0 * 2^96 + u_0`, didapat persamaan:

```
A_i * u_0 - u_i = leak_i*2^96 - A_i*leak_0*2^96 - C_i mod p
```

Semua `u_i` kecil, jadi ini diselesaikan dengan lattice small-error. Hasil seed akhir LCG:

```
seed = 0x258824d7b8c187a7bfe3bd77571dbac5
```

### Seal III

Seed dipakai untuk derive taps:

```
ALPHA taps = 0x6df19
BETA  taps = 0xb7d01
GAMMA taps = 0xc112d
```

Combiner Seal III:

```
z = (x1 & x2) ^ (x2 & x3) ^ x3
```

Fungsi ini punya korelasi kuat dengan `x1` dan `x3`. Header plaintext sudah diketahui, jadi keystream awal bisa dihitung:

```
known_keystream = ct_prefix XOR HEADER
```

Register ALPHA 19-bit dan GAMMA 23-bit dicari dengan correlation attack terhadap known keystream. State yang ditemukan:

```
ALPHA = 0x36229
GAMMA = 0x2a842f
```

Setelah `x1` dan `x3` diketahui, combiner menjadi:

```
z = x2 * (x1 XOR x3) XOR x3
```

Saat `x1 XOR x3 = 1`, bit output BETA langsung diketahui:

```
x2 = z XOR x3
```

Bit BETA yang terkumpul cukup untuk menyelesaikan state BETA sebagai sistem linear GF(2):

```
BETA = 0x580cb
```

Keystream penuh dibuat ulang, lalu ciphertext didekripsi.

## Penyusunan Solve Script

`solve_v01d_handout.py` melakukan semua langkah otomatis:

1. Parse `transmission.txt` jika ada.
2. Recover capsule Seal I.
3. Ambil `PRIME_P` dari 16 byte terakhir capsule.
4. Recover seed Seal II memakai lattice LLL kecil.
5. Derive taps LFSR dari seed.
6. Recover state ALPHA dan GAMMA dengan correlation attack.
7. Recover state BETA dengan eliminasi linear GF(2).
8. Decrypt `ct` dan extract payload di antara `HEADER` dan `FOOTER`.

Script sengaja tidak butuh Sage. Untuk langkah correlation cepat, script memakai `numpy`.

## Cara Menjalankan

Dari folder challenge:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve_v01d_handout.py
```

Output penting:

```
[+] Seal I: Franklin-Reiter RSA
    PRIME_P = 0xd8e6960ff5ed04c81cfbe022e774e809
[+] Seal II: truncated LCG lattice
    seed    = 0x258824d7b8c187a7bfe3bd77571dbac5
[+] Seal III: LFSR correlation + GF(2) solve
    taps    = 0x6df19, 0xb7d01, 0xc112d
    states  = 0x36229, 0x580cb, 0x2a842f
[+] flag = 0xV0ID{W0W_Y0U_4C7U4LLY_F0UND_M3!!}
```

Kalau `numpy` belum ada:

```bash
pip install numpy
```

## Flag

```
0xV0ID{W0W_Y0U_4C7U4LLY_F0UND_M3!!}
```
