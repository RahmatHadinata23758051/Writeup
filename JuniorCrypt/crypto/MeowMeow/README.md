# MeowMeow?

## Informasi Challenge

- **Kategori:** Crypto
- **Judul:** MeowMeow?
- **Flag format:** `grodno{}`

## File

```text
meow_rsa.meow
ciphertext.txt
```

`ciphertext.txt` berisi modulus RSA, public exponent, ciphertext, dan rentang waktu tujuh hari:

```text
window_utc = 2026-06-20 00:00:00..2026-06-26 23:59:59
n = ...
e = 65537
c = ...
```

File `.meow` terlihat seperti teks berulang, tetapi jumlah kata `Meow` pada setiap baris membawa data.

---

## Decode File Meow

Pola awal file:

```text
Meow Meow;
Meow Meow Meow ...;
Meow Meow Meow Meow Meow Meow Meow Meow Meow Meow;
```

Jumlah `Meow` per baris menghasilkan pola:

```text
2, 115, 10,
2, 101, 10,
2, 101, 10,
...
```

Setiap tiga baris berbentuk:

```text
2, <ASCII byte>, 10
```

Nilai tengah dapat langsung diubah menjadi karakter ASCII.

Hasil decode:

```text
seed = unix_time(2026-06-20 00:00:00 UTC .. 2026-06-26 23:59:59 UTC)
splitmix64(x):
  x = (x + 0x9E3779B97F4A7C15) mod 2^64
  z = x
  z = ((z xor (z >> 30)) * 0xBF58476D1CE4E5B9) mod 2^64
  z = ((z xor (z >> 27)) * 0x94D049BB133111EB) mod 2^64
  z = z xor (z >> 31)
state = seed xor 0x6A09E667F3BCC909
skip = 0x80 + ((seed >> 12) & 0xff) + (seed & 0x1f)
advance state skip times
p_words[i] = splitmix64(state) xor rol64(seed, i + 3)
q_words[i] = bswap64(splitmix64(state) xor 0xA5A5A5A5A5A5A5A5 xor p_words[i]) xor rol64(seed, 11 + i)
p = next_prime(pack6(p_words) | (1 << 383) | 1)
q = next_prime(pack6(q_words) | (1 << 383) | 1)
read ciphertext.txt
```

Jadi kelemahannya bukan RSA secara langsung. Kedua prime dibangkitkan dari Unix timestamp yang hanya berada dalam window tujuh hari.

Total kandidat:

```text
7 × 24 × 60 × 60 = 604800 seed
```

Jumlah ini cukup kecil untuk brute force.

---

## Rekonstruksi Generator

State awal:

```python
state = seed ^ 0x6A09E667F3BCC909
```

Jumlah advance:

```python
skip = 0x80 + ((seed >> 12) & 0xff) + (seed & 0x1f)
```

Enam word untuk `p` dibuat lebih dahulu:

```python
for i in range(6):
    state, value = splitmix64_next(state)
    p_words[i] = value ^ rol64(seed, i + 3)
```

Setelah itu baru enam word untuk `q`:

```python
for i in range(6):
    state, value = splitmix64_next(state)
    q_words[i] = (
        bswap64(value ^ CONST ^ p_words[i])
        ^ rol64(seed, 11 + i)
    )
```

`pack6` menggunakan urutan big-endian:

```python
value = 0
for word in words:
    value = (value << 64) | word
```

Prime final:

```python
p = nextprime(p_raw)
q = nextprime(q_raw)
```

---

## Optimasi Brute Force

Menjalankan `nextprime()` untuk seluruh 604800 seed bakal boros.

Untuk seed benar:

```text
p = p_raw + delta_p
q = q_raw + delta_q
```

`delta_p` dan `delta_q` biasanya kecil karena hanya selisih menuju prime berikutnya.

Akibatnya:

```text
n - p_raw*q_raw
```

juga jauh lebih kecil daripada modulus 768-bit.

Seed salah menghasilkan produk acak sehingga selisihnya hampir selalu sebesar modulus.

Filter yang dipakai:

```python
delta = abs(n - p_raw * q_raw)

if delta.bit_length() <= 430:
    p = nextprime(p_raw)
    q = nextprime(q_raw)

    if p * q == n:
        # seed ditemukan
```

Dengan filter ini, `nextprime()` hanya dijalankan pada kandidat yang benar-benar dekat.

---

## Seed dan Faktor RSA

Seed yang ditemukan:

```text
1782240431
```

Timestamp UTC:

```text
2026-06-23 18:47:11 UTC
```

Selisih menuju prime berikutnya:

```text
p - p_raw = 60
q - q_raw = 176
```

Verifikasi:

```text
p × q = n
```

Setelah modulus berhasil difaktorkan:

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
```

---

## Solver

Simpan sebagai `solve.py`, lalu jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Dependency:

```bash
pip install sympy
```

Output akhir:

```text
[+] Seed      : 1782240431
[+] Timestamp : 2026-06-23T18:47:11+00:00
[+] Plaintext : grodno{meowMeoWmEOwmeeoowMEOWWW}
[+] FLAG      : grodno{meowMeoWmEOwmeeoowMEOWWW}
```

## Flag

```text
grodno{meowMeoWmEOwmeeoowMEOWWW}
```
