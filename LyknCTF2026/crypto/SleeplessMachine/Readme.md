# Sleepless Machine

**CTF:** LYKNCTF 2026  
**Category:** Crypto  
**Difficulty:** Medium  
**Flag:** `LYKNCTF{888913966304452fb05a9b00861c76c0}`

## Deskripsi

> An old machine keeps running day and night in a forgotten bunker, broadcasting the same unchanging sequence. No one remembers what it was built for.

Server memberikan public key bergaya NTRU, empat nilai leakage, dan flag yang dienkripsi memakai AES-GCM. Kelihatannya private polynomial `f` dan `g` perlu direkonstruksi, tetapi jalur tersebut tidak diperlukan.

## Analisis

Parameter utama dari generator:

```python
N = 127
Q = 4093
Q_PRIME = 1000003
DENSITY = 0.36
```

Secret yang dipakai untuk membuat key adalah:

```python
s_alg = weighted_trace(f, g, N, Q_PRIME)
```

Nilai itu kemudian langsung dimasukkan ke HKDF:

```python
ikm = (
    s_alg.to_bytes(4, "big")
    + N.to_bytes(2, "big")
    + q.to_bytes(2, "big")
    + q_prime.to_bytes(4, "big")
)
```

Masalah utamanya ada pada domain `s_alg`:

```python
s_alg = weighted_trace(...) % 1000003
```

Artinya key AES hanya memiliki maksimal `1,000,003` kemungkinan. Public key NTRU tidak perlu diserang; cukup brute-force seluruh kandidat `s_alg`, turunkan key HKDF, lalu cek AES-GCM.

## Memanfaatkan Leakage

Polynomial dibuat oleh `constrained_ternary()`, sehingga setiap koefisien hanya bernilai `-1`, `0`, atau `1`.

Leakage yang diberikan:

```text
f_even_sum
f_odd_sum
g_even_sum
g_odd_sum
```

Generator menaruh koefisien awal sesuai target sum, kemudian menambahkan pasangan `(+1, -1)` pada indeks genap dan ganjil. Karena algoritma pembentukannya diketahui, jumlah koefisien positif dan negatif dapat dihitung tepat dari leakage.

Untuk polynomial dengan target genap `te`, target ganjil `to`, dan `N = 127`:

```python
used = abs(te) + abs(to)
target_total = int(0.36 * N)
pad_needed = max(target_total - used, 0)
pairs_per_parity = pad_needed // 4 + 1

positive = max(te, 0) + max(to, 0) + 2 * pairs_per_parity
negative = max(-te, 0) + max(-to, 0) + 2 * pairs_per_parity
```

Dari jumlah tanda pada `f` dan `g`, kita bisa menghitung banyaknya produk positif dan negatif:

```python
positive_products = fp * gp + fn * gn
negative_products = fp * gn + fn * gp
```

Pada cyclic convolution, setiap pasangan koefisien menyumbang tepat satu kali ke `weighted_trace`, dengan bobot antara `1` sampai `N`.

Batas integer untuk weighted trace sebelum modulo menjadi:

```python
lo = positive_products - N * negative_products
hi = N * positive_products - negative_products
```

Interval `[lo, hi]` dipetakan ke residue modulo `q_prime`. Pada instance normal, kandidat turun dari sekitar satu juta menjadi kurang lebih 280–300 ribu.

## Optimasi Brute Force

Setiap kandidat diuji dengan alur:

1. Turunkan key melalui HKDF-SHA256.
2. Dekripsi beberapa byte awal ciphertext.
3. Buang kandidat jika plaintext tidak diawali `LYKN{` atau `LYKNCTF{`.
4. Jalankan `decrypt_and_verify()` hanya pada kandidat yang lolos prefix.
5. Bagi interval ke beberapa worker menggunakan `multiprocessing`.

Prefix check menghindari kalkulasi verifikasi tag GCM pada hampir semua kandidat.

## Menjalankan Solver

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py HOST PORT -j 16
```

Solver juga menerima instance dari file:

```bash
python3 solve.py instance.json -j 16
```

Atau dari stdin:

```bash
cat instance.json | python3 solve.py -j 16
```

## Output

```text
[*] weighted integer bound: ...
[*] candidate residues: ... / 1000003
[*] workers: 16
[+] s_alg = ...
<FLAG>LYKNCTF{888913966304452fb05a9b00861c76c0}</FLAG>
```

## Flag

```text
LYKNCTF{888913966304452fb05a9b00861c76c0}
```
