# r3ticket — R3CTF 2026

**Category:** Crypto  
**Difficulty:** Hard  
**Flag:** `r3ctf{H0Pe-YoU-IOvE_THI5_t1cK3T-sERIE5-xd328f1}`

## Ringkasan

Server membuat 128 bilangan acak 16-bit, lalu pada setiap ronde memilih eksponen acak 24-bit `x` dan menghitung

\[
S_x = \sum_{i=0}^{127} n_i^x.
\]

Yang dikirim ke pemain hanya 64 digit pertama dari `S_x`. Eksponen harus dijawab dalam 3 detik dan proses ini diulang 16 kali.

Untuk hampir semua nilai `x`, suku dengan basis terbesar mendominasi penjumlahan. Prefix desimal tersebut akhirnya menjadi fingerprint mantissa dari `M^x`, dengan `M = max(nums)`. Nilai `x` bisa dipulihkan dari persamaan logaritma modular memakai CVP lattice 2 dimensi.

## Source Audit

Bagian utama challenge:

```python
nums = [gmpy2.mpz(secrets.randbits(16)) for _ in range(128)]

for round in range(16):
    x = secrets.randbits(24)
    h = sum([num**x for num in nums])
    print("challenge =", str(h)[:64])

    check = int(timed_input("x = ", 3))
    if check != x:
        exit()
```

Ada oracle tambahan bernama `get_num()` yang menyerupai interpolasi Lagrange, tetapi pembagian dilakukan dengan `//` pada setiap faktor:

```python
part *= (index - j) // (i - j)
```

Saat mengirim index `0`, fungsi hanya mengembalikan `nums[0]`. Semua term dengan `i > 0` memiliki faktor

```text
(0 - 0) // (i - 0) = 0
```

sehingga hilang dari hasil. Leak satu angka ini tidak dibutuhkan untuk serangan utama; solver mengirim `0` hanya untuk melewati tahap tersebut.

## Dominasi Nilai Maksimum

Misalkan:

- `M` adalah nilai terbesar dalam `nums`;
- `t` adalah berapa kali `M` muncul;
- nilai lainnya ditulis sebagai `a_i < M`.

Maka:

\[
S_x = tM^x + \sum_i a_i^x
    = tM^x\left(1 + \frac{1}{t}\sum_i\left(\frac{a_i}{M}\right)^x\right).
\]

Definisikan error relatif:

\[
\delta = \frac{1}{t}\sum_i\left(\frac{a_i}{M}\right)^x.
\]

Karena `x` adalah bilangan 24-bit, biasanya nilainya jutaan. Bahkan rasio basis yang sangat dekat dengan `M` akan dipangkatkan dengan eksponen besar, sehingga `delta` menjadi sangat kecil. Akibatnya:

\[
S_x \approx tM^x.
\]

Server memberi 64 digit pertama. Jika prefix itu dianggap sebagai integer `p`, mantissa desimalnya adalah

\[
m = \frac{p}{10^{63}}.
\]

Dengan demikian:

\[
\beta = \log_{10}(m)
\]

mendekati bagian pecahan dari `log10(S_x)`:

\[
\beta \approx \operatorname{frac}(x\log_{10}M + \log_{10}t).
\]

Jadi untuk kandidat `M` dan multiplicity `t`, targetnya adalah mencari `x < 2^{24}` yang memenuhi:

\[
x\log_{10}M \equiv \beta - \log_{10}t \pmod 1.
\]

## Ruang Pencarian Maksimum

Setiap `nums[i]` berada pada rentang `0..65535`. Nilai maksimum dari 128 sampel uniform hampir pasti cukup besar.

Solver hanya mencoba:

```text
M = 50000 .. 65535
```

Probabilitas seluruh 128 angka berada di bawah 50000 adalah:

\[
\left(\frac{50000}{65536}\right)^{128} \approx 9.09 \times 10^{-16}.
\]

Multiplicity maksimum normalnya `1`. Solver juga mencoba `t = 2` dan `t = 3` untuk menangani duplikasi nilai maksimum.

## Mengubah Persamaan Menjadi Lattice

Gunakan fixed-point precision:

```text
C = 2^256
A = round(C * log10(M))
T = round(C * frac(beta - log10(t)))
```

Persamaan modular berubah menjadi pencarian integer `k` dan `x`:

\[
Ax + Ck \approx T,
\qquad 0 \le x < 2^{24}.
\]

Lattice 2 dimensi dibentuk dari basis:

\[
b_1 = (C, 0),
\qquad
b_2 = (A, W),
\]

menggunakan:

```text
W = 2^128
```

Setiap titik lattice berbentuk:

\[
k b_1 + x b_2 = (Ck + Ax, Wx).
\]

Target CVP-nya adalah:

\[
(T, 0).
\]

Koordinat pertama mengukur error persamaan modular. Koordinat kedua memberi penalti pada besarnya `x` sekaligus memungkinkan eksponen dipulihkan lewat:

\[
x = \frac{y}{W}.
\]

Karena lattice hanya 2 dimensi, basis dapat direduksi dengan Gauss reduction memakai integer arithmetic. Setelah reduksi, solver menghitung lattice point terdekat dan memeriksa beberapa koefisien tetangga.

## Validasi Kandidat

Solver tidak langsung mengirim kandidat pertama. Beberapa pengecekan dipakai:

1. `x` wajib berada di bawah `2^24`.
2. Error fixed-point harus lebih kecil dari batas ekuivalen sekitar 60 bit mantissa yang cocok.
3. Kandidat dikelompokkan berdasarkan `x`; beberapa nilai `M` dapat menghasilkan eksponen yang sama akibat pembulatan.
4. Dua kandidat terbaik tidak boleh terlalu berdekatan. Jika ambigu, koneksi dibuang dan solver membuka sesi baru.
5. Untuk nilai `x` sangat kecil yang menghasilkan total kurang dari 64 digit, dipakai classifier berdasarkan estimasi:

\[
E[S_x] \approx \frac{128 \cdot 65535^x}{x+1}.
\]

Retry lebih aman daripada mengirim tebakan karena satu jawaban salah langsung mengakhiri sesi.

## Solver

Dependency:

```bash
source /home/nata/ctf_env/bin/activate
pip install mpmath
```

Jalankan:

```bash
python3 solve.py HOST PORT
```

Solver melakukan langkah berikut:

1. Precompute reduced basis untuk seluruh kandidat `M`.
2. Mengirim index `0` pada oracle awal.
3. Membaca prefix 64 digit setiap ronde.
4. Menyelesaikan CVP untuk memperoleh `x`.
5. Menjawab 16 ronde dalam batas 3 detik.
6. Retry otomatis bila kandidat tidak cukup kuat.

Contoh output akhir:

```text
[+] round 16/16: x=... (0.11s, M≈..., multiplicity=1, log-error≈...)
You won! Here is your real ticket: r3ctf{H0Pe-YoU-IOvE_THI5_t1cK3T-sERIE5-xd328f1}

<FLAG>r3ctf{H0Pe-YoU-IOvE_THI5_t1cK3T-sERIE5-xd328f1}</FLAG>
```

## Flag

```text
r3ctf{H0Pe-YoU-IOvE_THI5_t1cK3T-sERIE5-xd328f1}
```
