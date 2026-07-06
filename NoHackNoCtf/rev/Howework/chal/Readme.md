# Homework — Reverse Engineering

**CTF:** No Hack No CTF 2026  
**Category:** Reverse  
**Flag:** `NHNC{y0u_c4nt_di4g0n4l1z3_y0ur_w4y_0ut_0f_h0m3w0rk_e8a16ce2870f47f58173b6a715c2c2d3}`

## Ringkasan

Binary menyediakan kalkulator matriks dengan operasi custom bernama `blend`. Implementasi operasi ini memakai `shift` sebagai indeks elemen `Real` berukuran 128 byte, tetapi tidak memastikan indeks tersebut masih berada di dalam matriks 1×1 milik user.

Debug output bahkan membocorkan bahwa `Y[0]` berjarak tiga slot dari elemen rahasia `A[0][1]`. Input berikut menulis `1e80` ke elemen tersebut:

```text
X = [[0]]
Y = [[1e80]]
op = blend 3
```

Overwrite itu membuat matriks rahasia lolos pemeriksaan internal. Program kemudian membocorkan `n`, `a+d`, `bc`, dan 32 pasangan ciphertext. Plaintext dibalik memakai bentuk Cayley–Hamilton untuk matriks 2×2, tanpa perlu diagonalization.

## Reconnaissance

Arsip berisi binary, Dockerfile, compose file, dan flag dummy untuk pengujian lokal.

```bash
file chall
sha256sum chall
```

Output:

```text
chall: ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped
SHA256: d2b1a5d21e8398a1a88ce3f6e50dfdb05057181af5d1f5613e6143888f044aca
```

Binary berukuran besar karena static linking dan seluruh simbol sudah dihapus. String yang paling relevan:

```text
X size:
Y size:
X data:
Y data:
op:
blend
a_plus_d =
bc =
C =
T:
flag.txt
```

Saat dijalankan, program mencetak alamat row milik `X`, `Y`, dan matriks internal `A`:

```text
[debug] sizeof(Real) = 128
[debug] Y row 0 = 0x...
[debug] A[0][1] = 0x...
[debug] from Y row 0 to A[0][1]:
        byte_delta     = 384
        slot_delta     = 3
        slot_remainder = 0
        use shift      = 3
```

Ukuran satu objek `Real` adalah 128 byte. Selisih 384 byte berarti:

```text
384 / 128 = 3 elemen
```

Debug message sudah memberi indeks OOB yang dibutuhkan: `shift = 3`.

## Membalik operasi `blend`

Fungsi `blend` hanya menerima `X` dan `Y` berukuran 1×1. Dari disassembly terlihat pointer tujuan dihitung dengan pola:

```c
Real *dst = &Y[0][0] + shift;
```

Tidak ada validasi bahwa `shift` masih berada pada row `Y`. Validasi yang ada memakai batas lain yang tetap mengizinkan nilai 3.

Perilaku aritmetik dipetakan dengan beberapa input kecil:

```text
X=0, Y=3, blend 0 -> 3
X=1, Y=3, blend 0 -> 6
X=2, Y=3, blend 0 -> 9
```

Jadi nilai yang ditulis adalah:

```text
Y[shift] = (X[0] + 1) * Y[0]
```

Dengan:

```text
X[0] = 0
Y[0] = 1e80
shift = 3
```

hasilnya:

```text
Y[3] = 1e80
```

Karena layout heap menempatkan `A[0][1]` tepat pada `Y[3]`, operasi tersebut setara dengan:

```text
A[0][1] = 1e80
```

`NaN` dan infinity ditolak parser, jadi nilai finite yang sangat besar dipakai sebagai gantinya.

## Melewati verifier matriks

Tuliskan matriks rahasia setelah overwrite sebagai:

```text
A = [ a  b ]
    [ c  d ]
```

Dengan:

```text
b = 1e80
```

Program memeriksa hubungan antara diagonal dan hasil kali elemen off-diagonal. Gunakan notasi:

```text
t     = (a + d) / 2
delta = (a - d) / 2
```

Overwrite pada `b` membuat `|bc|` sangat besar, sedangkan `delta²` tetap berada di kisaran nilai asli matriks. Akibatnya syarat yang meminta kontribusi diagonal jauh lebih kecil daripada `|bc|` terpenuhi.

Setelah lolos, service mencetak:

```text
n = ...
a_plus_d = ...
bc = ...
C = [(x0,y0), (x1,y1), ...]
T:
```

Ada 32 pasangan di `C`, satu pasangan untuk setiap byte target `T`.

## Membalik perpangkatan matriks

Diagonalization bukan pilihan yang nyaman karena elemen matriks sangat besar dan `a-d` tidak dibocorkan. Matriks 2×2 bisa ditangani langsung dengan Cayley–Hamilton.

Definisikan:

```text
A = tI + D

D = [ delta   b ]
    [   c   -delta ]
```

Kuadrat `D` menjadi matriks skalar:

```text
D² = (delta² + bc) I
```

Misalkan:

```text
k = delta² + bc
```

Maka setiap pangkat `A` selalu dapat ditulis sebagai:

```text
A^n = pI + qD
```

`p` dan `q` dihitung sebagai koefisien dari:

```text
(t + u)^n = p + qu, dengan u² = k
```

Perkalian pasangan koefisien dilakukan memakai aturan:

```text
(p1, q1) * (p2, q2)
  = (p1*p2 + q1*q2*k,
     p1*q2 + q1*p2)
```

Karena itu binary exponentiation dapat menghitung `p` dan `q` dalam `O(log n)` tanpa membentuk bilangan simbolik atau eigenvector.

Verifier memaksa `delta²` sangat kecil dibanding `|bc|`. Dengan `b=1e80`, aproksimasi berikut memiliki error jauh di bawah presisi angka yang dicetak service:

```text
k ≈ bc
```

Pada output remote, maksimum error pembulatan plaintext hanya sekitar `2.0e-43`.

## Rumus dekripsi

Dari bentuk sebelumnya:

```text
A^n = [ p + q*delta      q*b     ]
      [    q*c        p - q*delta ]
```

Determinan matriks pangkat tersebut adalah:

```text
det_n = p² - q²k
```

Setiap karakter plaintext `m` dienkripsi sebagai vektor:

```text
C_i = A^n * [m_i, 0]^T
```

Jika pasangan ciphertext adalah `(x_i, y_i)`, komponen pertama hasil invers memberikan:

```text
m_i = ((p - q*delta)*x_i - q*b*y_i) / det_n
```

atau:

```text
m_i = (p*x_i - q*b*y_i - q*delta*x_i) / det_n
```

Masalah yang tersisa hanya `delta`, karena service membocorkan `a+d` tetapi tidak `a-d`.

## Recovery `delta` dari alfabet printable

Target terdiri dari 32 karakter printable ASCII pada rentang 33 sampai 126. Karakter pertama cukup dipakai sebagai anchor.

Untuk setiap kandidat `m_0` pada rentang tersebut, susun ulang rumus dekripsi:

```text
delta = (p*x_0 - q*b*y_0 - m_0*det_n) / (q*x_0)
```

Setelah memperoleh kandidat `delta`, seluruh 32 karakter dihitung. Kandidat diberi skor berdasarkan:

1. semua hasil berada pada rentang printable;
2. jarak setiap hasil ke integer terdekat;
3. maksimum error pembulatan.

Hanya satu kandidat menghasilkan 32 karakter printable dengan error sekitar `10^-43`. Kandidat salah biasanya menghasilkan karakter di luar rentang atau pecahan dengan error mendekati `0.5`.

Plaintext remote yang berhasil dipulihkan:

```text
CiS2\94NY!$Y2dm=l{/<r]9WilMe^73G
```

Nilai itu dikirim ke prompt `T:` pada koneksi yang sama.

## Solver

Dependency:

```bash
pip install mpmath
```

Pengujian lokal:

```bash
python3 solve.py --local ./chall
```

Remote:

```bash
python3 solve.py 160.30.99.158 30027
```

Output remote:

```text
[*] connecting to 160.30.99.158:30027
[+] recovered T = CiS2\94NY!$Y2dm=l{/<r]9WilMe^73G
[+] max rounding error = 2.0207e-43
[+] recovered delta = 2073531542178784997.74286
<FLAG>NHNC{y0u_c4nt_di4g0n4l1z3_y0ur_w4y_0ut_0f_h0m3w0rk_e8a16ce2870f47f58173b6a715c2c2d3}</FLAG>
```

## Flag

```text
NHNC{y0u_c4nt_di4g0n4l1z3_y0ur_w4y_0ut_0f_h0m3w0rk_e8a16ce2870f47f58173b6a715c2c2d3}
```
