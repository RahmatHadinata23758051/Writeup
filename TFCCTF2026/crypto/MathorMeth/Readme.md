# MATH OR METH?

## Observasi

`chall.py` membuat matriks rahasia `A` berukuran `57 x 88`. Semua elemennya
berada di `[0, 32]`, kecuali satu baris yang diganti dengan digit-digit
representasi basis-33 dari `msg`.

Output hanya memberikan:

```text
h[j] = sum(a[i] * A[i][j] for i in range(57)) mod p
```

Nilai `p` berukuran 1084 bit, sedangkan `m-n = 31`. Jadi faktorisasi RSA,
XOR, dan brute force byte bukan jalur yang relevan. Struktur yang berguna
adalah adanya 31 relasi linear antarkolom.

## Mencari nullspace dengan LLL

Buat lattice berisi baris-baris

```text
(e_0, h_0), (e_1, h_1), ..., (e_87, h_87), (0, p)
```

Vektor lattice dengan koordinat terakhir nol berarti

```text
sum(v[j] * h[j]) = 0 mod p
```

LLL menemukan tepat 31 vektor pendek dengan koordinat terakhir nol. Relasi
tersebut membentuk nullspace integer dari `A`, karena untuk setiap relasi `v`:

```text
v * h = v * (a * A) = a * (A * v) = 0 mod p.
```

Nullspace ini dihitung ulang secara eksak dengan Sage. Orthogonal complement-
nya adalah row lattice yang memuat semua baris `A`.

## Mencari baris planted

Row lattice direduksi lagi dengan LLL. Baris planted dicari sebagai kombinasi
pendek dari basis hasil reduksi, dengan constraint setiap koordinat berada di
`[0, 32]`. Enumerasi bounded memakai CP-SAT.

Setiap kandidat kemudian diubah kembali dari basis 33:

```python
value = sum(digit[i] * 33**i for i in range(88))
message = value.to_bytes(..., "big")
```

Kandidat yang terbaca adalah:

```text
this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs
```

Komentar pada source meminta hasil ditempatkan di wrapper `TFCCTF{}`.

## Menjalankan solver

Aktifkan environment Python dan jalankan Sage yang tersedia:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Output:

```text
<FLAG>TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs}</FLAG>
```
