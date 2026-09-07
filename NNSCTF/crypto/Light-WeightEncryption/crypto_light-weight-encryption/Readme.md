# Writeup CTF: Light-Weight Encryption

- **Kategori:** Cryptography
- **Tingkat Kesulitan:** Hard
- **Artefak:** `chall.sage`, `output.txt`
- **Flag:** `NNS{lwe,compact,broken:https://eprint.iacr.org/2017/742.pdf}`

---

# 1. Deskripsi Tantangan

Challenge memberikan implementasi skema enkripsi yang terlihat menyerupai:

```
Learning With Errors (LWE)
```

Secara umum, LWE dianggap aman karena menggabungkan:

- matriks random besar,
- secret key,
- noise kecil,
- modulus besar.

Namun implementasi pada challenge memiliki beberapa kelemahan fatal:

1. Modulus:

```
q = 2^768
```

sedangkan:

```
p = 520-bit
```

dan:

```
sk = 128-bit
```

2. Matriks:

```
A
```

hanya berisi nilai kecil:

```
0..15
```

3. Jumlah sample:

```
m = 112
```

dengan dimensi:

```
n = 16
```

Kombinasi tersebut memungkinkan pencarian relasi integer:

\[
uA=0
\]

yang kemudian membocorkan informasi tentang secret key.

---

# 2. Analisis Source Code

Bagian penting:

```python
k = R(p) / sk

B = A*s + k*e

ct = sum(A[i] for i in I), pt - sum(B[i] for i in I)
```

Bentuk enkripsi:

\[
B=A\cdot s+k\cdot e
\]

dengan:

- `A` sebagai matriks publik.
- `s` sebagai secret vector.
- `e` sebagai error/noise.
- `k=p/sk`.

---

# 3. Kelemahan Skema

Pada LWE normal:

\[
A\cdot s + e
\]

dibuat sulit dibalik karena noise dan dimensi besar.

Namun di challenge:

\[
B=A\cdot s+k\cdot e
\]

dengan:

\[
k=\frac{p}{sk}
\]

Jika ditemukan relasi:

\[
uA=0
\]

maka:

\[
uB=k(ue)
\]

Substitusi:

\[
sk \cdot uB
=
p(ue)
\pmod q
\]

---

Karena:

- error hanya 32-bit;
- koefisien relasi kecil;
- modulus sangat besar;

maka:

\[
p(ue)
\]

tetap jauh lebih kecil dibanding:

\[
q
\]

Sehingga nilai tersebut dapat diamati sebagai integer biasa.

---

# 4. Recover Secret Key

## 4.1 Mencari Null Relation

Dimensi:

```
n = 16
```

Ambil:

```
17 sample random
```

Karena jumlah vector lebih besar dari dimensi, pasti terdapat relasi non-trivial:

\[
c_0A_{i0}+c_1A_{i1}+...+c_{16}A_{i16}=0
\]

---

Untuk setiap relasi dihitung:

\[
v=
c_0B_{i0}+c_1B_{i1}+...+c_{16}B_{i16}
\pmod q
\]

Target:

mencari:

\[
sk
\]

sehingga:

\[
sk\cdot v
\]

menghasilkan residue kecil.

---

# 5. Hidden Number Problem

Masalah tersebut merupakan bentuk sederhana:

```
Hidden Number Problem
```

Lattice digunakan untuk mencari secret.

Basis lattice:

```
[q,0,...,0]

[0,q,...,0]

...

[v1,v2,...,scale]
```

Dengan:

```
LLL reduction
```

diperoleh vector pendek berbentuk:

\[
(sk v_1 \bmod q,
sk v_2 \bmod q,
...
sk \times scale)
\]

Koordinat terakhir memberikan:

\[
sk
\]

---

# 6. Hasil Recover Secret Key

Secret key:

```
sk =
270283635879737251538873624123331873743
```

---

# 7. Recover Modulus p

Setelah:

```
sk
```

diperoleh, setiap relasi:

\[
uA=0
\]

memberikan:

\[
centered(sk(uB))
=
p(ue)
\]

Karena seluruh nilai memiliki faktor:

\[
p
\]

maka modulus dapat diperoleh menggunakan:

\[
p=
gcd(|centered(sk v_i)|)
\]

---

Hasil:

```
p =
3027482295750605489255696042164651468249310701840658896590997289051911061727002063426402682573974942100626334692620363688451923900628757858102921612846994519
```

---

# 8. Recover Plaintext

Ciphertext terdiri dari:

```
ct = (ct_A, ct_B)
```

Bagian pertama:

```
ct_A
```

merupakan jumlah 130 baris random:

\[
ct_A=\sum A_i
\]

Tidak diperlukan index asli.

Cukup mencari vector integer kecil:

\[
x
\]

dengan kondisi:

\[
\sum x_i=130
\]

dan:

\[
\sum x_iA_i=ct_A
\]

---

# 9. Lattice Recovery

Solver mencari:

```
x
```

menggunakan:

```
embedding lattice + LLL
```

Karena:

\[
xA=ct_A
\]

maka:

\[
sk(ct_B+xB)
=
sk\cdot pt+p\cdot noise
\pmod q
\]

Noise masih kecil sehingga dapat digunakan centered representative.

---

Plaintext:

\[
pt=
(centered(sk(ct_B+xB))
\bmod p)
\times sk^{-1}
\bmod p
\]

---

# 10. Penyusunan Solver

File:

```
solve.py
```

melakukan:

1. Membaca ciphertext.
2. Membuat relasi null-space pada matrix A.
3. Menggunakan LLL untuk memperoleh secret key.
4. Menghitung modulus p.
5. Mencari kombinasi integer untuk ciphertext pertama.
6. Recover plaintext.
7. Mengubah integer menjadi bytes.

---

# 11. Algoritma Solver

Pseudocode:

```python
# recover sk

relations = find_null_relations(A)

for u in relations:

    v = u * B

    lattice.add(v)


sk = LLL(lattice)


# recover p

p = gcd(
    centered(sk * v1),
    centered(sk * v2),
    ...
)


# recover plaintext

x = solve_subset_relation(A, ctA)

noise = centered(
    sk * (ctB + x*B)
)

pt = (
    noise % p
    *
    inverse_mod(sk,p)
) % p
```

---

# 12. Cara Menjalankan

Jalankan:

```bash
python3 solve.py
```

Output:

```text
<FLAG>
NNS{lwe,compact,broken:https://eprint.iacr.org/2017/742.pdf}
</FLAG>
```

---

# 13. Kesimpulan

Implementasi LWE pada challenge ini gagal karena parameter dipilih secara tidak aman.

Masalah utama:

1. Matriks publik memiliki elemen terlalu kecil.

```
A = 0..15
```

2. Sample terlalu banyak dibanding dimensi.

```
m = 112
n = 16
```

3. Struktur modulus:

```
q = 2^768
```

membuat noise dapat dipisahkan dari nilai sebenarnya.

Dengan menemukan relasi:

\[
uA=0
\]

serangan lattice dapat memperoleh:

```
secret key
```

dan kemudian:

```
modulus p
```

Setelah itu plaintext dapat dipulihkan.

Flag berhasil diperoleh:

```
NNS{lwe,compact,broken:https://eprint.iacr.org/2017/742.pdf}
```
