# Mario Writeup

File berisi dua artefak utama:

- `mario.py`, generator challenge.
- `output.txt`, payload publik hasil eksekusi generator.

Parameter yang dipakai:

```
n = 96
m = 72
d = 24
s = 64
field = GF(16), modulus x^4 + x + 1
```

Flag dienkripsi dengan AES-GCM. Key AES tidak langsung ada di output. Key dibuat dari `row_reduce(public_oil_basis)`, lalu masuk ke HKDF dengan context `MARIO`.

Targetnya berarti jelas: pulihkan `public_oil_basis`, lakukan row reduction yang sama, turunkan key, lalu decrypt ciphertext.

## 1. Bentuk central map

Fungsi `oil_embed()` membentuk vektor 96 elemen dari input 24 elemen:

```python
y[0:v] = K*x
y[v:] = x
```

Jadi ada subspace rahasia berdimensi 24. Ini yang disebut oil subspace.

Fungsi `build_public_map()` membuat 72 quadratic form. Koefisien oil-oil disetel agar semua polynomial bernilai nol pada oil subspace. Setelah itu semua koordinat diacak dengan `monomial_scramble()`, yaitu permutasi koordinat plus scaling nonzero di GF(16).

Efek akhirnya:

```
public_oil_basis = transformed oil basis
A = quadratic forms yang vanish pada public_oil_basis
```

Kalau punya basis subspace itu, key langsung bisa dihitung.

## 2. Kebocoran dari reports

Bagian penting ada di pembuatan `reports`:

```python
oil_vec = oil_embed(k_mat, r(d))
mask = secrets.randbelow(15) + 1
reports.append(vec_add(oil_vec, vec_scale(g, mask)))
```

Setelah transformasi publik, bentuknya tetap sama secara linear:

```
B_i = u_i + a_i*g
```

Dengan:

- `u_i` berada pada oil subspace.
- `a_i` adalah scalar nonzero di GF(16).
- `g` adalah satu arah tambahan yang sama untuk semua report.

Jadi 64 report tidak acak penuh di ruang 96 dimensi. Semuanya berada di ruang kecil:

```
O + <g>
```

Dimensinya maksimal 25. Ini titik bocornya.

## 3. Menghapus arah g

Ambil dua report:

```
B_i = u_i + a_i*g
B_j = u_j + a_j*g
```

Gabungkan dengan scalar `c`:

```
B_i + c*B_j = (u_i + c*u_j) + (a_i + c*a_j)*g
```

Karena field-nya karakteristik 2, pengurangan sama dengan penjumlahan. Ada satu `c` nonzero yang membuat:

```
a_i + c*a_j = 0
```

Saat itu:

```
B_i + c*B_j = u_i + c*u_j
```

Vektor hasilnya berada murni di oil subspace.

Kita tidak tahu `a_i` dan `a_j`, tapi GF(16) hanya punya 15 scalar nonzero. Jadi brute force `c = 1..15` cukup.

Untuk mengecek apakah kandidat masuk oil subspace, evaluasi semua quadratic form publik. Kandidat valid kalau semuanya menghasilkan nol:

```python
if all(F(candidate) == 0 for F in A):
    candidate adalah oil vector
```

Dengan satu report sebagai referensi, 24 vektor independen sudah cukup untuk mendapatkan basis oil subspace.

## 4. Rebuild key

Setelah 24 vektor oil terkumpul, solver menjalankan row reduction yang sama dengan `mario.py`.

Material key dibuat dari semua elemen RREF:

```python
material = bytes(x for row in row_reduce(oil_basis) for x in row)
```

Lalu HKDF:

```python
key = HKDF(material, 32, salt, SHA256, context=b"MARIO")
```

Solver memakai implementasi HKDF-SHA256 manual agar tidak tergantung penuh pada PyCryptodome. Untuk AES-GCM, solver mencoba PyCryptodome dulu. Kalau tidak ada, fallback ke `cryptography`.

## 5. Decrypt

Payload `C` berisi:

```
salt
nonce
ciphertext || tag
```

AAD yang dipakai AES-GCM adalah:

```
MARIO
```

Setelah key benar, tag valid dan plaintext keluar:

```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```

## Cara jalanin

```
python3 solve.py
```

Output:

```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```
