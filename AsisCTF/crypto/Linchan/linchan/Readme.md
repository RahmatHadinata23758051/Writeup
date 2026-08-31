# ASIS CTF — Linchan Write-up

## Overview

Challenge ini memberikan dua file:

* `linchan.py` — generator challenge.
* `output.txt` — data publik yang berisi ciphertext dan kumpulan subspace matriks.

Tujuan akhirnya adalah mendapatkan key ChaCha20-Poly1305 yang digunakan untuk mengenkripsi flag.

Dari source terlihat bahwa challenge bekerja sepenuhnya di atas matriks \(32\times32\) pada \(GF(2)\). Parameter utamanya adalah:

```python
_n = 32
_l = ((16, 2), (17, 2), (18, 1))
_d = 34
_z = b"linchan/v2"
```

Artinya terdapat lima secret matrix secara total:

* 2 secret untuk \(m=16\)
* 2 secret untuk \(m=17\)
* 1 secret untuk \(m=18\)

Masing-masing secret merupakan matriks invertible \(32\times32\).

---

## 1. Matrix Representation

Setiap row matriks disimpan sebagai integer 32-bit.

Operasi penjumlahan matriks hanyalah XOR:

```python
def _a(A, B):
    return [x ^ y for x, y in zip(A, B)]
```

Sedangkan `_m(A,B)` melakukan perkalian matriks pada \(GF(2)\).

Challenge juga menyediakan transpose dan inverse matrix:

```python
_t(A)
_i(A)
```

Jadi seluruh konstruksi bisa dipandang sebagai linear algebra di \(GF(2)\).

---

## 2. Hidden Rank-25 Matrices

Bagian paling penting pertama adalah fungsi:

```python
def _h():
    while True:
        A = [secrets.randbits(25) for _ in range(_n)]
        B = [secrets.randbits(_n) for _ in range(25)]
        X = _m(A, B)
        if _r(X) == 25:
            return X
```

Matrix `A` mempunyai ukuran \(32\times25\), sedangkan `B` berukuran \(25\times32\).

Karena:

$$
X=A\cdot B
$$

maka:

$$
\operatorname{rank}(X)\le25
$$

Generator bahkan memastikan:

$$
\operatorname{rank}(X)=25
$$

dengan pengecekan `_r(X) == 25`.

Selanjutnya perhatikan:

```python
def _b(m, q=False):
    B = [_h(), _h()] if q else []
```

Jika `q=True`, sebuah box selalu dimulai dengan **dua matriks rank 25**.

Setelah itu box diisi matriks random sampai dimensinya menjadi `m`.

Ini merupakan distinguisher utama challenge.

---

## 3. Obfuscation Tidak Menghilangkan Low-Rank Element

Sebelum box diberikan ke player, generator menjalankan:

```python
def _o(B):
    B = [_c(x, B) for x in _u(len(B))]
    return [_t(A) for A in B] if secrets.randbits(1) else B
```

`_u(m)` menghasilkan basis invertible dari \(GF(2)^m\), lalu `_c()` membuat linear combination dari basis matrix sebelumnya.

Jadi `_o()` sebenarnya hanya melakukan:

1. change of basis pada matrix subspace;
2. optional transpose untuk seluruh subspace.

Hal pentingnya:

> Change of basis tidak mengubah subspace.

Dengan demikian dua matriks rank-25 tadi masih berada di dalam span box meskipun tidak lagi terlihat langsung sebagai elemen basis yang diberikan.

Karena \(m\) hanya 16, 17, atau 18, seluruh elemen subspace masih bisa dienumerasi:

$$
2^{16}=65536
$$

$$
2^{17}=131072
$$

$$
2^{18}=262144
$$

Ini sangat kecil untuk brute force.

---

## 4. MinRank Scan

Untuk setiap box, saya enumerasi semua nonzero linear combination:

$$
X=\sum_i c_i B_i,\qquad c_i\in GF(2)
$$

lalu menghitung:

$$
\operatorname{rank}(X)
$$

Jika ditemukan:

$$
\operatorname{rank}(X)\le25
$$

box tersebut ditandai sebagai planted box.

Untuk mempercepat enumerasi, solver menggunakan Gray code. Jadi dari combination sebelumnya ke berikutnya hanya satu basis matrix yang berubah dan state cukup di-XOR satu kali.

Pseudo-code:

```text
cur = 0

for mask in gray_code(1 .. 2^m-1):
    changed = previous_mask XOR mask
    cur ^= basis[index(changed)]

    if rank(cur) <= 25:
        save(mask)
```

Decoy dibentuk dari matriks random:

```python
B.append((m, _o(_b(m))))
```

sementara planted box berasal dari `_b(m, True)`.

Untuk instance ini, scan mendapatkan tepat 10 suspicious boxes:

```text
[1, 32, 44, 47, 49, 60, 82, 86, 92, 106]
```

Ini sesuai ekspektasi karena terdapat 5 secret dan setiap secret menghasilkan dua box.

---

## 5. Hubungan Antar Planted Box

Sekarang lihat bagaimana planted pair dibuat:

```python
C, S = _b(m, True), _g()
T = _i(S)
D = [_m(_m(S, A), T) for A in C]
```

Karena `T = S^-1`, maka setiap matrix pada box kedua berbentuk:

$$
D_i=S C_i S^{-1}
$$

Jadi dua subspace tersebut saling **conjugate**.

Inilah properti kedua yang digunakan untuk memasangkan 10 special boxes menjadi 5 pasangan.

Hasil pairing:

```text
m=16: box 49 <-> 60
m=16: box 82 <-> 86

m=17: box 1  <-> 92
m=17: box 47 <-> 106

m=18: box 32 <-> 44
```

---

## 6. Recover Secret Conjugator

Misalkan dua low-rank matrix yang bersesuaian adalah:

$$
A
$$

dan:

$$
B=SAS^{-1}
$$

Daripada langsung menyelesaikan persamaan nonlinear tersebut, kalikan kanan dengan \(S\):

$$
BS=SA
$$

Sekarang persamaannya **linear terhadap seluruh bit dari \(S\)**.

Karena \(S\) adalah matrix \(32\times32\), terdapat:

$$
32^2=1024
$$

unknown bits.

Untuk setiap pasangan elemen \(i,j\):

$$
(BS)_{ij}=(SA)_{ij}
$$

memberikan satu linear equation di \(GF(2)\).

Satu pasangan matriks memberikan hingga 1024 persamaan.

Saya menggunakan dua low-rank matrix sekaligus:

$$
B_1S=SA_1
$$

$$
B_2S=SA_2
$$

dan menggabungkan kedua linear system tersebut.

Pada planted pair yang benar, kernel akhirnya memiliki dimension 1.

Karena field-nya adalah \(GF(2)\), satu-satunya nonzero scalar adalah 1. Akibatnya nonzero vector di kernel langsung memberikan matrix conjugator yang kita cari.

Setelah reshape 1024 bit menjadi matrix \(32\times32\), solver memastikan:

```text
rank(S) = 32
```

dan memverifikasi kembali:

$$
S A_i S^{-1}=B_i
$$

---

## 7. Handling Transpose and Generator Ordering

Ada dua gangguan tambahan.

Pertama, `_o()` dapat mentranspose seluruh box:

```python
return [_t(A) for A in B] if secrets.randbits(1) else B
```

Kedua, dua hidden rank-25 generators tidak mempunyai ordering yang dapat dipercaya setelah basis transformation.

Karena hanya ada dua generator, solver cukup mencoba kemungkinan kecil berikut:

```text
transpose / no transpose
generator order (0,1) / (1,0)
```

Setiap kandidat kemudian diuji dengan equation conjugacy.

False positive akan gagal karena linear system tidak menghasilkan invertible conjugator yang valid.

---

## 8. Why Recovering an Equivalent Secret Is Enough

Menariknya, kita tidak harus mendapatkan orientasi `S` yang persis sama dengan generator.

Key derivation menggunakan:

```python
def _f(S):
    T = _i(S)
    return min(_p(S), _p(T), _p(_t(S)), _p(_t(T)))
```

Jadi generator menganggap empat representasi berikut ekuivalen:

$$
S
$$

$$
S^{-1}
$$

$$
S^T
$$

$$
(S^{-1})^T
$$

dan memilih serialized value terkecil.

Ini sangat membantu karena transpose pada `_o()` tidak perlu dibalik sampai mengetahui orientasi original dengan pasti.

Selama conjugator yang ditemukan termasuk dalam equivalence class tersebut, canonical representation akan sama.

---

## 9. Key Derivation

Setelah semua lima secret ditemukan, challenge melakukan:

```python
X = b"".join(sorted(_f(A) for A in S))
return hashlib.shake_256(
    b"linchan-v2/key\0" + X
).digest(32)
```

Jadi solver melakukan hal yang sama:

1. canonicalize kelima secret;
2. sort byte representation;
3. concatenate;
4. SHAKE-256;
5. ambil 32 byte.

Recovered key:

```text
c79d930f6691caace9686711a0d8b9e9590a16831b935f14fb5beb6a5c56b638
```

Key derivation ini sesuai fungsi `_k()` pada challenge.

---

## 10. Decrypt Flag

Ciphertext dibuat sebagai:

```python
nonce = secrets.token_bytes(12)

ct = nonce + ChaCha20Poly1305(_k(K)).encrypt(
    nonce,
    msg,
    b"linchan/v2"
)
```

Kemudian disimpan sebagai Base85 di JSON challenge.

Jadi setelah key ditemukan:

```python
ct = base64.b85decode(obj["ct"])

nonce = ct[:12]
ciphertext = ct[12:]

flag = ChaCha20Poly1305(key).decrypt(
    nonce,
    ciphertext,
    b"linchan/v2"
)
```

Hasilnya:

```text
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

---

# Exploit Summary

Keseluruhan serangan bisa dirangkum menjadi:

```text
output.txt
    |
    v
decode Base85 + zlib + JSON
    |
    v
enumerate every element of each m-dimensional matrix subspace
    |
    v
find matrices with rank <= 25
    |
    v
identify 10 planted boxes
    |
    v
pair boxes having equal m through simultaneous conjugacy
    |
    v
solve B*S = S*A over GF(2)
    |
    v
recover 5 invertible conjugators
    |
    v
canonicalize S, S^-1, S^T, S^-T
    |
    v
SHAKE-256 key derivation
    |
    v
ChaCha20-Poly1305 decrypt
    |
    v
FLAG
```

---

## Root Cause

Kelemahan utama challenge bukan ChaCha20 atau SHAKE-256.

Masalahnya adalah struktur algebra yang digunakan untuk menghasilkan key bocor melalui public boxes.

Setiap planted subspace sengaja memiliki dua low-rank matrices:

$$
\operatorname{rank}=25
$$

sedangkan dimensinya hanya:

$$
m\le18
$$

Maka seluruh subspace mempunyai maksimal \(2^{18}\) elemen dan dapat dicari secara exhaustive.

Setelah planted boxes teridentifikasi, hubungan:

$$
B=SAS^{-1}
$$

juga tidak cukup menyembunyikan `S`, karena dapat diubah menjadi linear system:

$$
BS=SA
$$

dan diselesaikan langsung di \(GF(2)\).

Dengan dua matriks random yang conjugate oleh `S` yang sama, ambiguity centralizer praktis hilang sehingga secret conjugator bisa direcover secara unik.

---

# Flag

```text
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```
