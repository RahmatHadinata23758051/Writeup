# Writeup CTF: Crypto Party 2

- **Kategori:** Cryptography
- **Tingkat Kesulitan:** Hard
- **Artefak:** Challenge server / source code
- **Algoritma:** ECDSA + AES-ECB
- **Flag:** `NNS{bu7_uu1ds_4r3_r4nd0m!!_1181a65695}`

---

# 1. Deskripsi Tantangan

Challenge ini merupakan implementasi sistem undangan digital menggunakan:

```
ECDSA
```

pada kurva:

```
NIST256p
```

Pemain dapat mendaftarkan maksimal:

```
6 teman
```

Setiap pendaftaran menghasilkan sebuah signature ECDSA.

Selain itu diberikan ciphertext yang berisi flag terenkripsi menggunakan:

```
AES-ECB
```

dengan secret key yang berasal dari private key ECDSA.

Tujuan challenge adalah memperoleh private key ECDSA melalui kelemahan pembangkitan nonce, kemudian menggunakan key tersebut untuk mendekripsi ciphertext.

---

# 2. Analisis Kerentanan

Kerentanan utama berada pada fungsi:

```
invite(m)
```

khususnya proses pembangkitan nonce:

```python
k = bytes_to_long(
    str(uuid.uuid4())[:32].encode()
)
```

---

# 3. Masalah pada Nonce ECDSA

ECDSA membutuhkan nonce:

```
k
```

yang harus:

- random;
- unik;
- memiliki entropi tinggi.

Namun implementasi menggunakan:

```
UUIDv4 string
```

secara langsung sebagai integer.

Contoh UUID:

```
xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
```

Ketika dipotong:

```
str(uuid.uuid4())[:32]
```

dan dikonversi:

```python
.encode()
```

maka yang digunakan bukan nilai random integer, tetapi byte ASCII.

---

# 4. Struktur UUIDv4

Format UUID:

```
xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
```

memiliki beberapa byte tetap.

Karakter:

| Posisi | Nilai |
|-|-|
| `-` | 45 |
| versi UUID | `4` = 52 |
| variant | terbatas |

Karakter lain hanya berasal dari:

```
0-9
a-f
```

Sehingga kemungkinan byte sangat terbatas.

---

# 5. Dampak Vulnerability

Nonce ECDSA menjadi memiliki struktur:

- sebagian byte diketahui;
- sebagian byte hanya memiliki kemungkinan kecil;
- tidak benar-benar random.

Hal ini memungkinkan serangan:

```
Hidden Number Problem (HNP)
```

menggunakan:

```
Lattice Reduction
```

---

# 6. Teori ECDSA

ECDSA signature:

\[
s=k^{-1}(h+r x)\pmod n
\]

dengan:

| Simbol | Keterangan |
|-|-|
| `k` | nonce |
| `h` | hash message |
| `r` | koordinat X dari kG |
| `x` | private key |
| `n` | order kurva |

---

Persamaan dapat ditulis ulang:

\[
k-(r s^{-1})x \equiv h s^{-1} \pmod n
\]

Definisikan:

\[
A=r s^{-1}\pmod n
\]

dan:

\[
B=h s^{-1}\pmod n
\]

maka:

\[
k-Ax\equiv B\pmod n
\]

Ini merupakan bentuk standar:

```
Hidden Number Problem
```

---

# 7. Konsep Serangan HNP

Nonce tidak diketahui sepenuhnya.

Namun karena struktur UUID diketahui, nonce dapat ditulis:

\[
k = k_{center}+e
\]

dengan:

- `k_center` = nilai perkiraan.
- `e` = error kecil.

Karena error kecil, sistem persamaan dapat dimasukkan ke lattice.

LLL digunakan untuk mencari:

```
short vector
```

yang berisi nilai error.

Setelah nonce berhasil dipulihkan:

```
k
```

private key dapat dihitung.

---

# 8. Pengumpulan Signature

Program dijalankan sebanyak 6 kali.

Input:

```
Pwn0
Pwn1
Pwn2
Pwn3
Pwn4
Pwn5
```

Untuk setiap signature disimpan:

```
r
s
h
```

dengan:

```
h = SHA256(message)
```

---

# 9. Analisis Struktur UUID

32 byte pertama UUID digunakan sebagai nonce.

Pemetaan:

```
byte 8
byte 13
byte 18
byte 23
```

berisi:

```
'-'
```

atau:

```
45
```

---

Byte versi:

```
byte 14
```

selalu:

```
'4'
```

atau:

```
52
```

---

Byte lain:

berasal dari:

```
hexadecimal ASCII
```

Kemungkinan:

```
0-9
a-f
```

Center value digunakan agar error berada dekat:

```
0
```

untuk kebutuhan lattice.

---

# 10. Konstruksi Lattice

Persamaan signature digabungkan dengan eliminasi private key.

Signature pertama digunakan sebagai referensi.

Matriks lattice:

```
168 x 168
```

dibangun.

Komponen matriks:

- variabel byte nonce;
- relasi antar signature;
- konstanta target.

Digunakan weight:

\[
K=2^{100}
\]

untuk memperkuat constraint.

---

# 11. LLL Reduction

Basis lattice direduksi menggunakan:

```
LLL
```

pada SageMath.

Output LLL berupa basis baru.

Dicari vector yang memiliki:

- error kecil;
- bobot target sesuai.

Vector tersebut memberikan rekonstruksi nonce.

---

# 12. Recovery Private Key

Setelah nonce pertama:

```
k0
```

diperoleh.

Private key dihitung:

\[
x=(k_0-B_0)A_0^{-1}\pmod n
\]

---

Hasil:

```
x =
11082561902398993088241177076169849413445717647034584180850200645534545851845
```

---

# 13. Dekripsi AES

Private key dikonversi menjadi byte.

Kemudian digunakan sebagai key:

```
AES-ECB
```

Ciphertext flag didekripsi menggunakan key tersebut.

---

# 14. Penyusunan Solver

Solver melakukan:

1. Mengambil 6 signature.
2. Menghitung hash message.
3. Membentuk model HNP.
4. Membuat lattice.
5. Menjalankan LLL.
6. Recover nonce.
7. Menghitung private key.
8. Mendekripsi ciphertext AES.

---

# 15. Struktur Solver

Pseudocode:

```python
signatures = []

for msg in messages:

    r, s = get_signature(msg)

    h = sha256(msg)

    signatures.append(
        (r,s,h)
    )


lattice = build_hnp_lattice(
    signatures
)


reduced = LLL(lattice)


k = recover_nonce(
    reduced
)


x = (
    k-B
)
*
inverse(A,n)
% n


flag = AES_ECB_decrypt(
    x,
    ciphertext
)
```

---

# 16. Hasil Akhir

Secret key:

```
11082561902398993088241177076169849413445717647034584180850200645534545851845
```

Flag:

```
NNS{bu7_uu1ds_4r3_r4nd0m!!_1181a65695}
```

---

# 17. Kesimpulan

ECDSA bergantung penuh pada keamanan nonce.

Implementasi challenge gagal karena:

1. Nonce tidak dibangkitkan secara random aman.
2. UUID string digunakan langsung sebagai integer.
3. Struktur byte nonce dapat diprediksi.
4. Jumlah signature cukup untuk serangan HNP.

Dengan lattice attack dan LLL reduction:

```
Nonce
 |
 v
Private Key
 |
 v
AES Key
 |
 v
Flag
```

berhasil dipulihkan.

Flag:

```
NNS{bu7_uu1ds_4r3_r4nd0m!!_1181a65695}
```
