# Replay-Jasmine?

- **Category:** Crypto
- **CTF:** LYKN CTF
- **Difficulty:** Hard
- **Flag:** `LYKNCTF{Connect_The_World}`

## Ringkasan

`chall.json` berisi dua instance Learning With Errors berukuran kecil, parameter scrypt, dan ciphertext final. Secret dari kedua instance dapat dipulihkan sebagai masalah closest vector pada q-ary lattice. Kedua secret lalu dipack sebagai signed integer 32-bit little-endian, diproses dengan scrypt, dan dipakai sebagai master key untuk `Shiina256PIGE`.

## Struktur data

Bagian penting dari `chall.json`:

| Field | Ukuran | Peran |
|---|---:|---|
| `Alcginlcgchall` | 32 x 20 | Matriks LWE pertama |
| `donttimebabybob` | 32 | Sampel LWE pertama |
| `timeforR` | 28 x 18 | Matriks LWE kedua |
| `c` | 28 | Sampel LWE kedua |
| `kdf` | object | Parameter scrypt |
| `finally` | hex | Ciphertext `Shiina256PIGE` |

Nilai matriks pertama berada pada rentang `0..768`, sehingga modulusnya `q1 = 769`. Matriks kedua berada pada rentang `0..502`, sehingga modulusnya `q2 = 503`.

Kedua sistem mengikuti bentuk:

```text
b = A*s + e mod q
```

`e` sangat kecil, sedangkan `s` juga memiliki koefisien kecil. Menyelesaikan sistem secara langsung modulo `q` tidak cukup karena noise membuat hasilnya tidak exact.

## Memulihkan secret dengan lattice

Untuk setiap instance, bentuk lattice:

```text
Λ = {A*x + q*z | x ∈ Z^n, z ∈ Z^m}
```

Generator kolomnya:

```text
G = [qI_m | A]
```

`b` berada sangat dekat dengan suatu titik lattice karena:

```text
b = A*s + q*z + e
```

Dengan kata lain, titik lattice terdekat terhadap `b` adalah `b - e`.

Langkah solver:

1. Hitung Hermite Normal Form dari `G` untuk memperoleh basis lattice persegi.
2. Transpose basis karena `fpylll` menggunakan row basis.
3. Reduksi basis memakai LLL.
4. Jalankan CVP untuk mencari titik lattice yang paling dekat dengan target.
5. Hitung noise sebagai `e = b - closest`.
6. Selesaikan `A*s = closest mod q` memakai eliminasi Gauss modular.
7. Ubah setiap koefisien ke representasi centered modulo `q`.

Secret yang didapat:

```text
s1 = [-1, 3, 3, 1, 2, 3, 2, 3, 2, 0,
       3, -1, 3, 0, 3, 2, -1, -2, -2, 1]

s2 = [-2, -2, 1, -1, -2, 2, 2, 0, -1,
      -2, -2, 0, 1, 0, -1, 0, -1, 2]
```

Validasi residual menunjukkan:

```text
instance 1: noise berada pada [-2, 2]
instance 2: noise berada pada [-1, 1]
```

Rentang sekecil ini memastikan hasil CVP benar, bukan sekadar solusi modular acak.

## Membentuk password scrypt

Kedua secret digabung dan dipack sebagai signed `int32` little-endian:

```python
coefficients = s1 + s2
password = struct.pack(f"<{len(coefficients)}i", *coefficients)
```

Parameter dari JSON:

```text
algorithm = scrypt
N         = 16384
r         = 8
p         = 4000
salt      = "shiina-ctf-2025"
dklen     = 32
```

Master key yang dihasilkan:

```text
b502f41599a0c55ef15bd3ab7282bf0ce58aadaafa73aa34a96975e589c4b1b6
```

`p=4000` membuat pemanggilan scrypt biasa berjalan lama. Tahap ROMix untuk setiap blok `p` bersifat independen, jadi `solve.py` membaginya ke beberapa worker. Hasilnya tetap identik dengan RFC 7914:

```text
B  = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
B' = ROMix(B_0) || ROMix(B_1) || ... || ROMix(B_(p-1))
DK = PBKDF2-HMAC-SHA256(password, B', 1, dklen)
```

## Dekripsi ciphertext

`_aux.py` mendefinisikan `Shiina256PIGE`. Format ciphertext:

```text
nonce  = 96 byte
body   = kelipatan 64 byte
tag    = HMAC-SHA512 64 byte
```

Master key diturunkan lagi dengan HKDF-like HMAC-SHA512 menjadi encryption key, MAC key, forward IV, dan backward IV. Autentikasi tag juga menjadi validasi final bahwa secret dan serialisasi password sudah tepat.

```python
plaintext = Shiina256PIGE(master_key).decrypt(bytes.fromhex(data["finally"]))
```

Output:

```text
LYKNCTF{Connect_The_World}
```

## Menjalankan solver

Letakkan file berikut dalam satu folder:

```text
chall.json
_aux.py
solve.py
```

Aktifkan environment dan pasang dependency:

```bash
source /home/nata/ctf_env/bin/activate
pip install sympy fpylll cysignals scrypt
```

Jalankan:

```bash
python3 solve.py chall.json --workers 4
```

Output akhir:

```text
<FLAG>LYKNCTF{Connect_The_World}</FLAG>
```
