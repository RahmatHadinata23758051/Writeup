# Sultan Writeup

## Ringkasan

Challenge ini berupa crypto-web service. Aplikasi membuat secret random per session, lalu endpoint `/download` memberikan file `secret.enc` yang berisi secret tersebut dalam bentuk terenkripsi.

Targetnya bukan brute force secret, karena secret panjangnya 28–32 karakter dari alfabet huruf dan angka. Jalur solvenya adalah membongkar format `secret.enc`, recover secret vector kecil dari transcript Sultan, derive stream key, decrypt secret string, lalu submit ke `/api/verify` untuk mendapat flag.

Flag valid:

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```

## File Challenge

File penting dari source:

```
app.py
crypto_engine.py
Dockerfile
requirements.txt
templates/index.html
```

Endpoint utama:

```
GET  /download atau /api/encrypt  -> download secret.enc
POST /api/verify                  -> submit secret hasil decrypt
POST /api/reset                   -> reset session dan secret baru
```

## Analisis Awal

Dari `app.py`, setiap user punya session sendiri. Secret dibuat random dengan panjang 28 sampai 32 karakter:

```python
MIN_SECRET_LENGTH = 28
MAX_SECRET_LENGTH = 32
alphabet = string.ascii_letters + string.digits
```

Secret disimpan di memory session sebagai `secret_string`. Endpoint `/download` mengenkripsi `secret_string` dan mengirim hasilnya sebagai `secret.enc`.

Bagian verifikasi ada di `/api/verify`:

```python
if hmac.compare_digest(guess, sess.secret_string):
    sess.solved = True
    return flag
```

Jadi tujuan solver jelas: recover `sess.secret_string`, bukan langsung cari flag dari file.

## Format secret.enc

Di `crypto_engine.py`, file hasil enkripsi dikompres dengan zlib:

```python
return zlib.compress(bytes(raw), 9)
```

Setelah decompress, struktur file:

```
header
nonce
ciphertext secret
tag
70 transcript Sultan
```

Parameter crypto:

```
q = 8380417
n = 64
ell = 1
m = 70
t = 16
b = 65000
committee_size = 63
threshold = 32
secret_bound = 3
```

Header menyimpan parameter tersebut dan panjang secret. Setelah header, ada:

```
nonce: 24 byte
ciphertext: secret_len byte
blake2s tag: 32 byte
R transcripts: 70 buah
```

## Analisis Crypto

Pada setiap enkripsi, program membuat secret vector lattice kecil:

```python
s = [_g(-secret_bound, secret_bound) for _ in range(ell)]
w = _secret_bytes(s)
k = shake_256(b"SULTAN/key" + w).digest(32)
```

Karena `secret_bound = 3`, setiap koefisien `s` hanya berada di range:

```
-3, -2, -1, 0, 1, 2, 3
```

Key stream untuk encrypt secret dibuat dari key tersebut:

```python
p = shake_256(b"SULTAN/stream" + k + nonce).digest(len(secret_data))
e = secret_data xor p
```

Berarti kalau kita bisa recover `s`, kita bisa derive `k`, generate stream, lalu decrypt `e` menjadi secret string.

## Leak dari Transcript

Setiap transcript menyimpan data berikut:

```python
x = secrets.token_bytes(32)
y = bytes(sorted(random_source.sample(range(committee_size), threshold)))
seed = x + y
u = [_g(0, q - 1) for _ in range(ell)]
c = _b(seed)
v = u + c*s
audit = floor(<r(seed), u> / b)
```

Yang disimpan ke file:

```python
R.append(x + y + audit + z(v))
```

Kita tahu `seed`, karena `x` dan `y` ada di transcript. Berarti kita bisa menghitung ulang:

```python
c = _b(seed)
r = _r(seed)
```

Kita juga tahu `v` dan `audit`.

Karena:

```
v = u + c*s mod q
u = v - c*s mod q
```

Lalu audit memberi constraint:

```
audit = floor(<r, u> / 65000)
```

Substitusi `u = v - c*s` menghasilkan constraint linear modular terhadap `s` dengan noise kecil dari pembulatan bucket `65000`.

Ini bentuk Hidden Number Problem / LWR kecil. Secret `s` pendek dan koefisiennya sangat kecil, jadi bisa direcover dengan lattice.

## Strategi Solver

Solver melakukan langkah berikut:

1. Buat session HTTP.
2. Download satu `secret.enc` dari `/download`.
3. Decompress zlib.
4. Parse header, nonce, ciphertext, tag, dan 70 transcript.
5. Untuk setiap transcript:
   - hitung `c = _b(seed)`
   - hitung `r = _r(seed)`
   - bentuk persamaan audit terhadap `s`
6. Susun lattice embedding dari constraint LWR.
7. Jalankan LLL/BKZ untuk recover vector `s`.
8. Pack `s` menjadi bytes memakai format asli `_secret_bytes(s)`.
9. Derive key:

```python
k = shake_256(b"SULTAN/key" + w).digest(32)
```

10. Decrypt ciphertext:

```python
stream = shake_256(b"SULTAN/stream" + k + nonce).digest(secret_len)
secret = ciphertext xor stream
```

11. Submit secret ke `/api/verify`.
12. Ambil flag dari JSON response.

## Bukti Valid

Setelah secret berhasil didecrypt dan dikirim ke `/api/verify`, server membalas `success: true` dan memberikan flag.

Flag yang didapat:

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```

## Cara Menjalankan

Run solver dari folder challenge:

```
conda activate sage
sage -python solve_sultan.py http://91.107.152.21:17131
```

Atau kalau environment Python sudah punya dependency lattice seperti `fpylll`:

```
python3 solve_sultan.py http://91.107.152.21:17131
```

Contoh output akhir:

```
[+] downloading secret.enc
[+] parsed Sultan archive
[+] recovered small secret vector s
[+] decrypted session secret
[+] verify success
<FLAG>ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}</FLAG>
```

## Flag

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```
