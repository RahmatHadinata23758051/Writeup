# China Crack? - 101

Category: Crypto  
Point: 101  
Flag: `V1T{Tryna_cRacK_iS_BaCk_MtfK_dffdf21a13908662e27d8c5c875809e4}`

## Ringkas

Arsip 7z memakai encrypted header. Password-nya sesuai hint challenge: password dari challenge lama yang namanya mirip, yaitu `Tryna crack`.

Password arsip:

```text
D4mn_br0_H0n3y_p07_7yp3_5h1d
```

Setelah header 7z bisa dibaca, ada dua file penting:

```text
CC01/.secret = zip_password + _V1T
CC01/CC01-challenge
```

Isi `.secret` berupa bit ASCII:

```text
01110011011100010111001001110100001010000101001101001101010100110100110100101001
```

Decode-nya:

```text
sqrt(SMSM)
```

Hint ini mengarah ke SM-family crypto, terutama SM2/SM3.

## Alur exploit

7z memakai AES-CBC dengan key hasil KDF SHA-256 7z. Setelah payload utama didekripsi, stream LZMA2 menghasilkan konten `CC01`. File `CC01-challenge` ternyata hex string yang jika dibaca sebagai bytes membentuk ciphertext SM2.

Format ciphertext-nya:

```text
C1 || C2 || C3
```

`C1` adalah point SM2 tanpa prefix `04`, jadi 64 byte pertama dipakai sebagai `(x, y)`. Point tersebut valid pada kurva SM2 standar.

Nama file `.secret = zip_password + _V1T` dipakai sebagai petunjuk private key. Private scalar dibuat dari string berikut:

```text
D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T
```

Lalu diubah menjadi integer big-endian dan direduksi modulo order kurva SM2:

```python
d = int.from_bytes((zip_password + "_V1T").encode(), "big") % n
```

Decryption SM2 dilakukan dengan SM3-KDF. Hash `C3` valid, jadi plaintext benar. Plaintext masih berupa hex dari PNG. Setelah `bytes.fromhex(...)`, gambar hasilnya berisi template flag:

```text
V1T{Tryna_cRacK_iS_BaCk_MtfK_[that-zip-password-in-md5]}
```

MD5 dari password zip:

```text
dffdf21a13908662e27d8c5c875809e4
```

Final flag:

```text
V1T{Tryna_cRacK_iS_BaCk_MtfK_dffdf21a13908662e27d8c5c875809e4}
```

## Run

```bash
python3 solve.py
```

Output:

```text
<FLAG>V1T{Tryna_cRacK_iS_BaCk_MtfK_dffdf21a13908662e27d8c5c875809e4}</FLAG>
```

Untuk menyimpan PNG hasil decrypt:

```bash
python3 solve.py --save-png
```
