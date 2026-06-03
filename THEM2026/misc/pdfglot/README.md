# Pdfglot - Writeup

## Ringkasan

Challenge memberikan dua artefak: `mistery.pdf` dan `flag.zip`. ZIP utama berisi `flag/flag.txt`, tetapi file tersebut terenkripsi memakai WinZip AES. PDF terlihat seperti file biasa, tetapi ternyata dibuat sebagai polyglot PDF/ZIP dan menampilkan hint password.

Flag yang didapat:

```text
THEM?!CTF{pygl0tt3d_fl4gg0}
```

## 1. Recon awal

Pertama cek tipe file:

```bash
file flag.zip mistery.pdf
```

Hasil penting:

- `flag.zip` adalah ZIP archive.
- `mistery.pdf` adalah PDF, tetapi saat dicek dengan tool ZIP, file ini juga punya struktur ZIP tersembunyi.

Cek isi ZIP utama:

```bash
zipinfo -v flag.zip
```

Terlihat ada `flag/flag.txt` dengan compression method `99`, yaitu WinZip AES encryption. Jadi `unzip` standar tidak cukup karena Python `zipfile` juga tidak mendukung metode AES ini.

## 2. Analisis PDF

`pdftotext mistery.pdf -` menghasilkan teks:

```text
NothingHereOrMaybe:

pwd:pyglotted
```

PDF juga punya tanda polyglot:

```bash
zipinfo mistery.pdf
```

Output menunjukkan ada entry ZIP seperti `hint/` dan `hint/hint.txt`, tetapi struktur offset-nya sengaja dibuat aneh/overlap sehingga `unzip` menolak mengekstrak. Karena itu jalur yang paling stabil adalah mengambil hint yang tampil di PDF.

Hint yang terlihat adalah:

```text
pyglotted
```

Namun password langsung `pyglotted` gagal untuk membuka `flag.zip`. Dari pola challenge dan nama `Pdfglot`, hint tersebut perlu ditransformasikan. Transformasi yang valid adalah MD5 hex dari `pyglotted`:

```text
md5("pyglotted") = bfa9c03cfd94cffd9381b83234ca6ac1
```

Password inilah yang cocok dengan verifier dan HMAC WinZip AES.

## 3. Dekripsi ZIP AES

Struktur WinZip AES pada `flag.zip`:

- AES strength: 3, berarti AES-256.
- Salt length: 16 byte.
- Password verifier: 2 byte.
- Encrypted compressed payload.
- Authentication code: HMAC-SHA1 truncated 10 byte.
- Actual compression method dari AES extra field: deflate.

Langkah dekripsi:

1. Ambil hint dari PDF: `pyglotted`.
2. Hitung password ZIP: `md5(pyglotted).hexdigest()`.
3. Derive key dengan PBKDF2-HMAC-SHA1, 1000 iterasi.
4. Validasi password verifier.
5. Validasi HMAC-SHA1 truncated 10 byte.
6. Dekripsi payload AES-CTR WinZip.
7. Inflate raw deflate stream.
8. Validasi CRC dan ambil flag.

Solver final ada di `solve.py` dan bisa dijalankan langsung:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
<FLAG>THEM?!CTF{pygl0tt3d_fl4gg0}</FLAG>
```
