# Writeup - What's the word?

Kategori: misc  
Nama challenge: **What's the word?**

## Ringkasan
File challenge cuma satu, namanya `file`. Dari deskripsi dan hint, terlihat ini soal nyari sesuatu yang "tersembunyi" di dalam file.

## 1. Enumerasi awal
Langsung cek tipe file:

```bash
file file
```

Hasil: `CDFV2 Encrypted`.

Ini khas dokumen Microsoft Office yang dienkripsi (container OLE dengan `EncryptionInfo` + `EncryptedPackage`).

Lalu cek isi container:

```bash
7z l file
```

Terlihat stream penting:
- `EncryptionInfo`
- `EncryptedPackage`

Berarti memang dokumen Office terenkripsi, jadi harus dapat password dulu.

## 2. Crack password dokumen
Extract hash Office pakai John helper:

```bash
office2john.py file > hash.txt
```

Lalu crack dengan wordlist bawaan John:

```bash
./john --format=office --wordlist=./password.lst hash.txt
```

Password ketemu:

`q1w2e3r4t5`

## 3. Decrypt dokumen
Decrypt dokumen dengan `msoffcrypto-tool` / library `msoffcrypto`.

Setelah decrypt, file hasilnya adalah DOCX (zip-based Office document).

Isi dokumen ternyata cuma gambar:

`word/media/image1.png`

## 4. Ekstraksi flag dari gambar
OCR biasa di gambar asli kurang konsisten, tapi saat fokus ke channel biru/threshold, teks flag kebaca jelas.

Hasil OCR konsisten mengarah ke:

`CIT{bird_1s_th3_w0rd}`

## Flag

<FLAG>CIT{bird_1s_th3_w0rd}</FLAG>
