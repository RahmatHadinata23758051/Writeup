# Writeup: forensics/skeleton

Challenge ini cuma ngasih satu file, `hash.txt`, yang isinya hash hasil `zip2john` dari sebuah ZIP terenkripsi. File ZIP aslinya tidak ada, jadi targetnya bukan sekadar brute-force arsip, tapi memanfaatkan data terenkripsi yang masih tersisa di hash itu sendiri.

## Recon awal

Isi folder:

- `hash.txt`

Kalau dilihat, format hash-nya seperti ini:

```text
flag.zip/flag.png:$pkzip2$1*1*2*0*12c*120*c8a6617a*0*26*0*12c*c8a6*81bd*...*$/pkzip2$:flag.png:flag.zip::flag.zip
```

Dari sini bisa dibaca beberapa hal penting:

- file di dalam ZIP bernama `flag.png`
- ukuran terenkripsi `0x12c` = 300 byte
- ukuran asli `0x120` = 288 byte
- metode kompresi `0`, artinya file disimpan tanpa kompresi

Karena file di dalam ZIP adalah PNG dan tidak dikompresi, plaintext awalnya sangat mudah ditebak. PNG selalu diawali signature dan header `IHDR`, jadi ini cocok untuk known-plaintext attack terhadap ZipCrypto.

## Langkah penyelesaian

Pertama saya ambil hash murninya lalu decode bagian ciphertext dari field terakhir hash menjadi file biner mentah.

Saya juga buat plaintext yang pasti diketahui dari format PNG:

- header awal: `89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52`
- trailer akhir PNG: `00 00 00 00 49 45 4E 44 AE 42 60 82`

Lalu saya jalankan `bkcrack`:

```bash
bkcrack -j 12 -c cipher.bin -p png_header.bin -o 0 -x 276 0000000049454e44ae426082
```

Setelah proses berjalan, `bkcrack` berhasil menemukan internal keys ZipCrypto:

```text
c639d1ca b1fd3d6c 25bb9b08
```

Dengan key itu, payload terenkripsi bisa langsung didekripsi menjadi PNG:

```bash
bkcrack -k c639d1ca b1fd3d6c 25bb9b08 -c cipher.bin -d flag.png
```

Hasilnya valid:

```text
flag.png: PNG image data, 220 x 20, 1-bit grayscale, non-interlaced
```

Setelah gambar dibuka, flag terlihat jelas.

## Flag

```text
tjctf{1ts_4ll_ab0ut_th3_keys}
```

## Inti pelajaran challenge

Challenge ini menarik karena file ZIP aslinya tidak dibagikan, tapi hash `zip2john` masih menyimpan cukup banyak informasi untuk melakukan serangan. Begitu diketahui bahwa file di dalam arsip adalah PNG yang disimpan tanpa kompresi, known-plaintext attack jadi jauh lebih masuk akal daripada brute-force password biasa.
