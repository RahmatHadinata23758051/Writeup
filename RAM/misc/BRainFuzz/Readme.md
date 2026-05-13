# BrainFuzz Writeup

## Ringkasan

Challenge memberi dua artefak utama:

- `generated_gibson.jpg`: gambar JPEG logo Gibson/RAMUNCHERS.
- `output.bin`: blob kecil berukuran 2112 byte.

Flag ditemukan dengan dua tahap:

1. Decode `output.bin` untuk mendapatkan passphrase.
2. Pakai passphrase tersebut untuk mengekstrak payload stego dari koefisien DCT JPEG.

Flag akhir:

```text
RMCTF{m37h0d_b3h1nd_7h3_m4dn355!}
```

## 1. Enumerasi awal

Pengecekan awal pada JPEG tidak menunjukkan data yang ditempel setelah marker EOF, metadata menarik, atau string flag langsung. `output.bin` juga tidak berisi string ASCII yang jelas.

Hal yang menarik muncul saat `output.bin` dilihat per blok 8 byte. File ini memiliki panjang 2112 byte, sehingga pas menjadi:

```text
2112 / 8 = 264 blok
264 bit = 33 byte
```

Mayoritas blok berisi `ff ff ff ff ff ff ff ff`. Dengan aturan sederhana:

- blok `ff ff ff ff ff ff ff ff` = bit `0`
- blok selain itu = bit `1`

lalu bit digabung per 8 bit secara MSB-first, hasilnya menjadi:

```text
\xa0d3f1n173ly_n07_4_53cR37_p4$$w0Rd
```

Byte pertama `0xa0` hanya padding/noise. String printable setelahnya adalah passphrase:

```text
d3f1n173ly_n07_4_53cR37_p4$$w0Rd
```

## 2. Ekstraksi data dari JPEG

Passphrase tersebut tidak muncul sebagai string di JPEG, jadi tahap berikutnya adalah steganografi pada JPEG. Payload berada di koefisien DCT terkuantisasi, bukan di pixel RGB biasa.

Langkah yang dipakai solver:

1. Baca koefisien DCT JPEG dengan `libjpeg`.
2. Ambil semua koefisien non-zero sebagai sample stego.
3. Buat selector pseudo-random dari passphrase:
   - hash passphrase dengan MD5;
   - pecah digest menjadi empat word 32-bit little-endian;
   - XOR keempat word itu untuk seed;
   - gunakan LCG `state = 1367208549 * state + 1` modulo `2^32`;
   - bentuk permutation selector seperti format steghide.
4. Untuk JPEG, satu embedded bit dihitung dari 3 sample:

```text
bit = (abs(sample_1) % 2 + abs(sample_2) % 2 + abs(sample_3) % 2) % 2
```

Header yang berhasil diekstrak:

```text
magic       = 0x73688d
version bit = 0
algorithm   = 2  # rijndael-128
mode        = 1  # cbc
nplainbits  = 505
```

Bagian encrypted payload berisi IV 16 byte di awal, lalu ciphertext. Untuk kompatibilitas mcrypt/steghide, `rijndael-128` berarti block size 128-bit, sedangkan key yang dipakai 32 byte. Jadi dekripsi dilakukan sebagai AES-256-CBC dengan key hasil keygen MD5 ala mcrypt:

```text
key = MD5(passphrase) || MD5(passphrase || MD5(passphrase))
```

Setelah dekripsi, plain bitstring dipotong ke 505 bit. Plain tersebut masih memakai zlib compression. Setelah decompress, struktur payload berisi checksum, nama file, lalu data file.

Nama file embedded:

```text
flag.txt
```

Isi file:

```text
RMCTF{m37h0d_b3h1nd_7h3_m4dn355!}
```
