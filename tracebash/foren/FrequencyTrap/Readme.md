# Frequency Trap

- **CTF:** TraceBash CTF
- **Category:** Forensics
- **Difficulty:** Medium
- **Flag:** `TBCTF{frequency_trap_successful}`

## Ringkasan

PNG ini tidak menyimpan flag lewat LSB atau appended data. Petunjuk metode ekstraksinya ditaruh di EXIF, sedangkan password disamarkan sebagai program Brainfuck.

Payload berada di domain frekuensi: channel luminance `Y` dipecah menjadi blok `8x8`, lalu satu bit dibaca dari koefisien DCT pada posisi `(3,3)`. Bitstream yang terbentuk didekripsi memakai password `frequencypass`.

## Recon

Identifikasi file dan cek metadata:

```bash
file frequency_trap.png
exiftool frequency_trap.png
```

Bagian yang relevan:

```text
File Type          : PNG
Image Width        : 2500
Image Height       : 1996
Color Type         : RGB
Image Description  : Method: YCbCr_DCT_8x8_coeff3x3
Lens Model         : ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.++++++++++++.-------------.++++++++++++.++++.----------------.+++++++++.-----------.++++++++++++++++++++++.---------.---------------.++++++++++++++++++..
```

`Image Description` sudah menjelaskan jalur utama:

```text
YCbCr -> DCT per blok 8x8 -> coefficient (3,3)
```

`Lens Model` hanya berisi karakter Brainfuck. Setelah dijalankan, output-nya:

```text
frequencypass
```

## Ekstraksi DCT

Gambar dikonversi dari RGB ke YCbCr. Channel `Y` dipakai karena menyimpan luminance dan menjadi channel yang disebut oleh metode pada metadata.

Langkah ekstraksinya:

1. Crop bagian kanan dan bawah agar ukuran habis dibagi 8.
2. Pecah channel `Y` menjadi blok `8x8`.
3. Hitung DCT 2D untuk setiap blok.
4. Ambil koefisien `(3,3)`.
5. Tanda koefisien membentuk bit: positif `1`, negatif `0`.
6. Susun bit secara row-major dan pack MSB-first.
7. XOR byte stream dengan password `frequencypass` secara berulang.
8. Cari pola flag pada hasil dekripsi.

Secara ringkas:

```python
bits.append(1 if dct_block[3, 3] >= 0 else 0)
plaintext[i] = ciphertext[i] ^ password[i % len(password)]
```

Solver juga mencoba rounded parity dan beberapa variasi QIM. Fallback ini berguna jika implementasi konversi YCbCr atau pembulatan DCT berbeda antar-library.

## Menjalankan Solver

Install dependency Python bila belum tersedia:

```bash
python3 -m pip install pillow numpy scipy
```

Jalankan terhadap file PNG asli:

```bash
python3 solve.py frequency_trap.png --verbose
```

Output:

```text
[*] ImageDescription: Method: YCbCr_DCT_8x8_coeff3x3
[*] Password: frequencypass
[+] Extraction path: Pillow YCbCr; coeff(3,3) sign; order=row; permutation=natural; invert=False; bit-offset=0; bit-order=big; decode=xor(password)
<FLAG>TBCTF{frequency_trap_successful}</FLAG>
```

Gunakan file asli berukuran `2500x1996`. Preview yang sudah di-resize akan mengubah batas blok dan koefisien DCT sehingga payload rusak.

## Flag

```text
TBCTF{frequency_trap_successful}
```
