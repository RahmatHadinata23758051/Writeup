# Magic Ways

## Ringkasan

`chall.png` tidak bisa dibuka karena bagian penting pada header PNG sengaja dirusak:

- signature PNG diganti dengan `DE AD BE EF 00 00 00 00`
- nilai tinggi gambar pada `IHDR` dibuat `0`
- CRC chunk `IHDR` dibuat `00000000`

Data gambar di dalam chunk `IDAT` masih utuh. Tinggi asli bisa dihitung dari ukuran scanline setelah payload `IDAT` didekompresi.

## Recon

Isi ZIP:

```bash
unzip -l chall.zip
```

```text
Archive:  chall.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     6518  2026-07-01 02:50   chall.png
---------                     -------
     6518                     1 file
```

Identifikasi file:

```bash
file chall.png
```

```text
chall.png: data
```

Header awal:

```bash
od -An -tx1 -N48 chall.png
```

```text
 de ad be ef 00 00 00 00 00 00 00 0d 49 48 44 52
 00 00 01 f4 00 00 00 00 08 02 00 00 00 00 00 00
 00 00 00 19 3d 49 44 41 54 78 9c ed dd 77 7c 14
```

Struktur chunk masih kelihatan:

```text
00 00 00 0d 49 48 44 52
            I  H  D  R
```

Nilai `IHDR` yang masih valid:

```text
width      = 00 00 01 f4 = 500
height     = 00 00 00 00 = rusak
bit depth  = 08
color type = 02           = RGB
```

## Menentukan tinggi gambar

PNG memakai RGB 8-bit, jadi satu piksel berukuran 3 byte.

```text
row data      = 500 × 3 = 1500 byte
filter byte   = 1 byte per scanline
scanline size = 1501 byte
```

Gabungan chunk `IDAT` didekompresi dengan zlib dan menghasilkan `300200` byte:

```text
height = 300200 / 1501
height = 200
```

Tinggi yang benar adalah `200`, atau `00 00 00 c8` dalam big-endian.

## Byte yang diperbaiki

Signature PNG standar:

```text
89 50 4e 47 0d 0a 1a 0a
```

Dimensi:

```text
width  = 00 00 01 f4 = 500
height = 00 00 00 c8 = 200
```

CRC32 baru dihitung dari:

```text
"IHDR" + 13 byte data IHDR
```

Hasil CRC:

```text
91 7b 84 bf
```

Header setelah perbaikan:

```text
89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
00 00 01 f4 00 00 00 c8 08 02 00 00 00 91 7b 84
bf 00 00 19 3d 49 44 41 54
```

## Solver

Solver menerima `chall.png` langsung atau ZIP yang berisi PNG:

```bash
python3 solve.py chall.png
```

atau:

```bash
python3 solve.py chall.zip
```

Output:

```text
[+] Source           : chall.png
[+] PNG signature    : 89504e470d0a1a0a
[+] Stored dimensions: 500x0
[+] IDAT raw size    : 300200 bytes (1501 bytes/scanline)
[+] Repaired size    : 500x200
[+] IHDR CRC         : 917b84bf
[+] Output           : repaired.png
<FLAG>bronco{wh4t_ar3_mag1c_byt3s}</FLAG>
```

OCR memakai `tesseract` jika tersedia. Tanpa OCR, buka `repaired.png`; flag tercetak jelas di tengah gambar.

## Flag

```text
bronco{wh4t_ar3_mag1c_byt3s}
```
