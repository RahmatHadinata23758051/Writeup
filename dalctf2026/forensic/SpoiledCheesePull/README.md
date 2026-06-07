# Spoiled Cheese Pull Writeup

## Ringkasan

Artefak yang diberikan adalah `chall(1).zip`. Di dalamnya hanya ada satu file bernama `chall.png`, tetapi hasil `file` menunjukkan bahwa file tersebut tidak benar-benar PNG. Header awalnya dibuat seperti JPEG/JFIF, sementara isi setelahnya ternyata mengikuti struktur PNG yang sengaja dirusak.

Flag ditemukan setelah memperbaiki struktur PNG, membaca gambar rMQR yang muncul, lalu mengekstrak payload byte mode dari simbol rMQR tersebut.

## Recon awal

```bash
file chall\(1\).zip
unzip -l chall\(1\).zip
unzip chall\(1\).zip
file chall.png
strings -a chall.png
```

Hasil penting:

```text
chall.png: JPEG image data, JFIF standard ...
JFIF
IHET
ISADx
SEND
Nothing2SeeHereGoLookSomewhereElse
```

Nama file adalah `.png`, tetapi signature awalnya JPEG. String `IHET`, `ISAD`, dan `SEND` terlihat mencurigakan karena sangat mirip dengan chunk PNG asli:

- `IHET` seharusnya `IHDR`
- `ISAD` seharusnya `IDAT`
- `SEND` seharusnya `IEND`

CRC chunk-nya juga cocok dengan nama chunk PNG yang benar, bukan nama yang rusak. Jadi file ini adalah PNG yang disamarkan dan chunk type-nya diganti.

## Perbaikan PNG

Struktur yang dipulihkan:

1. Ganti fake JPEG/JFIF prefix dengan PNG signature.
2. Buat ulang chunk pertama sebagai `IHDR` dengan panjang 13 byte.
3. Ganti chunk `ISAD` menjadi `IDAT`.
4. Ganti chunk `SEND` menjadi `IEND`.

Script `solve.py` melakukan perbaikan ini secara otomatis dan menghasilkan `fixed.png`.

Setelah diperbaiki:

```bash
file fixed.png
```

Hasilnya:

```text
fixed.png: PNG image data, 810 x 110, 8-bit/color RGBA, non-interlaced
```

Gambar yang muncul adalah barcode panjang berbentuk rMQR berukuran 7 x 77 module.

## Decode rMQR

Simbol pada gambar adalah rMQR versi `R7x77`. Dari format information, level ECC yang dipakai adalah `M`.

Langkah decode yang dilakukan:

1. Ambil grid hitam-putih dari gambar. Ukuran gambar 810 x 110, bounding box barcode 770 x 70, sehingga satu module berukuran 10 px.
2. Bentuk grid 7 baris x 77 kolom.
3. Tandai area non-data: finder pattern, sub-finder, corner finder, timing, alignment, dan format information.
4. Baca data region memakai pola placement rMQR dari kanan ke kiri.
5. Balikkan mask rMQR:

```text
(y // 2 + x // 3) % 2 == 0
```

6. Ekstrak 32 codeword.
7. Parse payload rMQR:
   - mode `011` = byte mode
   - character count `10011` = 19 byte
   - payload 19 byte menghasilkan flag.

Payload yang terbaca:

```text
dalCTF{WhY_$O_L0N5}
```

## Cara menjalankan solver

```bash
python3 solve.py chall.png
```

Output:

```text
dalCTF{WhY_$O_L0N5}
```

## Flag

```text
dalCTF{WhY_$O_L0N5}
```
