# Pharry - Organized Writeup

## Flag

```text
GPNCTF{tH4nk_Y0U_T0_entropia_for_OR6ANI2ING_GPN!}
```

## Ringkasan

Challenge ini terlihat seperti satu file berisi data acak. Setelah dicek, memang tidak ada magic header, string flag, atau format file umum. Triknya bukan mencari teks langsung, tetapi melihat bagaimana data acaknya **diorganisasi**.

File memiliki ukuran `7,650,000` byte. Ukuran ini bisa dibagi tepat menjadi:

```text
408 chunk x 18,750 byte
```

Setiap chunk terlihat random, tetapi jumlah bit `1` di dalam chunk tidak random penuh. Kalau dihitung popcount per chunk, nilainya jatuh ke 6 cluster yang sangat jelas. Enam cluster ini adalah digit level `0` sampai `5`.

## Langkah Analisis

Pertama, file dicek sebagai raw data:

```bash
file data
strings -a data | grep GPNCTF
```

Tidak ada string flag langsung.

Kemudian distribusi byte dicek. Byte `0x00`, power-of-two, dan byte dengan popcount rendah muncul dengan pola yang terlalu rapi untuk data random biasa. Ini mengarah ke analisis popcount.

Setelah file dipecah menjadi chunk `18,750` byte, setiap chunk dihitung jumlah bit `1`-nya. Hasilnya membentuk 408 simbol dengan 6 level stabil. Contoh awal stream level:

```text
00550055042204401452042310004423...
```

Stream ini kemudian dibagi per 4 digit:

```text
0055 0055 0422 0440 1452 0423 1000 4423 ...
```

Dari titik ini terlihat bahwa flag tidak dimulai dari awal stream. Dua byte awal adalah noise/header. Mulai dari codeword ke-4, pasangan 4 digit membentuk satu karakter:

```text
low_nibble high_nibble
```

Contoh awal decode:

```text
1452 0423 -> 0x47 -> G
1000 4423 -> 0x50 -> P
1055 0423 -> 0x4e -> N
1440 0423 -> 0x43 -> C
1022 4423 -> 0x54 -> T
1052 0423 -> 0x46 -> F
1444 5523 -> 0x7b -> {
```

Jadi urutan nibble-nya adalah **low nibble dulu**, lalu **high nibble**.

## Tabel Decode

Tabel low nibble:

```text
1000 -> 0    1400 -> 1    1040 -> 2    1440 -> 3
1022 -> 4    1422 -> 5    1052 -> 6    1452 -> 7
1004 -> 8    1404 -> 9    1044 -> A    1444 -> B
1025 -> C    1425 -> D    1055 -> E    1455 -> F
```

Tabel high nibble yang muncul pada data:

```text
2223 -> 2
5223 -> 3
0423 -> 4
4423 -> 5
2523 -> 6
5523 -> 7
```

Setelah seluruh stream didecode dan dua byte awal dilewati, flag keluar sebagai:

```text
GPNCTF{tH4nk_Y0U_T0_entropia_for_OR6ANI2ING_GPN!}
```

## Solver

Solver final ada di `solve.py`. Cara menjalankan:

```bash
python3 solve.py
```

Output:

```text
GPNCTF{tH4nk_Y0U_T0_entropia_for_OR6ANI2ING_GPN!}
```
