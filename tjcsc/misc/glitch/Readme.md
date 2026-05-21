# misc/glitch - Writeup

## Ringkasan

File yang diberikan adalah PNG 1920x1080. Gambarnya terlihat seperti TV test pattern yang penuh noise/glitch, tetapi petunjuk `Do not resist the glitch` mengarah ke resistor color code.

Flag akhirnya:

```text
tjctf{D3S1GN+TECH_:)}
```

## Recon awal

Perintah awal yang dipakai:

```bash
file g*.png
strings -a g*.png | head
```

Hasil `file` menunjukkan bahwa artefak adalah PNG RGBA normal berukuran 1920x1080. Tidak ada flag langsung dari `strings`, dan chunk PNG juga hanya berisi struktur standar `IHDR`, banyak `IDAT`, lalu `IEND`.

## Observasi penting

Warna pada gambar bukan sembarang warna. Setelah melihat pikselnya, warna dominan yang muncul adalah warna-warna resistor:

| Warna | Digit |
|---|---:|
| black | 0 |
| brown | 1 |
| red | 2 |
| orange | 3 |
| yellow | 4 |
| green | 5 |
| blue | 6 |
| violet | 7 |
| grey | 8 |
| white | 9 |

Ada juga band emas di kanan. Dalam resistor, band emas dipakai sebagai tolerance, bukan digit. Band hitam sebelum emas adalah multiplier `x1`, jadi dua band pertama pada setiap strip bisa dibaca sebagai angka decimal ASCII.

## Cara decode

Setiap bar horizontal dianggap sebagai satu resistor. Dari kiri ke kanan:

1. band warna pertama = digit pertama
2. band warna kedua = digit kedua
3. band hitam = multiplier `10^0`
4. band emas = tolerance

Jadi cukup ambil dua digit pertama dari tiap bar, lalu ubah angka decimal itu ke ASCII.

Urutan yang didapat:

```text
68 51 83 49 71 78 43 84 69 67 72 95 58 41
```

Decode ASCII:

```text
D3S1GN+TECH_:)
```
