# BoroCTF - Eschew

## Flag

```text
BoroCTF{SAT_1s_H@rd}
```

## Inti solve

File yang diberikan adalah PNG tipis berisi teks yang sudah dibuat sangat miring/collapsed. Hint `flipped and flopped` bukan sekadar rotasi biasa. Gambar perlu dibalik kiri-kanan lalu direkonstruksi sebagai teks yang semula berada di bidang miring.

## Langkah

### 1. Recon cepat

```bash
file chall.png
exiftool chall.png
strings chall.png | grep -i 'BoroCTF'
```

Tidak ada flag langsung dari metadata atau strings. PNG hanya menyimpan gambar visual.

### 2. Flip kanan-kiri

Karena teksnya terbalik kanan-kiri, langkah pertama adalah horizontal mirror.

```python
from PIL import Image, ImageOps

img = Image.open("chall.png").convert("L")
mirrored = ImageOps.mirror(img)
mirrored.save("mirrored.png")
```

Setelah mirror, arah teks sudah benar, tapi masih collapsed menjadi garis diagonal.

### 3. Rectification / undo oblique transform

Teks terlihat seperti hasil affine/shear ekstrem. Dua arah diagonal dominan dipakai sebagai basis untuk melakukan inverse mapping. Setelah beberapa sweep parameter, bentuk huruf mulai muncul.

Solver menghasilkan beberapa output:
- `out_mirrored.png`
- `out_rectified.png`
- `out_readable.png`
- `out_threshold_sheet.png`

Threshold sheet dipakai untuk memastikan huruf yang masih blur/moire.

### 4. Read flag

Setelah rectification dan thresholding, teks terbaca sebagai:

```text
BoroCTF{SAT_1s_H@rd}
```

## Catatan

Jebakannya ada di asumsi prefix. Prefix harus mengikuti format challenge, yaitu `BoroCTF{...}`. Kalau OCR/visual read dipaksa ke format lain, hasilnya gampang salah walaupun transformasinya sudah mendekati.
