# guessystego2

**Category:** Forensics  
**Flag:** `sctf{1_l0v3_gu335y_st3g0_2}`

## Ringkas

File yang dikasih cuma `dist.zip`. Isinya satu PNG RGBA. Gambarnya kelihatan normal, tapi alpha channel-nya tidak sepenuhnya konstan: ada nilai `254` dan `255`. Karena gambar tetap terlihat opaque, bagian paling mencurigakan adalah LSB dari alpha channel.

## Recon

```bash
file dist.zip
unzip -l dist.zip
unzip -q dist.zip -d guessystego2_work
file guessystego2_work/dist.png
```

Output penting:

```text
dist.zip: Zip archive data
Archive: dist.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1601408  2026-05-25 01:51   dist.png

guessystego2_work/dist.png: PNG image data, 2200 x 845, 8-bit/color RGBA, non-interlaced
```

Pengecekan biasa tidak langsung ngasih flag:

```bash
strings -a guessystego2_work/dist.png | grep -Ei 'flag|ctf|sctf|qr'
exiftool guessystego2_work/dist.png
```

## Titik aneh

Alpha channel harusnya full `255` kalau gambar benar-benar opaque. Di file ini nilainya cuma `254` dan `255`.

```python
from PIL import Image
import numpy as np

im = Image.open('dist.png').convert('RGBA')
a = np.array(im)[:, :, 3]
print(np.unique(a, return_counts=True))
```

Hasilnya:

```text
254 -> 23844 pixels
255 -> 1835156 pixels
```

LSB alpha diekstrak:

```python
bits = (alpha & 1).reshape(-1)
```

Kalau divisualkan sebagai gambar asli, bit-bit itu muncul seperti strip panjang di bagian atas. Polanya bukan QR yang sudah berbentuk kotak; bitstream-nya diratakan dulu ke pixel pertama PNG.

## Ekstraksi QR

Karena deskripsi menyebut QR code, bitstream alpha dicoba di-reshape ke ukuran kotak. Script melakukan brute force ukuran `n x n`, mulai dari ukuran QR kecil sampai batas `sqrt(total_pixel)`.

Ukuran yang valid ketemu di `246 x 246`. QR tersebut decode ke:

```text
https://www.youtube.com/watch?v=dQw4w9WgXcQ/#sctf{1_l0v3_gu335y_st3g0_2}
```

Fragment URL berisi flag.

## Solver

```bash
python3 solve.py dist.zip
```

Output:

```text
sctf{1_l0v3_gu335y_st3g0_2}
```

## Kenapa bukan RGB LSB

RGB bitplane terlihat seperti noise natural gambar. Alpha channel beda sendiri karena hanya punya dua nilai yang secara visual tetap opaque. Nilai `254/255` adalah trik tipis: gambar tetap normal, tapi bit terakhirnya cukup untuk menyimpan QR yang sudah di-flatten.
