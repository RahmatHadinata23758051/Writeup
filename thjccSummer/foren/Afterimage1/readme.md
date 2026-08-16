# Afterimage1 - Writeup

## Ringkasan

File yang diberikan adalah `challenge.mp4`. Flag tidak muncul sebagai text biasa di file dan bukan berasal dari metadata C2PA. Jalur yang benar adalah mengambil informasi dari **efek afterimage** pada frame video: objek cahaya kecil bergerak cepat dan meninggalkan jejak temporal. Setelah frame diekstrak lalu perubahan antar-frame diakumulasi, pola tersembunyi dapat dibaca.

**Flag:**

```text
THJCC{v1d3o_F0ren51cS_qkrejnga}
```

---

## 1. Recon File

Cek tipe file:

```bash
file challenge.mp4
```

Output menunjukkan file adalah MP4 valid:

```text
challenge.mp4: ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
```

Cek stream video/audio:

```bash
ffprobe -v error -show_format -show_streams challenge.mp4
```

Informasi penting:

* Codec video: H.264
* Resolusi: `1280x720`
* Frame rate: `24 FPS`
* Jumlah frame: `240`
* Audio: AAC, `48000 Hz`, stereo
* Durasi: sekitar 10 detik

Karena judul challenge adalah **Afterimage1**, analisis diarahkan ke perubahan antar-frame, bukan hanya mencari informasi pada satu frame statis.

---

## 2. Triage Cepat

Cari flag langsung dari raw bytes:

```bash
strings -a challenge.mp4 | grep -Ei 'THJCC|flag|ctf|{'
```

Tidak ditemukan flag yang valid.

Yang muncul justru metadata C2PA/SynthID seperti:

```text
urn:c2pa:4adeac53-4fe2-35e1-1656-4237d7c2d5ac
6a6aafee-32f5-49a8-86fc-4581cb57f176
019c34d3-733f-7a47-b917-50dd38f41ece
```

UUID tersebut sempat terlihat seperti kandidat flag, tetapi semuanya salah saat disubmit. Oleh karena itu, metadata C2PA diperlakukan sebagai **red herring**.

Cek metadata tambahan:

```bash
exiftool challenge.mp4
```

Tidak ada field yang secara langsung menyimpan flag. Metadata hanya mengarah ke informasi generative media / SynthID.

---

## 3. Extract Frame

Semua frame diekstrak agar dapat dianalisis satu per satu:

```bash
mkdir -p frames
ffmpeg -hide_banner -i challenge.mp4 -vsync 0 frames/%04d.png
```

Kemudian dibuat contact sheet untuk melihat perubahan besar antar-frame:

```bash
python3 - <<'PY'
from PIL import Image, ImageDraw
import glob, math

files = sorted(glob.glob('frames/*.png'))[::10]
thumbs = []

for i, f in enumerate(files):
    im = Image.open(f).resize((256, 144))
    d = ImageDraw.Draw(im)
    d.text((6, 6), str(i * 10 + 1).zfill(3), fill=(255, 255, 255))
    thumbs.append(im)

cols = 4
rows = math.ceil(len(thumbs) / cols)

out = Image.new('RGB', (cols * 256, rows * 144), 'black')

for i, im in enumerate(thumbs):
    out.paste(im, ((i % cols) * 256, (i // cols) * 144))

out.save('sheet10.png')
PY
```

Dari contact sheet terlihat adanya banyak titik cahaya kecil yang bergerak atau menyala pada frame-frame tertentu.

Karena titik-titik tersebut tersebar di beberapa frame, teks tidak dapat dibaca dengan baik dari satu frame saja.

---

## 4. Analisis Afterimage

Karena flag disembunyikan secara temporal, frame perlu digabung dengan metode yang menonjolkan perubahan cahaya.

Proses yang digunakan:

1. Mengubah frame menjadi grayscale/luminance.
2. Menghitung perbedaan dengan frame sebelumnya.
3. Mengambil area yang mengalami perubahan signifikan.
4. Memfokuskan pada objek bercahaya hangat/oranye.
5. Mengakumulasi seluruh perubahan.
6. Menggunakan normalisasi log agar jejak cahaya yang redup tetap terlihat.

Script rekonstruksi:

```python
import cv2
import numpy as np

VIDEO = 'challenge.mp4'
OUT = 'afterimage_acc.png'

cap = cv2.VideoCapture(VIDEO)
prev = None
acc = None

while True:
    ok, frame = cap.read()
    if not ok:
        break

    frame = frame.astype(np.float32)

    # luminance untuk motion/difference
    gray = cv2.cvtColor(
        frame.astype(np.uint8),
        cv2.COLOR_BGR2GRAY
    ).astype(np.float32)

    # channel BGR
    b, g, r = cv2.split(frame)

    # titik flag lebih dominan hangat/terang
    # dibanding background biru-ungu
    warm = np.maximum((r + g) - (1.35 * b), 0)
    bright = np.maximum(gray - 90, 0)

    if prev is None:
        prev = gray
        acc = np.zeros_like(gray, dtype=np.float32)
        continue

    diff = cv2.absdiff(gray, prev)

    # motion + cahaya hangat
    mask = (diff > 6).astype(np.float32)
    signal = warm * bright * mask

    acc += signal
    prev = gray

cap.release()

# log scale agar afterimage yang redup ikut terlihat
acc = np.log1p(acc)
acc = acc / acc.max() * 255
acc = acc.astype(np.uint8)

# sedikit perjelas
acc = cv2.equalizeHist(acc)

cv2.imwrite(OUT, acc)

print('[+] saved', OUT)
```

Jalankan:

```bash
python3 solve_afterimage.py
```

Hasilnya menyatukan jejak cahaya yang sebelumnya tersebar di berbagai frame. Dari akumulasi tersebut, pattern text mulai terlihat.

---

## 5. Memperjelas Hasil

Jika hasil masih terlalu redup, threshold dan contrast dapat dinaikkan:

```bash
python3 - <<'PY'
import cv2

img = cv2.imread('afterimage_acc.png', 0)

img = cv2.GaussianBlur(img, (3, 3), 0)
img = cv2.normalize(
    img,
    None,
    0,
    255,
    cv2.NORM_MINMAX
)

_, th = cv2.threshold(
    img,
    145,
    255,
    cv2.THRESH_BINARY
)

cv2.imwrite('afterimage_threshold.png', th)

print('[+] saved afterimage_threshold.png')
PY
```

Setelah rekonstruksi dan peningkatan contrast, bagian teks yang terbaca adalah:

```text
v1d3o_F0ren51cS_qkrejnga
```

Challenge menggunakan prefix `THJCC{...}`, sehingga flag final adalah:

```text
THJCC{v1d3o_F0ren51cS_qkrejnga}
```

---

## Flag

```text
THJCC{v1d3o_F0ren51cS_qkrejnga}
```
