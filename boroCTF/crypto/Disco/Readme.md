# Disco - Cryptography Writeup

## Analisis
Diberikan sebuah gambar `chall.png` berukuran 400x300 piksel. Deskripsi challenge menyebutkan "The hexagonal colors are simply beautiful." yang memberikan petunjuk bahwa warna dalam format heksadesimal (RGB) adalah kunci penyelesaiannya.

Setelah memeriksa gambar, ditemukan 11 warna unik termasuk hitam (background). 10 warna lainnya membentuk blok-blok berukuran 100x100 piksel yang tersusun dalam grid.

Setiap warna terdiri dari tiga komponen RGB (Red, Green, Blue). Jika nilai desimal dari komponen-komponen ini dikonversi ke karakter ASCII, kita mendapatkan potongan string.

## Eksploitasi
Langkah-langkah untuk mendapatkan flag:
1. Ekstrak warna unik dari setiap blok 100x100 dalam grid 4x3 secara row-major.
2. Konversi setiap komponen RGB (R, G, B) menjadi karakter ASCII.
3. Gabungkan semua karakter tersebut hingga menemukan penutup flag `}`.

Warna-warna yang ditemukan:
- (98, 111, 114) -> `bor`
- (111, 67, 84) -> `oCT`
- (70, 123, 110) -> `F{n`
- (69, 118, 51) -> `Ev3`
- (114, 95, 108) -> `r_l`
- (48, 36, 101) -> `0$e`
- (95, 89, 111) -> `_Yo`
- (85, 52, 95) -> `U4_`
- (66, 101, 64) -> `Be@`
- (116, 125, 0) -> `t}`

Hasil penggabungan: `boroCTF{nEv3r_l0$e_YoU4_Be@t}`

## Script
```python
from PIL import Image

img = Image.open('chall.png')
pixels = img.load()

flag = ""
for y in range(0, 300, 100):
    for x in range(0, 400, 100):
        r, g, b = pixels[x, y]
        if (r, g, b) == (0, 0, 0): continue
        flag += chr(r) + chr(g) + chr(b)
        if '}' in flag:
            print(flag.strip('\x00'))
            break
```

Flag: `boroCTF{nEv3r_l0$e_YoU4_Be@t}`
