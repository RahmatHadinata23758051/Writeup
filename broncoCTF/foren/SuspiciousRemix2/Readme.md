# Suspicious Remix 2

## Ringkasan

Flag tidak ditanam langsung sebagai pola audio. File WAV dipakai sebagai cover file `steghide`, sedangkan password-nya disembunyikan pada bitplane gambar.

Alurnya:

```text
tolerate_this.png
  -> Red channel, bit 2
  -> "Password = release year the non-OST song was from"
  -> gambar Rick Astley / Never Gonna Give You Up
  -> tahun rilis 1987
  -> steghide extract sg_remix2.wav
  -> flag
```

## Initial recon

```bash
file tolerate_this.png sg_remix2.wav
```

Output:

```text
tolerate_this.png: PNG image data, 500 x 409, 8-bit/color RGBA, non-interlaced
sg_remix2.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM,
               16 bit, stereo 48000 Hz
```

`strings` dan metadata tidak langsung membocorkan flag. Deskripsi menyebut dua hal yang cukup spesifik:

```text
more hide-n
typing the steg command
```

Ini mengarah ke `steghide`, yang memang mendukung WAV sebagai cover file. Masalah berikutnya tinggal mencari passphrase dari gambar.

## Memeriksa bitplane gambar

Gambar memiliki empat channel RGBA. Seluruh bitplane bisa diperiksa dengan loop sederhana:

```python
from PIL import Image

image = Image.open("tolerate_this.png").convert("RGBA")

for channel_name in "RGBA":
    channel = image.getchannel(channel_name)

    for bit in range(8):
        plane = channel.point(
            lambda value, bit=bit:
                255 if ((value >> bit) & 1) else 0
        )

        plane.save(f"{channel_name}_bit{bit}.png")
```

Bitplane yang berisi teks adalah:

```text
Red channel, bit 2
```

Ekstraksi yang lebih langsung:

```python
from PIL import Image, ImageOps

image = Image.open("tolerate_this.png").convert("RGBA")
red = image.getchannel("R")

plane = red.point(
    lambda value: 255 if ((value >> 2) & 1) else 0
).convert("L")

ImageOps.invert(plane).save("R_bit2.png")
```

Teks tersembunyinya:

```text
Password = release year the non-OST song was from
```

Teks dibuat diagonal, jadi OCR mentah kurang stabil. Rotasi sekitar 25–35 derajat membuat Tesseract membacanya dengan benar.

## Menentukan password

Gambar utama berasal dari video musik Rick Astley, **Never Gonna Give You Up**. Lagu tersebut dirilis pada 1987, sehingga password `steghide` adalah:

```text
1987
```

Keterangan `non-OST` menegaskan bahwa tahun yang diminta adalah tahun rilis lagunya, bukan tahun rilis soundtrack atau media lain yang memakai lagu tersebut.

## Ekstraksi dari WAV

Ekstrak payload dengan `steghide`:

```bash
steghide extract \
  -sf sg_remix2.wav \
  -p 1987 \
  -xf extracted_payload.bin \
  -f
```

Lalu baca payload:

```bash
cat extracted_payload.bin
```

Output:

```text
bronco{7h3y_g07_y0u_4g4in_didn'7_7h3y?}
```

## Solver

Dependency:

```bash
python3 -m pip install pillow
sudo apt install steghide tesseract-ocr
```

Tesseract bersifat opsional. Tanpa Tesseract, solver tetap membuat `R_bit2.png` dan memakai password yang sudah diperoleh dari analisis.

Jalankan:

```bash
python3 solve.py sg_remix2.wav tolerate_this.png
```

Output yang diharapkan:

```text
[+] Hidden hint saved to: R_bit2.png
[+] OCR hint: Password = release year the non-OST song was from
[*] Trying steghide password: 1987
[+] Payload extracted: extracted_payload.bin
<FLAG>bronco{7h3y_g07_y0u_4g4in_didn'7_7h3y?}</FLAG>
```

Jika password utama gagal, solver juga menyediakan fallback brute-force tahun:

```bash
python3 solve.py sg_remix2.wav tolerate_this.png --bruteforce-years
```

## Flag

```text
bronco{7h3y_g07_y0u_4g4in_didn'7_7h3y?}
```
