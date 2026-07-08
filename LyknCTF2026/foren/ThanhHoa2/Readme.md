# Thanh Hoa 2 — Forensics Writeup

**CTF:** LYKNCTF 2026  
**Category:** Forensics  
**Challenge:** Thanh Hoa 2  
**Description:** `36 Thanh Hoa`  
**Flag:** `LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}`

## TL;DR

File MP4 punya stream PNG bertipe `attached_pic`. Tepat setelah chunk `IEND` PNG tersebut, ada ZIP AES yang ditempel sampai akhir file. Password ZIP disimpan lewat LSB pada channel RGB cover dan terbaca sebagai `NEMCHUATHANHHOA`. Setelah ZIP dibuka, `flag.txt` berisi flag final.

## 1. Recon file

Mulai dari identifikasi container dan stream yang ada.

```bash
file lyknctf.mp4
ffprobe -v error -show_streams lyknctf.mp4
```

Output penting dari `ffprobe`:

```text
Stream #0: H.264 video, 1280x720
Stream #1: AAC audio, stereo
Stream #2: PNG, 1280x720, attached_pic=1
```

Stream ketiga bukan frame video biasa, tetapi cover PNG yang ditanam sebagai attached picture.

## 2. Ekstrak cover PNG

Cover bisa diekstrak langsung tanpa re-encode.

```bash
ffmpeg -v error -i lyknctf.mp4 -map 0:2 -c copy raw_cover.png
```

Hasilnya merupakan PNG valid berukuran `1280x720`. Secara visual cuma gambar bokeh, jadi petunjuknya tidak berada pada tampilan normal gambar.

## 3. Temukan ZIP yang ditempel ke MP4

Pencarian signature menunjukkan PNG berada dekat akhir file dan ada local header ZIP setelahnya.

```bash
grep -oba $'\x89PNG\r\n\x1a\n' lyknctf.mp4
grep -oba $'PK\x03\x04' lyknctf.mp4
```

Output pada file yang diberikan:

```text
28554246: PNG signature
28817164: PK\x03\x04
```

Chunk `IEND` PNG berakhir tepat sebelum offset ZIP. Arsip kemudian di-carve mulai dari offset `28817164`.

```bash
dd if=lyknctf.mp4 of=hidden.zip bs=1 skip=28817164 status=none
file hidden.zip
unzip -l hidden.zip
```

Isi arsip:

```text
Archive: hidden.zip
  Length      Name
---------     --------
       45     flag.txt
```

`flag.txt` menggunakan WinZip AES, jadi isinya belum bisa dibaca tanpa password.

## 4. Ambil password dari LSB cover

Bit terendah setiap channel gambar dibaca dengan urutan RGB. Setiap delapan bit digabungkan secara MSB-first menjadi satu byte.

```python
from PIL import Image

image = Image.open("raw_cover.png").convert("RGB")
bits = []

for r, g, b in image.getdata():
    bits.extend((r & 1, g & 1, b & 1))

message = bytearray()
for i in range(0, len(bits) - 7, 8):
    value = 0
    for bit in bits[i:i + 8]:
        value = (value << 1) | bit
    message.append(value)

print(bytes(message[:100]))
```

Outputnya langsung membentuk teks berulang:

```text
NEMCHUATHANHHOA NEMCHUATHANHHOA NEMCHUATHANHHOA ...
```

Password ZIP:

```text
NEMCHUATHANHHOA
```

Nama ini juga nyambung dengan deskripsi: `Nem chua Thanh Hoa` merupakan frasa yang disisipkan ke gambar, bukan password hasil tebakan dari judul.

## 5. Buka ZIP dan baca flag

Dengan `7z`:

```bash
7z x -pNEMCHUATHANHHOA hidden.zip
cat flag.txt
```

Output:

```text
LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}
```

## Solver otomatis

`solve.py` mengerjakan semua tahap berikut secara otomatis:

1. Mencari PNG terakhir di dalam MP4.
2. Mem-parse chunk PNG sampai `IEND`.
3. Mengambil ZIP yang ditempel setelah PNG.
4. Membaca LSB RGB untuk mendapatkan password.
5. Mendekripsi WinZip AES dan mengekstrak `flag.txt`.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py lyknctf.mp4
```

Output akhir:

```text
[+] PNG offset : 28554246
[+] ZIP offset : 28817164
[+] Password   : NEMCHUATHANHHOA
<FLAG>LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}</FLAG>
```
