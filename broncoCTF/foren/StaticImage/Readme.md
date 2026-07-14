# Static Image

- **CTF:** BroncoCTF
- **Category:** Forensics
- **Difficulty:** Medium
- **Flag:** `bronco{n0w_th4ts_dyn4m1c}`

## Triage

`static.mp4` adalah video MPEG-4 tanpa audio:

```text
Resolution : 300x300
Frame rate : 60 FPS
Duration   : 25 seconds
Frames     : 1500
Pixel fmt  : yuv420p
```

Satu frame hanya terlihat seperti TV static hitam-putih. Averaging seluruh video juga tidak mengeluarkan pesan karena sinyalnya tidak disimpan sebagai brightness tetap.

## Relasi Antar-Frame

Jumlah frame habis dibagi tiga:

```text
1500 / 3 = 500 triplet
```

Setiap unit diproses sebagai:

```text
A = frame[3k]
B = frame[3k + 1]
C = frame[3k + 2]
```

Frame diubah menjadi bitmap hitam-putih dengan threshold `128`, lalu frame pertama dan ketiga di-XOR:

```python
mask = (A >= 128) ^ (C >= 128)
```

Hasilnya punya dua state:

```text
blank  -> A dan C identik
active -> A XOR C membentuk satu glyph putih
```

Frame tengah `B` hanya menambah noise.

## Carrier

State berganti secara periodik:

```text
blank  sekitar 10 triplet
active sekitar 10 triplet
blank  sekitar 10 triplet
active sekitar 10 triplet
```

Satu glyph diulang selama satu run aktif. Karena itu mask hanya disimpan saat terjadi transisi:

```text
blank -> active
```

Ada 25 run aktif.

## Contact Sheet

Hasil XOR terbaca:

```text
b r o n c
o { n 0 w
_ t h 4 t
s _ d y n
4 m 1 c }
```

Gabungannya:

```text
bronco{n0w_th4ts_dyn4m1c}
```

Teksnya merupakan leetspeak dari `now thats dynamic`, sesuai permainan kata pada judul.

## Solver

```bash
python3 solve.py static.mp4
```

Output:

```text
[+] Active glyph runs: 25
[+] Flag: bronco{n0w_th4ts_dyn4m1c}
```

Simpan contact sheet:

```bash
python3 solve.py static.mp4 --dump glyphs.png
```

## Flag

```text
bronco{n0w_th4ts_dyn4m1c}
```
