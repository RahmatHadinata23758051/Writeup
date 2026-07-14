# EX-BOOST

## Ringkasan

Tiga gambar style Lost Judgment dipakai sebagai petunjuk channel RGB dan indeks bitplane:

| Urutan | Style | Warna | Heat bar | Bitplane | Teks |
|---|---|---:|---:|---:|---|
| 1 | Tiger | Red | 1 | bit 0 | `F33L` |
| 2 | Snake | Green | 3 | bit 2 | `TH3` |
| 3 | Crane | Blue | 5 | bit 4 | `H34T` |

Urutan dibaca sebagai **RGB**, bukan urutan file yang diberikan. Karena indeks bit dimulai dari nol, heat level `1`, `3`, dan `5` menunjuk ke bit `0`, `2`, dan `4`.

Hasil ketiga bagian digabung tanpa spasi:

```text
F33L + TH3 + H34T
```

## Recon

File yang diberikan:

```text
Crane.png
Snake.png
Tiger.png
```

Ketiganya PNG RGBA biasa. Tidak ada metadata atau file tambahan yang relevan. Petunjuk utama ada pada kalimat:

```text
I much prefer the RGB trifecta.
But what's with the heat bar amount on each style?
```

Style dan channel-nya:

```text
Tiger -> Red
Snake -> Green
Crane -> Blue
```

Urutan RGB berarti:

```text
Tiger, Snake, Crane
```

## Bitplane yang dipakai

Heat bar pada masing-masing style menunjukkan level ganjil:

```text
Tiger = 1
Snake = 3
Crane = 5
```

Bitplane Python memakai indeks mulai dari nol:

```text
heat 1 -> bit 0
heat 3 -> bit 2
heat 5 -> bit 4
```

Rumus ekstraksinya:

```python
bit = (channel_value >> bit_index) & 1
```

Nilai `0` dibuat hitam dan nilai `1` dibuat putih.

## Ekstraksi manual dengan Python

```python
from PIL import Image

tests = [
    ("Tiger.png", 0, 0, "Tiger_R_bit0.png"),
    ("Snake.png", 1, 2, "Snake_G_bit2.png"),
    ("Crane.png", 2, 4, "Crane_B_bit4.png"),
]

for filename, channel, bit_index, output in tests:
    image = Image.open(filename).convert("RGB")
    selected = image.getchannel(channel)

    plane = selected.point(
        lambda value: 255 if ((value >> bit_index) & 1) else 0
    )

    plane.save(output)
```

Hasilnya terlihat langsung:

```text
Tiger R bit 0 -> F33L
Snake G bit 2 -> TH3
Crane B bit 4 -> H34T
```

## Solver

Dependency:

```bash
python3 -m pip install pillow
```

Tesseract dipakai untuk membaca hasil secara otomatis:

```bash
sudo apt install tesseract-ocr
```

Letakkan `solve.py` bersama ketiga gambar, lalu jalankan:

```bash
python3 solve.py
```

Output:

```text
[+] Tiger: channel=R heat=1 bit=0 -> extracted/Tiger_R_bit0.png
    OCR: F33L
[+] Snake: channel=G heat=3 bit=2 -> extracted/Snake_G_bit2.png
    OCR: TH3
[+] Crane: channel=B heat=5 bit=4 -> extracted/Crane_B_bit4.png
    OCR: H34T
<FLAG>bronco{F33LTH3H34T}</FLAG>
```

## Flag

```text
bronco{F33LTH3H34T}
```
