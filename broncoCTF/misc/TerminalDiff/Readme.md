# Terminal Diff

## Challenge

**Category:** Misc  
**CTF:** BroncoCTF 2026

> I used to be too big picture, never focusing on the details (keeping track of like 90 things at once). Then, I starting looking into things a little bit too much (this phase only lasted like 7 days). Nowadays though, I am primed to look at things with just the right width (and height too). Anyways, here's the flag! You should be able to read it just fine, as long as you align with my mindset.

File yang diberikan cuma satu baris panjang berisi underscore, pola `/\/\`, marker arah, dan gambar Braille. Isi tersebut bukan ciphertext biasa. Data ini dibuat supaya ter-wrap menjadi tampilan terminal dengan ukuran tertentu.

## Analisis panjang data

Newline terakhir dibuang lebih dulu.

```bash
python3 - <<'PY'
from pathlib import Path
import sympy

s = Path("flag.txt").read_text().rstrip("\r\n")
print(len(s))
print(sympy.factorint(len(s)))
PY
```

Output:

```text
3395
{5: 1, 7: 1, 97: 1}
```

Panjang payload adalah:

```text
3395 = 5 × 7 × 97
```

Angka pada deskripsi mengarahkan ke dimensi terminal:

- “like 90 things at once” mengarah ke lebar sekitar 90 kolom.
- Faktor prima terdekat yang tersedia adalah `97`.
- “lasted like 7 days” memberi tinggi `7`.
- Kata “primed” menegaskan bahwa lebar dan tinggi yang dipakai adalah bilangan prima.

Jadi datanya terdiri dari lima frame terminal berukuran:

```text
97 kolom × 7 baris
```

## Membentuk ulang frame

Payload di-wrap setiap 97 karakter, lalu dibagi per tujuh baris.

```python
WIDTH = 97
HEIGHT = 7

rows = [
    payload[i:i + WIDTH]
    for i in range(0, len(payload), WIDTH)
]

frames = [
    rows[i:i + HEIGHT]
    for i in range(0, len(rows), HEIGHT)
]
```

Underscore dipakai sebagai spasi agar posisi karakter tidak hilang saat file disalin.

```python
print(row.replace("_", " "))
```

Setelah lima frame ditampilkan dengan ukuran yang benar, pola `/\/\` membentuk banner pixel. Satu pasangan `/\` dianggap sebagai satu pixel penuh. Marker berikut menunjukkan arah penyambungan fragmen:

```text
vvvvvvvvvv
^^^^^^^^^^^^^^
>>
<<
```

Frame-frame tersebut harus disejajarkan mengikuti marker arah. Prefix pada bagian atas langsung terbaca sebagai:

```text
bronco{r
```

Fragmen berikutnya melingkari gambar besar di tengah. Setelah arah dan orientasinya dinormalisasi, teks lengkapnya menjadi:

```text
bronco{resizing_the_whole_world}
```

Gambar besar di tengah sesuai dengan isi flag: terminal sedang “resizing the whole world”.

## Solver

Jalankan:

```bash
python3 solve.py flag.txt
```

Output akhirnya:

```text
<FLAG>bronco{resizing_the_whole_world}</FLAG>
```

## Flag

```text
bronco{resizing_the_whole_world}
```
