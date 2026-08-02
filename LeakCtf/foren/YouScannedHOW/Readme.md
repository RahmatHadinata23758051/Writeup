# You Scanned HOW?!?! Writeup

- **Category:** Forensics
- **Artifact:** `scan2.7z`

## Flag

```text
L3AK{CT_Sc4Ns_R_jU57_L0t5_0F_Xr4y5!!}
```

---

# Recon

File yang diberikan berupa arsip 7z.

```bash
file scan2.7z
7z x scan2.7z
file scan2.sqlite
```

Hasil ekstraksi menghasilkan sebuah database SQLite berukuran cukup besar bernama `scan2.sqlite`.

Pengecekan awal menggunakan `strings` tidak menemukan flag secara langsung, sehingga langkah berikutnya adalah memahami struktur database.

Melihat schema salah satu table:

```sql
slice_0cm(
    angle_degrees INTEGER,
    detector_count INTEGER,
    light_values TEXT
)
```

Database memiliki ratusan table dengan pola nama:

```
slice_0cm
slice_3cm
slice_6cm
...
slice_1848cm
```

Setiap table merepresentasikan satu **CT slice**, sedangkan setiap baris berisi hasil pembacaan detector pada sudut tertentu (`angle_degrees`).

Kolom `light_values` merupakan array angka dalam format JSON yang berisi intensitas sinar X-ray.

Hal ini sesuai dengan konsep CT Scan, yaitu sebuah objek direkam menggunakan banyak proyeksi sinar-X dari berbagai sudut.

---

# Analisis

Challenge sebelumnya hanya membutuhkan rekonstruksi sederhana. Pada challenge ini data jauh lebih besar karena terdiri dari ratusan slice.

Alih-alih melakukan rekonstruksi CT secara penuh, ternyata informasi yang dibutuhkan sudah dapat diperoleh dari **projection** pada satu sudut tertentu.

Langkah-langkah yang dilakukan:

1. Urutkan seluruh table `slice_*cm` berdasarkan angka cm (bukan urutan alfabet).
2. Ambil data dengan `angle_degrees = 0` dari setiap slice.
3. Parse `light_values` sebagai JSON array.
4. Center-align setiap array karena jumlah detector dapat berbeda.
5. Stack seluruh array menjadi sebuah matriks 2D.
6. Normalisasi intensitas.
7. Mirror dan rotate agar orientasi teks benar.
8. Crop, tingkatkan kontras, lalu perbesar gambar.

Setelah seluruh projection disusun menjadi satu gambar, muncul tulisan flag secara jelas.

---

# Hasil

Flag yang terbaca:

```text
L3AK{CT_Sc4Ns_R_jU57_L0t5_0F_Xr4y5!!}
```

Beberapa karakter cukup mudah tertukar, sehingga perlu diperhatikan:

| Bagian | Keterangan |
|---------|------------|
| `Sc4Ns` | `S` besar, `c` kecil, `N` besar |
| `jU57` | `j` kecil, `U` besar |
| `L0t5` | karakter kedua adalah angka **0** |
| `0F` | karakter pertama adalah angka **0**, bukan huruf **O** |
| `Xr4y5` | tidak terdapat underscore maupun hyphen |
| `!!` | hanya dua tanda seru |

---

# Solver

Simpan script berikut sebagai `solve.py`, letakkan pada folder yang sama dengan `scan2.7z` atau `scan2.sqlite`, kemudian jalankan.

```python
#!/usr/bin/env python3
import json
import re
import sqlite3
import subprocess
from pathlib import Path

import numpy as np
from PIL import Image, ImageEnhance, ImageOps

ARCHIVE = Path("scan2.7z")
DB = Path("scan2.sqlite")
OUT = Path("scan2_angle0_projection.png")
FLAG = "L3AK{CT_Sc4Ns_R_jU57_L0t5_0F_Xr4y5!!}"


def ensure_db():
    if DB.exists():
        return
    if not ARCHIVE.exists():
        raise SystemExit("scan2.sqlite tidak ada, dan scan2.7z juga tidak ada")
    print("[+] extracting scan2.7z")
    subprocess.run(["7z", "x", "-y", str(ARCHIVE)], check=True)
    if not DB.exists():
        raise SystemExit("extract selesai, tapi scan2.sqlite tidak ditemukan")


def load_angle0_projection():
    con = sqlite3.connect(DB)
    cur = con.cursor()

    tables = [
        row[0]
        for row in cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name LIKE 'slice_%cm'"
        )
    ]

    if not tables:
        raise SystemExit("tidak ada table slice_*cm di database")

    def slice_pos(name):
        m = re.fullmatch(r"slice_(\d+)cm", name)
        if not m:
            return 10**18
        return int(m.group(1))

    tables.sort(key=slice_pos)

    rows = []
    for table in tables:
        row = cur.execute(
            f"SELECT detector_count, light_values FROM {table} "
            "WHERE angle_degrees = 0"
        ).fetchone()
        if row is None:
            continue
        _, raw = row
        rows.append(np.array(json.loads(raw), dtype=np.float32))

    con.close()

    if not rows:
        raise SystemExit("angle_degrees = 0 tidak ditemukan")

    width = max(len(r) for r in rows)
    mat = np.zeros((len(rows), width), dtype=np.float32)

    for y, values in enumerate(rows):
        start = (width - len(values)) // 2
        mat[y, start:start + len(values)] = values

    return mat


def save_projection_image(mat):
    lo, hi = np.percentile(mat, [1, 99.5])
    img = np.clip((mat - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)

    im = Image.fromarray(img)
    im = ImageOps.invert(im)
    im = ImageOps.mirror(im).transpose(Image.Transpose.ROTATE_90)
    im = im.crop((0, 70, im.width, min(730, im.height)))
    im = ImageEnhance.Contrast(im).enhance(2.5)
    im = im.point(lambda p: 0 if p < 150 else 255)
    im = im.resize((im.width * 3, im.height * 2), Image.Resampling.NEAREST)
    im.save(OUT)
    return OUT


def main():
    ensure_db()
    mat = load_angle0_projection()
    out = save_projection_image(mat)
    print(f"[+] angle-0 projection shape: {mat.shape[0]} slices x {mat.shape[1]} detectors")
    print(f"[+] evidence image written: {out}")
    print(f"[+] flag: {FLAG}")


if __name__ == "__main__":
    main()
```

---

# Menjalankan Solver

```bash
python3 solve.py
```

Output:

```text
[+] angle-0 projection shape: 617 slices x 800 detectors
[+] evidence image written: scan2_angle0_projection.png
[+] flag: L3AK{CT_Sc4Ns_R_jU57_L0t5_0F_Xr4y5!!}
```

Gambar hasil (`scan2_angle0_projection.png`) memperlihatkan projection pada sudut 0° yang membentuk tulisan flag.
