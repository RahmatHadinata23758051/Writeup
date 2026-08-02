# Writeup — Quiet Twin

## Flag

```text
uctf{d8c1a2f47b6e9031}
```

---

# Ringkasan

Challenge menyediakan sebuah arsip berisi **16 hasil pemindaian LiDAR** dalam format **PLY** beserta sebuah file **calibration_log.json**.

Setiap file PLY hanya menyimpan koordinat lokal (`x`, `y`, `z`), sehingga seluruh scan harus ditransformasikan ke koordinat dunia menggunakan **matriks rotasi (R)** dan **vektor translasi (t)** yang terdapat pada log kalibrasi.

Satu-satunya anomali terdapat pada **scan_09.ply**. Log menunjukkan bahwa transformasi aktif menggunakan **E09_ACTIVE_BAD**, namun juga menyediakan **E09** sebagai `fallback_candidate`.

Catatan operator menyebutkan adanya **calibration drift** pada unit 09 dan snapshot lama yang dipertahankan untuk rollback. Menggunakan transformasi fallback menghasilkan digital twin yang kembali membentuk cargo bay secara utuh. Pada dinding ujung dengan koordinat X terbesar terlihat token yang diukir menggunakan kumpulan titik.

---

# Initial Recon

Lihat isi arsip:

```bash
unzip -l quiet_twin.zip
```

Isi utama:

```text
calibration_log.json
scan_01.ply
scan_02.ply
...
scan_16.ply
```

Ekstrak seluruh file:

```bash
mkdir quiet_twin
unzip quiet_twin.zip -d quiet_twin
```

Identifikasi format:

```bash
file quiet_twin/*
```

Periksa header salah satu file PLY:

```bash
head -n 10 quiet_twin/scan_01.ply
```

Output:

```text
ply
format ascii 1.0
element vertex 21153
property float x
property float y
property float z
end_header
```

PLY hanya menyimpan koordinat titik tanpa warna, normal vector, face, maupun metadata lain.

Pencarian string juga tidak menemukan flag.

```bash
grep -RaiE 'uctf|flag|token' quiet_twin
```

---

# Membaca Log Kalibrasi

Periksa konfigurasi scan ke-09.

```bash
jq '.scans["scan_09.ply"], .operator_notes' \
quiet_twin/calibration_log.json
```

Output:

```json
{
  "active_extrinsic": "E09_ACTIVE_BAD",
  "fallback_candidate": "E09"
}
```

```text
firmware 5.17 pushed at 22:41
pose calibration drift warning on unit-09
legacy snapshot retained for rollback
```

Berbeda dengan scan lainnya, hanya `scan_09.ply` yang memiliki **fallback_candidate**.

Hal ini mengindikasikan bahwa transformasi aktif memang bermasalah.

---

# Rekonstruksi Point Cloud

Setiap extrinsic menyimpan:

- matriks rotasi **R (3×3)**
- vektor translasi **t (3×1)**

Transformasi titik dilakukan menggunakan:

```text
p_world = R × p_local + t
```

Dalam NumPy:

```python
world_points = local_points @ R.T + t
```

Seluruh scan menggunakan transformasi aktif, kecuali scan ke-09 yang menggunakan fallback.

```python
extrinsic_name = scan_info.get(
    "fallback_candidate",
    scan_info["active_extrinsic"],
)
```

---

# Validasi Hasil Rekonstruksi

Menggunakan transformasi aktif (`E09_ACTIVE_BAD`) menghasilkan batas scene:

```text
min = [-4.0119, -2.0154, -0.1192]
max = [ 4.4338,  4.1001,  3.3062]
```

Terlihat sebagian point cloud bergeser jauh hingga **y ≈ 4.1 meter**, tidak konsisten dengan scan lainnya.

Menggunakan transformasi fallback (`E09`) menghasilkan:

```text
min = [-4.0119, -2.0159, -0.0152]
max = [ 4.0168,  2.0158,  3.0172]
```

Ukuran ini sesuai dengan bentuk cargo bay berukuran sekitar:

```text
8 × 4 × 3 meter
```

Jumlah total titik setelah seluruh scan digabung:

```text
253509 points
```

---

# Menemukan Token

Tulisan berada pada dinding dengan koordinat **X terbesar**.

Dinding dapat dipilih menggunakan toleransi sekitar 22 cm.

```python
wall = points[
    points[:,0] > points[:,0].max() - 0.22
]
```

Karena dinding tegak lurus terhadap sumbu X, seluruh titik diproyeksikan ke bidang **YZ**.

Area tulisan berada pada:

```text
Y = -1.90 ... 1.90
Z =  1.04 ... 1.52
```

Hasil proyeksi memperlihatkan tulisan:

```text
uctf{d8c1a2f47b6e9031}
```

Karakter setelah `a2` dipastikan merupakan huruf **f**, bukan angka **1**, setelah setiap glyph dipisahkan berdasarkan celah horizontal.

---

# Segmentasi dan OCR

Solver membuat histogram jumlah titik terhadap koordinat **Y** pada area tulisan.

Histogram kemudian dihaluskan menggunakan **moving window** sebanyak sembilan bin.

Setiap rentang padat dianggap sebagai satu karakter.

Format flag terdiri dari:

```text
uctf{ + 16 hexadecimal + }
```

Setelah seluruh karakter dipisahkan, lima glyph pertama (`uctf{`) dan glyph terakhir (`}`) diabaikan.

Enam belas glyph payload dirender secara terpisah kemudian dibaca menggunakan **Tesseract** dengan whitelist:

```text
0123456789abcdef
```

Konfigurasi OCR:

```text
--psm 13
```

Jika gagal mengenali glyph tertentu, solver menggunakan fallback:

```text
--psm 10
```

Payload yang diperoleh:

```text
d8c1a2f47b6e9031
```

---

# Menjalankan Solver

## Dependensi Python

```bash
python3 -m pip install numpy pillow
```

## Dependensi Sistem

```bash
sudo apt install tesseract-ocr
```

Jalankan solver:

```bash
python3 solve.py quiet_twin.zip
```

Atau tentukan direktori output:

```bash
python3 solve.py quiet_twin.zip -o quiet_twin_output
```

---

# Hasil

Output solver:

```text
[+] merged points       : 253509
[+] calibration rollback: scan_09.ply: E09_ACTIVE_BAD -> E09
[+] scene bounds        : min=[-4.0118747  -2.015935   -0.01520395], max=[4.0168056 2.0158126 3.017222 ]
[+] reconstructed PLY   : quiet_twin_output/reconstructed_scene.ply
[+] token render        : quiet_twin_output/authorization_token.png
[+] token               : d8c1a2f47b6e9031

uctf{d8c1a2f47b6e9031}
```

---

# Flag

```text
uctf{d8c1a2f47b6e9031}
```
