# Signal Haze

## Informasi Challenge

| Field | Value |
|-------|-------|
| **Kategori** | Forensics |
| **Judul** | Signal Haze |

---

# Ringkasan

Challenge memberikan sebuah file audio berformat **Ogg Vorbis** berdurasi sekitar **115,2 detik**. Audio tersebut bukan berisi suara manusia, melainkan transmisi **Slow Scan Television (SSTV)**.

Dengan menganalisis header VIS pada sinyal SSTV, mode transmisi berhasil diidentifikasi sebagai **Martin M1 (VIS 44)**. Setelah seluruh sinyal FM didekode menjadi data piksel, diperoleh sebuah gambar berukuran **320 × 256** yang berisi flag challenge.

---

# File Challenge

Artefak yang diberikan:

```
transmission.ogg
```

Hasil identifikasi file:

```
Format      : Ogg Vorbis
Channel     : Mono
Sample Rate : 44.100 Hz
Durasi      : ±115,2 detik
```

---

# Analisis Awal

Magic bytes file diawali dengan:

```
OggS
```

yang mengidentifikasi file sebagai container Ogg.

Metadata audio menunjukkan stream:

```
Vorbis
Mono
44.100 Hz
```

Visualisasi spectrogram memperlihatkan pola yang sangat khas milik transmisi SSTV.

Urutan tone yang muncul adalah:

```
Leader     : 1900 Hz (300 ms)

Break      : 1200 Hz (10 ms)

Leader     : 1900 Hz (300 ms)

VIS Start  : 1200 Hz (30 ms)

8 VIS Bits : masing-masing 30 ms

VIS Stop   : 1200 Hz (30 ms)
```

Struktur tersebut sesuai dengan spesifikasi header SSTV.

---

# Identifikasi VIS Header

Setiap sel VIS dianalisis dengan membandingkan energi pada:

```
1100 Hz

dan

1300 Hz
```

Delapan bit yang diperoleh:

```
00110101
```

Encoding VIS menggunakan urutan **Least Significant Bit (LSB) terlebih dahulu**.

Dari tujuh bit data diperoleh:

```
44
```

Bit terakhir merupakan parity dan sesuai dengan spesifikasi SSTV.

Mode tersebut mengidentifikasi transmisi sebagai:

```
Martin M1
```

---

# Parameter Martin M1

Mode Martin M1 memiliki parameter berikut.

| Parameter | Nilai |
|-----------|-------|
| Resolusi | 320 × 256 |
| Urutan warna | Green → Blue → Red |
| Sync | 4,862 ms |
| Porch | 0,572 ms |
| Scan per channel | 146,432 ms |
| Separator | 0,572 ms |
| Total per baris | 446,446 ms |

Durasi total gambar juga sesuai.

```
Header
+
256 baris

=

0,910 s
+
256 × 0,446446 s

≈

115,200176 s
```

Nilai tersebut sangat dekat dengan durasi file audio sehingga semakin menguatkan identifikasi mode Martin M1.

---

# Proses Ekstraksi

Tahapan decoding dilakukan sebagai berikut.

### 1. Konversi Audio

File Ogg dikonversi menjadi WAV mono 44,1 kHz menggunakan:

```bash
ffmpeg
```

agar proses analisis sinyal lebih mudah dilakukan.

---

### 2. Validasi VIS

Header VIS dibaca untuk memastikan mode transmisi.

Hasil:

```
VIS value : 44

Parity    : valid
```

Sehingga decoder dapat menggunakan parameter Martin M1.

---

### 3. Demodulasi FM

Audio kemudian diproses menggunakan **Hilbert Transform** untuk memperoleh analytic signal.

Kemiringan fase (phase slope) pada setiap interval piksel digunakan untuk menghitung frekuensi carrier.

---

### 4. Konversi Frekuensi ke Intensitas

Standar Martin M1 menggunakan rentang:

```
1500 Hz
```

sebagai warna hitam dan

```
2300 Hz
```

sebagai warna putih.

Frekuensi setiap piksel dipetakan menjadi intensitas warna.

---

### 5. Rekonstruksi RGB

Setiap baris terdiri dari tiga channel warna:

```
Green

↓

Blue

↓

Red
```

Ketiga channel kemudian digabung sehingga menghasilkan gambar RGB berukuran:

```
320 × 256
```

Hasil akhir disimpan sebagai:

```
decoded_martin_m1.png
```

---

# Solver

Solver melakukan langkah berikut.

1. Membaca file Ogg.
2. Mengubah audio menjadi WAV mono.
3. Mengidentifikasi VIS header.
4. Memastikan mode Martin M1.
5. Mendemodulasi sinyal FM menggunakan Hilbert transform.
6. Mengubah frekuensi menjadi level intensitas.
7. Menyusun channel Green–Blue–Red.
8. Menyimpan hasil sebagai PNG.
9. Membaca flag dari gambar hasil decoding.

---

# Dependensi

Solver membutuhkan:

```
ffmpeg

Python 3

numpy

scipy

Pillow
```

---

# Cara Menjalankan

Jika file challenge bernama:

```
transmission.ogg
```

jalankan:

```bash
python3 solve.py transmission.ogg
```

Atau menggunakan nama file asli:

```bash
python3 solve.py '../data(1).file' -o decoded.png
```

---

# Output

Output solver:

```text
[+] VIS value: 44; parity bit: 1

[+] Decoded Martin M1 image:
    decoded_martin_m1.png

<FLAG>bushbash{gR0und_c0ntr0l}</FLAG>
```

---

# Alur Penyelesaian

```text
Ogg Vorbis Audio
        │
        ▼
Analisis Header SSTV
        │
        ▼
Decode VIS
        │
        ▼
Mode Martin M1
        │
        ▼
Hilbert Transform
        │
        ▼
FM Demodulation
        │
        ▼
Konversi Frekuensi
        │
        ▼
Green • Blue • Red
        │
        ▼
Rekonstruksi Gambar
        │
        ▼
Flag Terbaca
```

---

# Flag

```text
bushbash{gR0und_c0ntr0l}
```
