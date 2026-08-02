# Occultation Window Writeup

## Ringkasan

Challenge menyediakan tiga buah artefak:

```text
asset.tle
contacts.csv
relay_station.txt
```

`contacts.csv` berisi **15.000 laporan posisi** satelit pada tanggal **1 Agustus 2026**. Sebagian besar laporan merupakan data palsu.

Untuk menentukan laporan yang valid, challenge memberikan dua syarat:

1. Posisi latitude dan longitude pada laporan harus sesuai dengan hasil propagasi orbit **AL-7** dari TLE dengan toleransi maksimal **0.05°**.
2. Pada timestamp tersebut, satelit harus terlihat dari stasiun **ALE-DSR-04** dengan elevasi minimal **10°**.

Setelah kedua filter diterapkan, tersisa **29 laporan valid**.

Token dari laporan tersebut jika diurutkan berdasarkan waktu membentuk flag:

```text
uctf{gr0und_tr4ck_n3v3r_l13s}
```

---

# File Challenge

```text
asset.tle
contacts.csv
relay_station.txt
```

Pemeriksaan awal:

```bash
$ file *

asset.tle:         ASCII text
contacts.csv:      CSV ASCII text
relay_station.txt: ASCII text
```

Jumlah data:

```bash
$ wc -l contacts.csv

15001 contacts.csv
```

Baris pertama merupakan header sehingga terdapat **15.000 laporan posisi**.

---

# Analisis Awal

## TLE Asset

```text
ASSET AL-7
1 99001U 26001A   26213.00000000  .00000000  00000-0  10000-3 0    10
2 99001  53.0000 182.4082 0011000  41.4178 259.3121 15.20000000  1003
```

Parameter penting yang digunakan:

| Parameter | Nilai |
|-----------|-------|
| Epoch | 2026-08-01 00:00:00 UTC |
| Inclination | 53.0000° |
| RAAN | 182.4082° |
| Eccentricity | 0.0011000 |
| Argument of Perigee | 41.4178° |
| Mean Anomaly | 259.3121° |
| Mean Motion | 15.2 orbit/hari |
| B* | 1.0×10⁻⁴ |

---

## Relay Station

```text
Latitude      : 48.6921° N
Longitude     : 6.1844° E
ECEF          : (4193.807, 454.438, 4768.185) km
Horizon Mask  : 10°
Fix Accuracy  : 0.05°
Time Standard : UTC
```

Karena seluruh timestamp berada pada hari yang sama dengan epoch TLE, propagasi hanya dilakukan untuk rentang satu hari.

---

# Analisis

Token pada `contacts.csv` tidak dapat digunakan untuk membedakan laporan valid dan palsu karena seluruh token menggunakan alfabet yang sama dengan format flag.

Oleh karena itu, proses penyaringan sepenuhnya bergantung pada data orbit.

Langkah analisis:

1. Membaca elemen orbit dari `asset.tle`.
2. Membaca koordinat stasiun dari `relay_station.txt`.
3. Memproses setiap laporan pada `contacts.csv`.
4. Melakukan propagasi orbit menggunakan **SGP4**.
5. Mengubah koordinat TEME menjadi ECEF menggunakan **GMST**.
6. Mengubah ECEF menjadi koordinat geodetik WGS84.
7. Menghitung selisih posisi terhadap laporan.
8. Menghitung sudut elevasi satelit terhadap stasiun.
9. Mengambil token hanya jika memenuhi seluruh syarat.

Implementasi awal menggunakan model Kepler dua benda menghasilkan prefix flag yang benar, tetapi galat posisi meningkat sepanjang hari karena tidak memperhitungkan perturbasi orbit.

Implementasi akhir menggunakan **SGP4 near-Earth** sehingga galat posisi berada pada kisaran **0.0002°**, jauh di bawah toleransi challenge.

---

# Analisis Dynamic

Setelah seluruh laporan diproses menggunakan SGP4 dan difilter berdasarkan posisi serta elevasi, diperoleh lima window observasi.

| Window (UTC) | Token |
|--------------|-------|
| 00:46:00 – 00:49:45 | `uctf{g` |
| 17:51:07 – 17:55:12 | `r0und_` |
| 19:29:00 – 19:35:07 | `tr4ck_` |
| 21:09:13 – 21:12:45 | `n3v3r_` |
| 22:47:20 – 22:52:34 | `l13s}` |

Menggabungkan seluruh token berdasarkan urutan timestamp menghasilkan:

```text
uctf{gr0und_tr4ck_n3v3r_l13s}
```

Ringkasan hasil:

```text
matched contacts: 29
uctf{gr0und_tr4ck_n3v3r_l13s}
```

Seluruh kontak yang lolos memiliki galat posisi sekitar **0.00018°–0.00027°**, sehingga jauh di bawah batas toleransi **0.05°**.

---

# Algoritma Validasi

Challenge tidak menggunakan proses encoding terhadap token.

Penyembunyian dilakukan melalui pemalsuan posisi satelit.

Untuk setiap laporan pada waktu **t**:

## Propagasi Orbit

```text
rTEME(t) = SGP4(TLE, t − epoch)
```

---

## Konversi ke ECEF

```text
rECEF(t) = R3(GMST(t)) × rTEME(t)
```

---

## Konversi ke WGS84

```text
(latitude, longitude) =
ECEF_to_WGS84(rECEF)
```

---

## Error Posisi

Galat dihitung menggunakan pemisahan sudut pada permukaan bumi.

```text
position_error =
angle(
    reported_position,
    predicted_position
)
```

---

## Elevasi

Vektor line-of-sight:

```text
ρ =
rsatellite
−
rstation
```

Sudut elevasi:

```text
elevation =
asin(
dot(ρ, up)
/ |ρ|
)
```

---

## Filter

Laporan diterima apabila:

```text
position_error ≤ 0.05°

elevation ≥ 10°
```

Token dari laporan yang lolos kemudian diurutkan berdasarkan timestamp.

---

# Penyusunan Solve Script

`solve.py` dibuat tanpa dependency eksternal dan terdiri dari beberapa komponen utama:

- parser TLE beserta implied-decimal B*;
- propagator SGP4 near-Earth menggunakan konstanta WGS-72;
- konversi TEME ke ECEF menggunakan GMST;
- konversi ECEF ke koordinat geodetik WGS84;
- perhitungan angular separation;
- perhitungan sudut elevasi terhadap stasiun;
- filter posisi dan horizon mask;
- penyusunan token secara kronologis.

Script juga menampilkan setiap kontak yang lolos beserta timestamp, token, galat posisi, dan elevasi sehingga hasil dapat diverifikasi secara langsung.

---

# Cara Menjalankan

Pastikan seluruh file berada pada direktori yang sama.

```text
asset.tle
contacts.csv
relay_station.txt
solve.py
```

Jalankan:

```bash
chmod +x solve.py

./solve.py
```

atau

```bash
python3 solve.py
```

Contoh bagian akhir output:

```text
2026-08-01T22:52:34Z
token=}
error=0.000210 deg
elevation=21.091 deg

matched contacts: 29

uctf{gr0und_tr4ck_n3v3r_l13s}
```

---

# Flag

```text
uctf{gr0und_tr4ck_n3v3r_l13s}
```
