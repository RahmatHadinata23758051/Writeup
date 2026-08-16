# Map Detective — OSINT Writeup

## Challenge Information

**Category:** OSINT / Geolocation
**Challenge:** Map Detective

### Description

> Look closely at the maritime views. Find the coordinates.

Flag format:

```text
0xV0ID{xx.xxx,xx.xxx}
```

Confirmed accepted flag:

```text
0xV01D{39.466,-0.324}
```

---

# 1. Initial Image Analysis

Challenge hanya memberikan sebuah street-level image tanpa metadata atau nama lokasi yang terlihat dengan jelas.

Karena itu, langkah pertama adalah melakukan **visual geolocation** dengan menginventarisasi objek yang dapat digunakan sebagai clue.

Beberapa karakteristik penting dari gambar:

* Jalan lebar di daerah perkotaan.
* Banyak pohon palem tinggi di sepanjang jalan.
* Cuaca dan vegetasi terlihat khas kawasan Mediterania.
* Terdapat area yang tampak seperti kawasan pantai atau maritime district.
* Marka jalan dan arsitektur terlihat khas Eropa.
* Di sisi kanan terdapat bangunan besar berwarna putih dengan gaya klasik/neoklasik.
* Bangunan memiliki kolom besar, cornice, balustrade, serta tower pada bagian sudut.
* Lingkungan di sekitarnya tampak seperti kawasan resort atau promenade tepi laut.

Clue paling berguna bukan pohon palemnya, karena karakteristik tersebut terlalu umum, melainkan **bangunan putih besar di sisi kanan gambar**.

---

# 2. Identifying the Country

Dari kombinasi:

```text
Mediterranean architecture
+ palm-lined boulevard
+ maritime environment
+ European road layout
```

wilayah pencarian dapat dipersempit ke kota-kota pesisir Mediterania.

Beberapa kandidat awal yang masuk akal antara lain:

```text
Spain
Portugal
Southern France
Italy
```

Namun gaya lingkungan perkotaan dan promenade paling konsisten dengan pesisir timur **Spanyol**.

Selanjutnya pencarian difokuskan pada kota-kota pesisir Spanyol.

---

# 3. Identifying the Landmark

Bangunan putih besar pada sisi kanan gambar menjadi landmark utama.

Ciri-cirinya:

```text
- large white façade
- classical columns
- symmetrical architecture
- corner pavilion/tower
- directly beside a palm-lined coastal road
```

Setelah membandingkan landmark hotel dan bangunan bersejarah di kawasan pesisir Spanyol, bangunan tersebut cocok dengan:

```text
Hotel Balneario Las Arenas
Las Arenas Balneario Resort
Valencia, Spain
```

Situs resmi hotel mencantumkan lokasinya di:

```text
Eugenia Viñes, 22–24
46011 Valencia
Spain
```

The Leading Hotels of the World juga mencantumkan Hotel Las Arenas pada alamat yang sama di Valencia.

---

# 4. Maritime Clue Confirmation

Clue pada challenge menggunakan kata:

```text
maritime views
```

Hal ini ternyata sangat relevan.

Las Arenas Balneario Resort memang berada di kawasan pantai Valencia. Sumber hotel/travel menyebut properti tersebut berada di **Las Arenas Beach**, sementara informasi akomodasi juga mencatat lokasinya berada di kawasan **Poblats Marítims**.

Dengan demikian kita memiliki beberapa kecocokan sekaligus:

```text
Challenge image
      │
      ├── Maritime environment
      ├── Palm trees
      ├── Wide coastal boulevard
      ├── Large classical white building
      │
      ▼
Hotel Balneario Las Arenas
      │
      ▼
Valencia, Spain
```

---

# 5. Street-Level Verification

Setelah landmark ditemukan, tahap berikutnya adalah mencocokkan lingkungan di sekitar hotel dengan challenge image.

Beberapa elemen yang harus diperhatikan:

### A. Hotel façade

Bangunan berada tepat di sisi jalan dan memiliki façade putih monumental.

### B. Palm trees

Terdapat jajaran pohon palem di median dan sisi jalan.

### C. Road orientation

Sudut pengambilan gambar menunjukkan kamera berada pada boulevard yang melewati bagian depan kompleks Las Arenas.

### D. Maritime district

Hotel berada dekat pantai sehingga konsisten dengan petunjuk challenge mengenai *maritime views*.

Dengan kombinasi clue tersebut, titik dapat dipersempit ke jalan tepat di depan Hotel Las Arenas di Valencia.

---

# 6. Coordinate Extraction

Setelah lokasi ditemukan, titik Street View/geolocation diperiksa di sekitar:

```text
Hotel Las Arenas
Eugenia Viñes
Valencia, Spain
```

Koordinat berada pada kisaran:

```text
Latitude  ≈ 39.466
Longitude ≈ -0.324
```

Challenge hanya meminta tiga angka desimal:

```text
xx.xxx,xx.xxx
```

Sehingga coordinate pair yang digunakan oleh challenge adalah:

```text
39.466,-0.324
```

---

# 7. Important Precision Note

Pada challenge geolocation, koordinat landmark dan posisi kamera dapat berbeda beberapa meter.

Artinya, jangan hanya mengambil koordinat pusat bangunan.

Yang dicari sebaiknya adalah:

```text
camera position / road position
```

bukan:

```text
hotel building centroid
```

Hal ini penting karena perbedaan beberapa puluh meter dapat mengubah digit ketiga desimal.

Dalam challenge ini, coordinate pair yang terbukti diterima oleh checker adalah:

```text
39.466,-0.324
```

---

# 8. Flag Construction

Coordinate:

```text
39.466,-0.324
```

Masukkan ke format challenge:

```text
0xV01D{LATITUDE,LONGITUDE}
```

Hasil:

```text
0xV01D{39.466,-0.324}
```

---

# OSINT Tracker

| #  | Investigation            | Method / Query                 | Result                              | Status |
| -- | ------------------------ | ------------------------------ | ----------------------------------- | ------ |
| 1  | Analisis lingkungan      | Visual inspection              | Coastal / maritime urban area       | ✅      |
| 2  | Identifikasi iklim       | Vegetation + architecture      | Mediterranean region                | ✅      |
| 3  | Cari negara              | Road + architecture comparison | Spain                               | ✅      |
| 4  | Landmark utama           | Analisis bangunan putih        | Luxury / historic coastal hotel     | ✅      |
| 5  | Identifikasi bangunan    | Landmark comparison            | Hotel Balneario Las Arenas          | ✅      |
| 6  | Verifikasi alamat        | Official hotel website         | Eugenia Viñes 22–24, Valencia       | ✅      |
| 7  | Verifikasi maritime clue | Location research              | Las Arenas Beach / Poblats Marítims | ✅      |
| 8  | Cocokkan jalan           | Street-level surroundings      | Palm-lined road cocok               | ✅      |
| 9  | Cari posisi kamera       | Map / Street View inspection   | Depan Hotel Las Arenas              | ✅      |
| 10 | Ekstrak latitude         | Coordinate inspection          | `39.466`                            | ✅      |
| 11 | Ekstrak longitude        | Coordinate inspection          | `-0.324`                            | ✅      |
| 12 | Submit flag              | Challenge checker              | Accepted                            | ✅      |

---

# Investigation Flow

```text
Challenge Image
      │
      ▼
Visual Recon
      │
      ├── Palm trees
      ├── Mediterranean weather
      ├── Coastal boulevard
      └── Distinctive white building
      │
      ▼
Search Mediterranean Coastal Cities
      │
      ▼
Spain
      │
      ▼
Valencia
      │
      ▼
Identify White Building
      │
      ▼
Hotel Balneario Las Arenas
      │
      ▼
Verify Address + Beach Location
      │
      ▼
Inspect Street Position
      │
      ▼
39.466, -0.324
      │
      ▼
0xV01D{39.466,-0.324}
```

---


**Flag:**

```text
0xV01D{39.466,-0.324}
```
