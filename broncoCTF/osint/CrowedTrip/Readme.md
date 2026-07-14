# Crowed Trip

**Category:** OSINT / Geolocation  
**Flag:** `bronco{3050}`

## Challenge

Bucky berangkat dari Santa Clara University, bergerak ke timur, lalu melewati dua lokasi yang ditampilkan pada foto. Craig ingin mengetahui total jarak perjalanan pulang-pergi dalam garis lurus atau *as the crow flies*. Hasil akhirnya harus dibulatkan ke kelipatan 25 mil terdekat.

## Ringkasan

Dua foto dapat diidentifikasi sebagai:

```text
Santa Clara University
→ Winnemucca, Nevada
→ Kansas City, Missouri
→ Santa Clara University
```

Total jarak garis lurus sekitar `3,057 mil`, yang dibulatkan ke kelipatan 25 terdekat menjadi `3,050`.

## 1. Menentukan titik awal

Deskripsi menyebut Bucky berangkat dari SCU. Titik awal yang masuk akal adalah area Santa Clara University di Santa Clara, California.

Untuk perhitungan jarak, koordinat pusat kampus sudah cukup karena hasil akhirnya dibulatkan ke kelipatan 25 mil.

## 2. Mengidentifikasi foto pertama

Petunjuk paling kuat pada foto pertama adalah billboard hotel:

```text
Super 8
Exit 176
```

Pencarian yang dapat digunakan:

```text
"Super 8" "Exit 176" Nevada
"Super 8 Winnemucca" exit 176
```

Hasilnya mengarah ke:

```text
Winnemucca, Nevada
```

Kota ini juga cocok dengan arah perjalanan ke timur dari California melalui koridor Interstate 80.

## 3. Mengidentifikasi foto kedua

Foto kedua memperlihatkan papan jalan dengan beberapa tujuan:

```text
Wichita
Downtown
St. Joseph
Des Moines
```

Kombinasi tujuan tersebut sangat khas persimpangan jalan bebas hambatan di sekitar:

```text
Kansas City, Missouri
```

Validasi dilakukan dengan melihat arah jalan utama:

- Wichita berada di selatan/barat daya.
- St. Joseph dan Des Moines berada di utara.
- Tulisan `Downtown` cocok dengan area metropolitan Kansas City.

## 4. Menghitung jarak garis lurus

Jarak yang digunakan:

```text
SCU → Winnemucca          ≈ 337 mil
Winnemucca → Kansas City  ≈ 1,231 mil
Kansas City → SCU         ≈ 1,489 mil
------------------------------------
Total                     ≈ 3,057 mil
```

Karena challenge meminta pembulatan ke kelipatan 25 mil terdekat:

```text
round(3057 / 25) × 25
= 122 × 25
= 3050
```

Perhitungan sederhana dengan Python:

```python
distance = 3057
rounded = round(distance / 25) * 25
print(rounded)
```

Output:

```text
3050
```

## Penyusunan Flag

```text
bronco{3050}
```
