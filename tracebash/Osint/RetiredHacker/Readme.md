# Retired Hacker — OSINT Walkthrough

## Challenge

**Judul:** Retired Hacker  
**Kategori:** OSINT

> A leaked chat screenshot reveals an individual who walked away from the hacking scene. Investigate the person and identify the tram station where they got off on May 7, 2026.

Format flag:

```text
TBCTF{Tram_Station_Name}
```

Spasi pada nama halte harus diganti dengan underscore.

---

## TL;DR

Jalur investigasinya:

```text
Screenshot chat
→ profil Komoot
→ Jim Lee
→ handle jiml33t
→ posting Threads tanggal 7 Mei 2026
→ tulisan irigatii.ro
→ Calea Buziașului, Timișoara
→ Auchan Buziașului
→ halte Piața Gheorghe Domășneanu
```

Flag:

```text
TBCTF{Piața_Gheorghe_Domășneanu}
```

---

## 1. Menganalisis screenshot chat

File challenge berisi screenshot percakapan dengan seseorang yang mengaku sudah meninggalkan dunia hacking. Sekarang ia lebih sering melakukan aktivitas seperti hiking, bersepeda, dan berlari.

Petunjuk terpenting pada screenshot bukan username chat-nya, tetapi sebuah URL Komoot yang dibagikan langsung:

```text
https://www.komoot.com/user/5667624959835
```

Komoot adalah platform untuk mencatat aktivitas outdoor seperti hiking, cycling, dan running. Karena URL berisi ID pengguna yang spesifik, profil tersebut menjadi pivot pertama.

Query alternatif:

```text
"5667624959835"
"komoot.com/user/5667624959835"
```

---

## 2. Pivot dari Komoot ke identitas target

Profil Komoot tersebut menggunakan nama:

```text
Jim Lee
```

Dari profil dan jejak publik yang saling terhubung, ditemukan handle:

```text
jiml33t
```

Handle tersebut juga digunakan pada GitHub:

```text
https://github.com/jiml33t
```

Bio akun GitHub mengandung informasi seperti:

```text
Ex-Hacker
Avid Runner
```

Informasi ini cocok dengan isi screenshot:

- Target pernah aktif di dunia hacking.
- Target sekarang lebih fokus pada aktivitas outdoor.
- Deskripsi challenge menyebut seseorang yang meninggalkan hacking scene.

Kecocokan persona dan penggunaan handle yang sama membuat `jiml33t` menjadi kandidat target yang kuat.

Query yang dapat digunakan:

```text
"jiml33t"
site:github.com/jiml33t
site:threads.com/@jiml33t
```

---

## 3. Mencari aktivitas pada 7 Mei 2026

Challenge meminta lokasi target secara spesifik pada:

```text
May 7, 2026
```

Dengan handle `jiml33t`, pencarian dilanjutkan ke platform sosial lain. Ditemukan akun Threads dengan handle yang sama.

Pada posting yang relevan tanggal 7 Mei 2026, target menyebut bahwa ia:

1. Selesai melakukan aktivitas lari.
2. Naik trem.
3. Turun untuk menuju supermarket Prancis favoritnya.
4. Ingin membeli atau meminum kopi.

Posting tersebut juga menyertakan foto lingkungan sekitar. Pada salah satu bagian foto terlihat tulisan:

```text
irigatii.ro
```

Dari sini terdapat dua kelompok petunjuk:

- `irigatii.ro` digunakan untuk menentukan kota dan area.
- “French supermarket” digunakan untuk menentukan tujuan target.

Query yang membantu:

```text
site:threads.com/@jiml33t tram
site:threads.com/@jiml33t "French supermarket"
"jiml33t" "irigatii.ro"
```

---

## 4. Geolokasi melalui tulisan `irigatii.ro`

Tulisan `irigatii.ro` kemungkinan merupakan nama domain atau bisnis lokal. Pencarian terhadap domain tersebut mengarah ke sebuah lokasi di Romania.

Alamat landmark tersebut berada di:

```text
Calea Buziașului 13
Timișoara, Romania
```

Dengan demikian, kota target dapat dipersempit menjadi:

```text
Timișoara
```

Hal ini penting karena Timișoara memiliki jaringan trem yang aktif. Petunjuk target menaiki trem menjadi konsisten dengan kota tersebut.

Query yang dapat digunakan:

```text
"irigatii.ro" address
"irigatii.ro" "Calea Buziașului"
tram station near irigatii.ro Timisoara
```

---

## 5. Mengidentifikasi “French supermarket”

Caption menyebut sebuah supermarket Prancis.

Salah satu jaringan supermarket Prancis yang beroperasi di Romania adalah:

```text
Auchan
```

Di area Calea Buziașului terdapat:

```text
Auchan Buziașului
Calea Buziașului 11
Timișoara
```

Alamat tersebut sangat dekat dengan landmark `irigatii.ro` yang berada di nomor 13.

Kedekatan kedua alamat memperkuat kesimpulan bahwa supermarket yang dimaksud target adalah Auchan Buziașului.

```text
Auchan Buziașului : Calea Buziașului 11
irigatii.ro       : Calea Buziașului 13
```

Karena target mengatakan turun dari trem sebelum menuju supermarket tersebut, halte yang dicari harus berada di sekitar kompleks Auchan atau area AEM.

Query:

```text
Auchan Buziașului tram stop
tram station near Auchan Buziașului
site:smtt.ro Auchan Buziașului
```

---

## 6. Menentukan halte trem

Pencarian halte di sekitar Auchan Buziașului dan Calea Buziașului mengarah ke:

```text
Piața Gheorghe Domășneanu
```

Nama tersebut muncul pada jaringan transportasi Timișoara. Pada beberapa rute, lokasinya juga diberi penjelas seperti:

```text
Piața Gheorghe Domășneanu (Auchan)
```

atau dikaitkan dengan area:

```text
AEM
```

Bagian dalam tanda kurung hanya berfungsi sebagai penjelas lokasi atau arah platform. Nama halte utamanya tetap:

```text
Piața Gheorghe Domășneanu
```

Validasi sebaiknya dilakukan menggunakan situs operator transportasi resmi Timișoara, yaitu SMTT, bukan hanya mengandalkan label peta atau blog pihak ketiga.

Query validasi:

```text
site:smtt.ro "Piața Gheorghe Domășneanu"
site:smtt.ro "Gheorghe Domășneanu" tram
```

---

## 7. Perbedaan ejaan nama halte

Beberapa sumber pihak ketiga menulis nama belakangnya sebagai:

```text
Domășnean
```

Namun, sumber transportasi resmi menggunakan:

```text
Domășneanu
```

Karena flag challenge biasanya mengikuti nama resmi lokasi, versi dengan huruf `u` di akhir merupakan kandidat paling kuat.

Nama halte:

```text
Piața Gheorghe Domășneanu
```

Setelah spasi diganti underscore:

```text
Piața_Gheorghe_Domășneanu
```

---

## Flag

```text
TBCTF{Piața_Gheorghe_Domășneanu}
```

Apabila sistem flag tidak menerima karakter Unicode, fallback yang dapat diuji adalah:

```text
TBCTF{Piata_Gheorghe_Domasneanu}
```

Namun, jawaban utama tetap versi dengan diakritik karena mengikuti ejaan resmi.

---

## Referensi

- Komoot user profile  
  `https://www.komoot.com/user/5667624959835`

- GitHub `jiml33t`  
  `https://github.com/jiml33t`

- Threads post  
  `https://www.threads.com/@jiml33t/post/DYCg8B1iMAl/media`

- Irigații.ro  
  `https://irigatii.ro/`

- Auchan Romania store directory  
  `https://www.auchan.ro/magazine-auchan`

- SMTT Timișoara  
  `https://smtt.ro/linie-transport-public-9-r/`

---

## Kesimpulan

Challenge ini diselesaikan dengan teknik username reuse dan context chaining.

Satu URL Komoot dari screenshot membawa ke identitas Jim Lee dan handle `jiml33t`. Handle tersebut kemudian digunakan untuk menemukan posting tanggal 7 Mei 2026. Tulisan `irigatii.ro` pada foto menentukan area Calea Buziașului di Timișoara, sedangkan petunjuk “French supermarket” mengarah ke Auchan Buziașului.

Halte trem yang melayani area tersebut dan menggunakan nama resmi pada jaringan transportasi Timișoara adalah:

```text
Piața Gheorghe Domășneanu
```

Sehingga flag akhirnya:

```text
TBCTF{Piața_Gheorghe_Domășneanu}
```
