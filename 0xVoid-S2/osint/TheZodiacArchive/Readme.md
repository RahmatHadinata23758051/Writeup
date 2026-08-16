# The Zodiac Archive — OSINT Writeup

## Challenge

**Category:** OSINT
**Challenge:** The Zodiac Archive

> A private collector claims to possess four original letters attributed to the Zodiac Killer. Although all four appear authentic, investigators believe one contains a historical inconsistency. Examine the scans, verify the historical details using publicly available sources, and identify the forged document.

Flag format:

```text
0xV0ID{YEAR_NAME}
```

Final flag:

```text
0xV0ID{1975_BICENTENNIAL}
```

---

# 1. Initial Recon

Challenge memberikan sebuah arsip:

```text
letters.zip
```

Isi arsip dapat diperiksa menggunakan:

```bash
unzip -l letters.zip
```

Hasilnya terdapat empat scan utama:

```text
letter_1.png
letter_2.png
letter_3.png
letter_4.png
```

Karena challenge mengatakan keempat surat tampak autentik tetapi salah satunya memiliki **historical inconsistency**, fokus analisis bukan pada steganografi atau manipulasi file, melainkan mencari objek di dalam scan yang tidak mungkin berasal dari periode yang diklaim.

Keempat dokumen mengarah pada periode **1971**. Oleh karena itu, setiap detail visual seperti perangko, tarif pos, desain, tanggal penerbitan, dan objek historis lain harus dibandingkan dengan timeline tahun tersebut.

---

# 2. Visual Inspection

Saya membandingkan keempat surat secara manual.

Hal yang paling menarik muncul pada:

```text
letter_3.png
```

Pada bagian perangkonya terdapat perangko Amerika Serikat bernilai:

```text
10¢
```

Desainnya berkaitan dengan:

```text
Lexington and Concord
1775–1975
```

Tulisan **1775–1975** langsung menjadi indikator kuat.

Jika surat benar-benar berasal dari tahun **1971**, sebuah perangko yang secara eksplisit memperingati periode **1775–1975** sangat mencurigakan.

Hipotesis awal:

```text
letter_3.png menggunakan perangko yang belum diterbitkan pada 1971.
```

---

# 3. Identifying the Stamp

Pencarian difokuskan pada kombinasi ciri:

```text
10 cent
Lexington Concord
1775
1975
US postage stamp
```

Perangko tersebut berhasil diidentifikasi sebagai perangko:

```text
10c Lexington and Concord 1775
```

koleksi Smithsonian National Postal Museum.

Catatan resmi Smithsonian menyatakan tanggal perangko tersebut:

```text
April 19, 1975
```

atau:

```text
1975-04-19
```

Smithsonian juga menjelaskan bahwa perangko Lexington & Concord bernilai 10¢ tersebut diterbitkan pada **19 April 1975**, tepat pada peringatan 200 tahun Battles of Lexington and Concord.

Ini merupakan bukti utama.

Surat mengklaim berasal dari:

```text
1971
```

sedangkan perangkonya baru ada pada:

```text
1975
```

Maka perangko tersebut berada sekitar empat tahun terlalu awal apabila benar digunakan pada surat tahun 1971.

---

# 4. Secondary Verification — Postal Rate

Untuk memastikan bahwa anomali bukan sekadar kesalahan identifikasi desain, saya melakukan cross-check menggunakan riwayat tarif resmi United States Postal Service.

USPS mencatat tarif surat domestik first-class sebagai berikut:

```text
January 7, 1968  -> 6¢
May 16, 1971     -> 8¢
March 2, 1974    -> 10¢
December 31, 1975 -> 13¢
```

Dengan demikian, tarif **10¢** sendiri baru berlaku mulai:

```text
March 2, 1974
```

National Postal Museum juga mencatat timeline yang sama: tarif domestik menjadi **8¢ pada 16 Mei 1971**, kemudian menjadi **10¢ pada 2 Maret 1974**.

Jadi `letter_3.png` memiliki **dua historical inconsistencies**:

```text
1. Perangko Lexington & Concord baru diterbitkan tahun 1975.
2. Tarif first-class 10¢ sendiri baru berlaku tahun 1974.
```

Keduanya tidak cocok dengan surat yang diklaim berasal dari tahun 1971.

---

# 5. Control Check — 1971 Postage

Sebagai pembanding, Smithsonian mencatat perangko **8¢ Dwight D. Eisenhower** dengan tanggal penerbitan:

```text
May 10, 1971
```

National Postal Museum menjelaskan bahwa ketika tarif first-class naik menjadi **8¢ pada 16 Mei 1971**, perangko Eisenhower dibuat dalam denominasi 8¢ untuk menyesuaikan tarif tersebut.

Hal ini memberikan baseline yang masuk akal untuk material pos dari periode 1971.

Namun, yang paling penting untuk challenge ini bukan membuktikan ketiga surat lainnya asli secara absolut. Kita hanya perlu menemukan satu dokumen dengan detail yang **mustahil secara historis**, dan `letter_3.png` memenuhi kondisi tersebut secara definitif.

---

# 6. Forged Document

Dokumen palsu adalah:

```text
letter_3.png
```

Reason:

```text
Claimed year : 1971
Stamp        : 10¢ Lexington and Concord Bicentennial
Stamp year   : 1975
10¢ rate     : only effective from 1974
```

Timeline sederhananya:

```text
1971
 │
 ├── Letter claims to exist here
 ├── Domestic letter rate becomes 8¢
 │
 ▼
1974
 │
 ├── Domestic letter rate becomes 10¢
 │
 ▼
1975
 │
 └── Lexington & Concord Bicentennial 10¢ stamp issued
```

Dengan kata lain:

```text
1971 letter
     +
1975 commemorative stamp
     =
historical impossibility
```

---

# 7. Flag Construction

Format challenge:

```text
0xV0ID{YEAR_NAME}
```

Tahun diambil dari tahun penerbitan objek yang menyebabkan anachronism:

```text
1975
```

Nama yang digunakan untuk tema perangko tersebut:

```text
BICENTENNIAL
```

Maka:

```text
YEAR = 1975
NAME = BICENTENNIAL
```

Final flag:

```text
0xV0ID{1975_BICENTENNIAL}
```

---

# OSINT Tracker

| #  | Target / Pertanyaan                                | Query / Metode                                   | Source                             | Evidence                                                 | Status |
| -- | -------------------------------------------------- | ------------------------------------------------ | ---------------------------------- | -------------------------------------------------------- | ------ |
| 1  | Berapa scan yang tersedia?                         | `unzip -l letters.zip`                           | Local artifact                     | `letter_1.png` sampai `letter_4.png`                     | ✅      |
| 2  | Dokumen mana yang mencurigakan?                    | Visual comparison                                | Challenge scans                    | `letter_3.png` memiliki perangko 10¢ bertema `1775–1975` | ✅      |
| 3  | Apa identitas perangkonya?                         | Cari `10 cent Lexington Concord 1775 1975 stamp` | Smithsonian National Postal Museum | `10c Lexington and Concord 1775`                         | ✅      |
| 4  | Kapan perangko tersebut diterbitkan?               | Smithsonian object record                        | National Postal Museum             | **19 April 1975**                                        | ✅      |
| 5  | Apakah perangko itu peringatan Bicentennial?       | Smithsonian historical page                      | National Postal Museum             | Diterbitkan pada 200th anniversary Lexington & Concord   | ✅      |
| 6  | Berapa tarif surat domestik tahun 1971?            | USPS postal history                              | USPS                               | **8¢ mulai 16 Mei 1971**                                 | ✅      |
| 7  | Kapan tarif menjadi 10¢?                           | USPS postal history                              | USPS                               | **2 Maret 1974**                                         | ✅      |
| 8  | Apakah 10¢ valid untuk surat 1971?                 | Timeline comparison                              | USPS                               | Tidak; tarif tersebut belum berlaku                      | ✅      |
| 9  | Apakah perangko Lexington-Concord valid pada 1971? | Issue-date comparison                            | Smithsonian                        | Tidak; perangko baru terbit tahun 1975                   | ✅      |
| 10 | Forged document                                    | Evidence correlation                             | All evidence                       | `letter_3.png`                                           | ✅      |
| 11 | Flag year                                          | Stamp issue date                                 | Smithsonian                        | `1975`                                                   | ✅      |
| 12 | Flag name                                          | Stamp theme                                      | Smithsonian / challenge convention | `BICENTENNIAL`                                           | ✅      |
| 13 | Final flag                                         | Assemble `YEAR_NAME`                             | Challenge format                   | `0xV0ID{1975_BICENTENNIAL}`                              | ✅      |

---

# Evidence Chain

```text
letters.zip
    │
    ├── letter_1.png
    ├── letter_2.png
    ├── letter_3.png  <── suspicious
    └── letter_4.png
             │
             ▼
    10¢ Lexington & Concord
        "1775–1975"
             │
             ▼
 Smithsonian verification
             │
             ├── Issue date: April 19, 1975
             │
             ▼
      USPS rate history
             │
             ├── 1971 = 8¢
             └── 1974 = 10¢
             │
             ▼
       Anachronism confirmed
             │
             ▼
       Forgery = letter_3
             │
             ▼
0xV0ID{1975_BICENTENNIAL}
```

---

