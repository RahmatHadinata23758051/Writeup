# Time Traveler — OSINT Writeup

## Challenge Information

**Category:** OSINT
**Challenge:** Time Traveler

**Description:**

> Your ancestors had to work much harder for flags like these. Y'all have it easy.

Tidak ada file, gambar, maupun informasi tambahan yang diberikan pada challenge. Satu-satunya petunjuk adalah judul **Time Traveler** dan kalimat pada deskripsi.

---

## Analysis

Karena challenge tidak menyediakan artefak apa pun, analisis dimulai dari interpretasi clue.

Dua bagian yang paling menarik adalah:

* **Time Traveler**
* **Your ancestors had to work much harder for flags like these**

Kata **ancestors** kemungkinan tidak merujuk pada leluhur secara literal, tetapi kepada peserta atau challenge dari event **scriptCTF sebelumnya**, khususnya scriptCTF 2025.

Sementara itu, **Time Traveler** mengindikasikan bahwa informasi yang dicari kemungkinan berasal dari masa lalu tetapi berkaitan dengan event saat ini, yaitu scriptCTF 2026.

Dengan asumsi tersebut, pencarian diarahkan ke challenge dan writeup OSINT scriptCTF 2025.

---

## Finding the Previous Challenge

Pada rangkaian challenge OSINT scriptCTF 2025 terdapat challenge **The Insider 3**.

Challenge tersebut mengharuskan pemain melakukan proses OSINT hingga menemukan sebuah repository yang berkaitan dengan scriptCTF tahun berikutnya, yaitu **scriptCTF 2026**.

Yang menarik, flag yang ditemukan pada challenge tahun 2025 tersebut adalah:

```text
scriptCTF{2026_fl4g_f0und_1n_2025}
```

Isi flag tersebut sendiri berarti:

```text
2026 flag found in 2025
```

Hal ini sangat sesuai dengan konsep **Time Traveler**, karena sebuah flag untuk tahun **2026** sudah ditemukan oleh peserta pada tahun **2025**.

---

## Connecting the Clues

Clue challenge dapat diinterpretasikan sebagai berikut:

### `Your ancestors`

Merujuk kepada peserta **scriptCTF 2025**, yaitu peserta event tahun sebelumnya.

### `had to work much harder`

Pada tahun 2025, peserta harus melakukan rangkaian investigasi OSINT untuk menemukan akun, repository, dan akhirnya flag tersebut.

### `Y'all have it easy`

Peserta scriptCTF 2026 tidak perlu mengulang seluruh rangkaian OSINT tersebut. Kita cukup melihat kembali hasil investigasi peserta tahun sebelumnya.

### `Time Traveler`

Flag berasal dari tahun 2025 tetapi secara eksplisit menyebut dirinya sebagai flag tahun 2026.

Dengan demikian, flag tersebut secara metaforis telah melakukan perjalanan waktu dari scriptCTF 2025 ke scriptCTF 2026.

---

## Flag

```text
scriptCTF{2026_fl4g_f0und_1n_2025}
```

## Conclusion

Challenge **Time Traveler** merupakan challenge OSINT berbasis sejarah event.

Tidak diperlukan eksploitasi maupun analisis file. Kunci penyelesaiannya adalah memahami bahwa kata **ancestors** mengarah kepada peserta scriptCTF tahun sebelumnya, kemudian mencari kembali jejak challenge OSINT scriptCTF 2025.

Challenge tersebut ternyata sudah membocorkan sebuah flag untuk scriptCTF 2026:

```text
scriptCTF{2026_fl4g_f0und_1n_2025}
```


