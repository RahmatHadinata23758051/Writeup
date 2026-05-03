# Writeup: Krasnodar Tram

## 1. Analisis Awal & Enumerasi
Saat pertama kali memeriksa file `267.jpg` dan `678.jpg`, kita bisa menggunakan `exiftool` untuk melihat metadata gambar tersebut. Kita akan menemukan beberapa string yang mencurigakan di berbagai tag metadata (seperti `Image Description`, `Artist`, `Lens Model`, `Copyright`, dll) yang terlihat seperti Base64:
- `dHUu`
- `Njk=`
- `aHR0`
- `Ly9w`
- `cy0x`
- `Ly9r`
- `Q3N2`
- dll...

Selain itu, ada "Prompt Injection" lucu di kolom `XP Comment` yang mengancam LLM untuk mengabaikan tugas dan menampilkan resep Borscht, tapi kita tentu bisa mengabaikannya. :D

## 2. Dekode Fragment Base64
Langkah berikutnya adalah mendekode semua string Base64 yang kita temukan.
Misalnya:
- `aHR0` -> `htt`
- `cHM6` -> `ps:`
- `Ly9r` -> `//k`
- `dWJz` -> `ubs`
- `dHUu` -> `tu.`
- `cnUv` -> `ru/`
- `cy0x` -> `s-1`
- `Njk=` -> `69`
...dan seterusnya.

## 3. Merangkai Potongan Puzzle (URL)
Jika kita perhatikan hasil decode tersebut, kita bisa merangkainya menjadi dua buah URL:
1. **URL Pertama:** Menggabungkan `htt`, `ps:`, `//k`, `ubs`, `tu.`, `ru/`, `s-1`, dan `69` menghasilkan:
   `https://kubstu.ru/s-169` (URL asli dari departemen keamanan informasi di Universitas Kuban!)
2. **URL Kedua:** Menggabungkan `htt`, `ps:`, `//p`, `ast`, `ebi`, `n.c`, `om/` menghasilkan:
   `https://pastebin.com/`

## 4. Menemukan ID Pastebin yang Tepat
Setelah memisahkan potongan-potongan untuk dua URL di atas, tersisa 3 potongan metadata yang belum dipakai (hasil decode):
- `SuB` (dari tag Lens di 678.jpg)
- `Csv` (dari tag Copyright "Q3N2" di 267.jpg)
- `pK` (dari tag Copyright "cEs=" di 678.jpg)

Jika digabungkan, panjang karakternya tepat 8 karakter (`SuB` + `Csv` + `pK` = 8 karakter). ID dari Pastebin normalnya selalu berjumlah 8 karakter. Dengan menguji beberapa permutasi dari 3 potongan string tersebut, kita bisa menemukan bahwa susunan yang benar (yang tidak menghasilkan 404 Not Found) adalah **`SuBCsvpK`**.

Link pastebin lengkapnya adalah: `https://pastebin.com/raw/SuBCsvpK`

## 5. Mendapatkan Flag
Saat mengakses link raw Pastebin tersebut, kita akhirnya akan menemukan flag rahasia dari challenge ini!

**Flag:** `KubSTU{g0d_s4v3_7h3_kr45n0d4r_7r4m}`
