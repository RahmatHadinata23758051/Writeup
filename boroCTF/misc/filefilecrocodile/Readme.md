# File File Crocodile - Misc

## Analisis
Diberikan sebuah file gambar `chall.png`. Deskripsi menyinggung soal buaya ("crocodile") yang menelan locked archive dan "stomach acid" yang merusak file signature. Kata kunci "croc" juga ditekankan.

Pengecekan awal dengan `exiftool` menunjukkan adanya trailer data setelah chunk `IEND` (akhir dari PNG).
```bash
exiftool chall.png
# Warning: [minor] Trailer data after PNG IEND chunk
```

Pengecekan hex menunjukkan data tersebut menyerupai struktur file ZIP, namun dengan signature `FC` (46 43) bukannya `PK` (50 4B).
- `46 43 03 04` (Local file header)
- `46 43 01 02` (Central directory header)
- `46 43 05 06` (End of central directory record)

Ini sesuai dengan tema "File Crocodile" (`FC`).

## Solusi
1. Ekstrak data setelah chunk `IEND` pada `chall.png`.
2. Ganti semua signature `FC` (\x46\x43) menjadi `PK` (\x50\x4B).
3. Simpan sebagai file `.zip`.
4. Buka ZIP tersebut menggunakan password `croc`.
5. Flag ditemukan di dalam `flag.txt`.

### Flag
`boroCTF{n3v3r_sm1l3_4t_4_p0lygl0t_cr0c0d1l3}`
