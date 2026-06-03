# Writeup Challenge: Obsufucationmax

## Deskripsi
Dalam challenge ini, kita diberikan file bernama `chall.png`. Deskripsi tantangannya adalah untuk merecover atau memulihkan file gambar tersebut dan menggunakan nilai hash SHA256 dari gambar yang telah dipulihkan sebagai flag.

## Langkah-langkah Penyelesaian

### 1. Analisis Awal File
Pertama-tama, saya melakukan pengecekan terhadap file dengan tool seperti `file`, `exiftool`, dan `pngcheck`.
Ternyata `pngcheck` menampilkan pesan error bahwa terdapat chunk yang invalid:
`invalid chunk name "S!(+"`

Ini menandakan bahwa struktur PNG pada file ini rusak atau disembunyikan.

### 2. Inspeksi Hex
Setelah mengetahui ada kerusakan pada file, saya membuka file menggunakan `xxd` (Hex Viewer). 
Ketika melihat bagian header (33 byte pertama dari awal file sampai chunk `IHDR` beserta CRC-nya selesai), semuanya terlihat normal dan valid:
```
8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
0000 026b 0000 01fc 0806 0000 008e c7e8  ...k............
```
Namun, tepat setelah byte ke-33 (offset `0x21`), data yang seharusnya merupakan header chunk normal (misalnya `sRGB` atau `IDAT`) berubah menjadi teks aneh: `saieS!(+ ...`. Ini menandakan bahwa data setelah byte ke-33 telah diobfuskasi atau dienkripsi.

### 3. Mencari Clue
Saya kemudian mencoba mencari teks biasa (strings) di dalam file. Saat mengecek di bagian paling akhir file, saya menemukan sebuah kalimat aneh:
`i have encrypted this cuz my pet said so`

Panjang string tersebut adalah tepat 40 karakter (byte). Kalimat ini sangat mencurigakan dan tampak seperti *key* atau kunci enkripsi yang digunakan.

### 4. Memecahkan Enkripsi XOR
Karena biasanya obfuskasi sederhana pada CTF menggunakan algoritma XOR, saya berasumsi bahwa file tersebut di-XOR menggunakan kunci `i have encrypted this cuz my pet said so`.

Saya mencoba melakukan dekripsi XOR dengan key tersebut mulai dari offset 33 (karena 33 byte pertama sudah valid). Algoritmanya bekerja dengan mengulang kunci (repeating-key XOR). Setelah dicoba menggunakan script Python kecil, hasil dekripsi dari offset ke-33 memunculkan chunk PNG yang valid, seperti:
```
00 00 00 01 73 52 47 42 ... (chunk sRGB)
```
Ini membuktikan bahwa tebakan kuncinya benar.

### 5. Memulihkan File
Saya kemudian menulis script dekripsi penuh untuk me-XOR seluruh isi data file mulai dari offset 33 sampai bagian akhir gambar (ujung dari chunk `IEND`). 

Satu hal yang perlu diperhatikan: string clue `i have encrypted this cuz my pet said so` yang ditambahkan di akhir file membuat file menjadi berlebih (append data). File PNG yang valid harus berakhir setelah chunk `IEND`. Chunk `IEND` berakhir tepat di offset byte ke-380633. Jadi, kita harus memotong file hasil dekripsi agar tidak ada extra byte, dengan cara mengambil tepat 380633 byte saja.

### 6. Mendapatkan Flag
Setelah mendapatkan gambar original yang 100% *clean* tanpa error saat di-scan kembali menggunakan `pngcheck`, langkah terakhir adalah menghitung hash SHA256 dari gambar tersebut sesuai instruksi deskripsi challenge.

```bash
sha256sum recovered.png
```

Hasil hash-nya adalah:
`8bf9507282aefcfc9122b0d9f4e5b765d6cc35c0e9034e0a8e79a031873d2fff`

## Flag
<FLAG>THEM?!CTF{8bf9507282aefcfc9122b0d9f4e5b765d6cc35c0e9034e0a8e79a031873d2fff}</FLAG>