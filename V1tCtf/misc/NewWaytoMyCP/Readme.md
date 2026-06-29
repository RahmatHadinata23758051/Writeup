# New Way to Store My CP — OSINT

## Challenge

**Judul:** New Way to store my CP (Collections of Photos)
**Kategori:** OSINT

### Deskripsi

> Recently, I put all my money into 1xbet and now I'm broke af.
> I found a good way to store my 36GB CP and I will share u guys below.
>
> https://pastebin.com/899yXPGK

Target challenge ini adalah mengikuti rangkaian petunjuk dari Pastebin, menemukan data yang disembunyikan di dalam video, lalu merekonstruksi flag akhir.

---

## 1. Memeriksa Pastebin

Saat Pastebin dibuka, teksnya terlihat seperti teks biasa. Namun, terdapat kata-kata yang mengarah ke teknik penyembunyian pesan menggunakan karakter tidak terlihat, terutama petunjuk:

```text
new cloak
```

Ketika isi Pastebin diperiksa pada level Unicode, ditemukan banyak karakter zero-width seperti:

* Zero Width Non-Joiner
* Zero Width Joiner
* Word Joiner
* Invisible Separator

Karakter-karakter tersebut biasa digunakan oleh tool bernama **StegCloak** untuk menyembunyikan data di dalam teks normal.

Isi Pastebin kemudian disalin secara utuh dan diproses menggunakan StegCloak.

Hasil decoding:

```text
5h0ut_0ut_t0_Brandon
```

Awalnya string tersebut terlihat seperti kandidat isi flag. Namun, ketika dibungkus menjadi:

```text
V1T{5h0ut_0ut_t0_Brandon}
```

flag ditolak.

Artinya, hasil StegCloak bukanlah flag akhir, melainkan password atau key untuk tahap berikutnya.

---

## 2. Menemukan Video YouTube

Di dalam Pastebin juga terdapat referensi menuju video YouTube:

```text
https://youtu.be/hLX0Igh-DKg
```

Video tersebut berisi tampilan seperti noise hitam-putih. Secara sekilas, frame-frame videonya terlihat acak, tetapi setelah diperbesar, pola tersebut ternyata tersusun dari blok-blok piksel berukuran tetap.

Percobaan mengunduh video menggunakan `yt-dlp` sempat gagal:

```bash
yt-dlp --no-playlist -f "bv*" \
  "https://youtu.be/hLX0Igh-DKg" \
  -o "cp_storage.%(ext)s"
```

Error yang muncul:

```text
Precondition check failed
HTTP Error 403: Forbidden
```

Video akhirnya diunduh menggunakan downloader alternatif dengan kualitas 1080p agar struktur blok piksel tidak rusak oleh resize atau kompresi tambahan.

File yang dianalisis:

```text
YTDown_YouTube_I-store-my-CP-here_Media_hLX0Igh-DKg_001_1080p.mp4
```

---

## 3. Mengekstrak Frame Video

Informasi video dapat diperiksa menggunakan `ffprobe`:

```bash
ffprobe -hide_banner video.mp4
```

Selanjutnya, semua frame diekstrak menggunakan FFmpeg:

```bash
mkdir frames

ffmpeg -i video.mp4 frames/frame_%05d.png
```

Saat salah satu frame diperbesar, terlihat bahwa gambar bukan random noise murni.

Setiap bit direpresentasikan menggunakan blok piksel dengan ukuran sekitar:

```text
2 × 4 piksel
```

Piksel terang dan gelap merepresentasikan nilai biner:

```text
putih = 1
hitam = 0
```

Dengan membaca blok-blok tersebut secara berurutan, setiap frame dapat dikonversi kembali menjadi byte.

---

## 4. Mengidentifikasi Format Paket

Setelah bit pada frame dikonversi menjadi byte, ditemukan magic header:

```text
SFTY
```

Hal ini menunjukkan bahwa video dibuat menggunakan proyek **yt-media-storage**.

Aplikasi tersebut menyimpan file sebagai rangkaian frame video melalui beberapa tahap:

```text
File asli
  ↓
Enkripsi
  ↓
Fountain encoding
  ↓
Paket SFTY
  ↓
Konversi bit menjadi frame video
```

Paket yang berhasil diekstrak memiliki ukuran tetap. Dari seluruh video diperoleh sekitar:

```text
2808 paket
```

Data sumber sebenarnya hanya membutuhkan sekitar:

```text
470 blok
```

Paket tambahan merupakan redundansi dari fountain code agar file masih dapat dipulihkan meskipun ada frame yang rusak atau hilang.

---

## 5. Fountain Code Wirehair

Data tidak bisa direkonstruksi hanya dengan menggabungkan paket menggunakan `cat`.

Hal ini terjadi karena proyek tersebut menggunakan **Wirehair**, yaitu fountain code atau erasure code. Setiap paket dapat berisi kombinasi dari beberapa blok sumber.

Bahkan paket sumber pertama sengaja tidak tersedia secara langsung, sehingga proses decoding Wirehair memang wajib dilakukan.

Secara umum, prosesnya adalah:

```text
SFTY packets
  ↓
Parse packet ID dan payload
  ↓
Masukkan paket ke Wirehair decoder
  ↓
Pulihkan seluruh blok sumber
  ↓
Gabungkan menjadi encrypted blob
```

Decoder Wirehair dijalankan melalui implementasi WebAssembly yang kompatibel dengan proyek aslinya.

Setelah decoding berhasil, diperoleh blob dengan ukuran:

```text
120243 byte
```

Data tersebut masih terlihat acak karena merupakan ciphertext.

---

## 6. Mendekripsi Payload

Berdasarkan source code `yt-media-storage`, payload dienkripsi menggunakan:

```text
XChaCha20-Poly1305
```

String hasil StegCloak digunakan sebagai password:

```text
5h0ut_0ut_t0_Brandon
```

Password tersebut diproses menggunakan mekanisme derivasi key yang sama seperti implementasi asli, kemudian dipakai untuk mendekripsi blob hasil Wirehair.

Alur akhirnya:

```text
Password dari StegCloak
        +
Encrypted blob dari video
        ↓
Key derivation
        ↓
XChaCha20-Poly1305 decrypt
        ↓
Plaintext
```

Dekripsi berhasil, yang membuktikan bahwa `5h0ut_0ut_t0_Brandon` memang merupakan password dan bukan flag.

---

## 7. Mendapatkan Flag

Plaintext hasil dekripsi berisi flag yang dipisahkan oleh kata `Quack`:

```text
V Quack 1 Quack T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
```

Kata `Quack` di antara huruf awal hanya berfungsi sebagai separator.

Setelah separator tersebut dihapus:

```text
V1T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
```

## Flag

```text
V1T{Quack_Quack_Quack_1_l0ve_Qu4cking_r34l_much_br}
```

---

## Ringkasan

Rangkaian penyelesaian challenge:

```text
Pastebin
  ↓
Deteksi karakter zero-width
  ↓
Decode dengan StegCloak
  ↓
Password: 5h0ut_0ut_t0_Brandon
  ↓
Unduh video YouTube
  ↓
Ekstrak frame
  ↓
Baca blok piksel sebagai bit
  ↓
Temukan paket SFTY
  ↓
Decode fountain code Wirehair
  ↓
Dapatkan encrypted blob
  ↓
Decrypt XChaCha20-Poly1305
  ↓
Hapus separator Quack
  ↓
Flag
```

Challenge ini menggabungkan beberapa teknik sekaligus:

* Unicode zero-width steganography
* OSINT melalui Pastebin dan YouTube
* Penyimpanan data di dalam frame video
* Fountain code atau erasure coding
* Authenticated encryption menggunakan XChaCha20-Poly1305
