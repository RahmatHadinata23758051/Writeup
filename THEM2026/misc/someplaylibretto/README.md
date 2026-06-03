# Writeup - Some Play's Libretto

## Analisis Awal
Challenge ini memberikan sebuah file bernama `score.txt` yang berisi teks drama yang tampak aneh dan terobsesi dengan angka serta karakter bernama Romeo dan Juliet. Dari judulnya, "The Arithmetic Tragedy of the Bard's Secret" (setelah didekode), saya mencurigai ini adalah kode dalam bahasa pemrograman esoterik bernama **Shakespeare Programming Language (SPL)**.

## Langkah Penyelesaian

### 1. Dekripsi Caesar Cipher
Teks dalam `score.txt` ternyata dienkripsi menggunakan Caesar Cipher dengan shift 6 (atau 20 tergantung arah). Setelah didekripsi, kita mendapatkan kode SPL yang valid.
Judul asli: `Nby Ulcnbgyncw Nluayxs iz nby Vulx'm Mywlyn.`
Didekode menjadi: `The Arithmetic Tragedy of the Bard's Secret.`

### 2. Analisis Kode SPL
Kode tersebut terdiri dari dua bagian utama:
- **Bagian Pertama (Scene I - XXI):** Meminta input karakter satu per satu dan membandingkannya dengan nilai yang dihitung. Jika benar, ia lanjut ke scene berikutnya. Ini semacam pemeriksaan password. Kata sandinya adalah: `shakespeare from temu`.
- **Bagian Kedua (Scene XXIII):** Bagian ini menghitung nilai-nilai tertentu dan mencetaknya menggunakan perintah `Speak thy mind!`. Nilai-nilai ini adalah karakter dari pesan rahasia yang kita cari.

### 3. Ekstraksi Pesan
Dengan menggunakan script Python untuk memparsing aturan SPL (di mana kata sifat menggandakan nilai kata benda, dan kata benda bernilai 1), saya berhasil mengekstrak pesan aslinya:
`bro might actually be shakespeare`

### 4. Konversi ke Leetspeak
Sesuai instruksi challenge dan contoh yang diberikan (`THEM?!CTF{50m3_pl41n73x7_6035_h3r3}`), kita harus mengubah pesan tersebut ke dalam format leetspeak dengan aturan:
- `a` -> `4`
- `e` -> `3`
- `i` -> `1`
- `o` -> `0`
- `s` -> `5`
- `t` -> `7`
- `g` -> `6`
- Spasi -> `_` (Underscore)

Hasil konversi:
`br0_m16h7_4c7u4lly_b3_5h4k35p34r3`

## Flag Akhir
Menggabungkan hasil konversi dengan format prefix yang diberikan pada contoh:
`THEM?!CTF{br0_m16h7_4c7u4lly_b3_5h4k35p34r3}`
