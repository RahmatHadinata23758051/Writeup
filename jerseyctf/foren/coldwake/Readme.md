# Cold Wake - Forensics Writeup

## Ringkasan
Challenge ini berisi 3 file gambar:
- `Tape1.jpg`
- `Tape2.jpg`
- `Tape3.jpg`

Format flag: `JCTF{XXXXX-XXXXX-XXXXX}`

Dari narasi challenge, launch authorization dibagi menjadi 3 segmen dan tiap segmen disembunyikan dengan cara berbeda.

## 1) Initial Recon
Langkah awal:
- `file Tape1.jpg Tape2.jpg Tape3.jpg`
- `exiftool Tape1.jpg Tape2.jpg Tape3.jpg`
- `strings` untuk triage cepat

Hasil penting:
- `Tape1.jpg` punya metadata/comment mencurigakan:
  - `ORBITAL LAB ARCHIVE :: SINGULARITY INIT SEGMENT :: SEQ=47291`
- `Tape2.jpg` dan `Tape3.jpg` tampak seperti JPEG biasa (tanpa metadata jelas).

Segmen pertama langsung terlihat kuat: **47291**.

## 2) Analisis Tape2.jpg
Karena `strings` biasa tidak memberi flag langsung, lanjut stego check:
- `steghide info Tape2.jpg`
- `stegseek Tape2.jpg /usr/share/wordlists/rockyou.txt`

Hasil:
- Ditemukan passphrase: **`galaxy`**
- Berhasil extract file: `Tape2.jpg.out`
- Isi extracted file berupa JPEG kecil (`Tape2Paper_small.jpg`).

Dari OCR/inspeksi visual pada file hasil extract, token angka yang konsisten terbaca adalah:
- **80536**

Ini dipakai sebagai segmen kedua.

## 3) Analisis Tape3.jpg
Lanjut metode serupa karena pattern-nya kemungkinan satu rangkaian:
- `stegseek Tape3.jpg _pw2.txt` (wordlist kecil custom yang memuat `galaxy`)

Hasil:
- Passphrase kembali ketemu: **`galaxy`**
- Extract file: `Tape3.jpg.out` (MP3 pendek, ~4 detik)

Kemudian audio ditranskrip:
- `whisper Tape3.jpg.out --model base.en --language en --task transcribe`

Output transkrip:
- **"One, nine, four, zero, eight."**
- Segmen ketiga: **19408**

## 4) Korelasi Akhir
Tiga segmen yang didapat:
1. `47291` (metadata Tape1)
2. `80536` (gambar hasil extract Tape2)
3. `19408` (audio hasil extract Tape3)

Maka flag final:

`JCTF{47291-80536-19408}`

## Catatan
- Tidak pakai writeup internet.
- Full analisis dilakukan dari artefak lokal challenge.
