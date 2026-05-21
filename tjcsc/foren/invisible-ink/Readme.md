# invisible-ink Writeup

Challenge ini kelihatannya sederhana karena cuma kasih satu file PDF, jadi saya mulai dari triage dasar dulu tanpa asumsi aneh.

## Ringkasan cepat

Flag yang didapat:

`tjctf{p01yg10t_f1les_4r3_s0_c001}`

## Langkah penyelesaian

### 1. Recon awal

Pertama saya cek isi folder dan tipe file:

```bash
ls -lah
file chall.pdf
exiftool chall.pdf
```

Hasil pentingnya:

- File hanya satu: `chall.pdf`
- Tipe file: PDF 2 halaman
- `exiftool` ngasih warning `Invalid xref table`

Warning ini cukup menarik, karena sering muncul kalau PDF-nya bukan PDF biasa atau ada data lain yang ditempel di belakang file.

### 2. Cari petunjuk langsung dari isi PDF

Lanjut saya ambil text dari PDF:

```bash
pdftotext chall.pdf -
```

Output halaman kedua langsung ngasih petunjuk:

```text
Ok fine here’s the password: DBf8nEBgwRhZ
```

Berarti ada sesuatu yang memang sengaja diproteksi password, dan password-nya justru diselipkan di dalam PDF.

### 3. Cek apakah ada file lain yang di-append ke PDF

Karena warning xref tadi mencurigakan, saya cek struktur file pakai `binwalk`:

```bash
binwalk chall.pdf
```

Temuan utamanya:

- Ada ZIP archive di offset `0x7AE8`
- ZIP itu berisi file `original_distorted.png`

Jadi file ini ternyata polyglot: valid sebagai PDF, tapi di belakangnya juga ada ZIP terenkripsi.

### 4. Ekstrak ZIP yang nempel di PDF

Karena password sudah ketemu dari text PDF, file PNG-nya bisa langsung diekstrak:

```bash
unzip -P 'DBf8nEBgwRhZ' chall.pdf
```

Hasilnya keluar file:

- `original_distorted.png`

### 5. Analisis image

Cek metadata dan tampilannya:

```bash
file original_distorted.png
exiftool original_distorted.png
```

File ini PNG biasa, 1920x1080, dibuat dengan GIMP. Secara visual isinya tulisan merah yang diputar/di-whirl cukup parah. Jadi fokusnya bukan stego LSB, tapi pemulihan bentuk tulisan.

### 6. Balikkan efek distorsi

Karena bentuknya sangat mirip efek `swirl`, saya coba inverse transform dengan ImageMagick. Dari beberapa percobaan, nilai `-240` paling enak dibaca:

```bash
convert original_distorted.png -background white -swirl -240 solved.png
```

Setelah di-dewhirl, teksnya terbaca menjadi:

```text
tjctf{p01yg10t_f1les_4r3_s0_c001}
```

## Kenapa ini worked

Trik challenge ini ada dua layer:

1. PDF dipakai sebagai umpan dan penyimpan password.
2. ZIP terenkripsi di-append ke PDF supaya orang yang cuma buka PDF biasa mungkin tidak sadar ada file lain di belakangnya.

Setelah ZIP diekstrak, layer keduanya adalah gambar dengan distorsi visual. Jadi solve-nya bukan brute-force aneh-aneh, tapi:

- sadar file-nya polyglot
- ambil password dari konten PDF
- ekstrak PNG
- pulihkan distorsi visual

## File yang saya buat

- `solve.py` untuk mengulang langkah inti solve
- `original_distorted.png` sebagai artefak hasil ekstraksi dari PDF

## Command inti

```bash
pdftotext chall.pdf -
binwalk chall.pdf
unzip -P 'DBf8nEBgwRhZ' chall.pdf
convert original_distorted.png -background white -swirl -240 solved.png
```
