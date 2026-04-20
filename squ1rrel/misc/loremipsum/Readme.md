# Writeup - misc/lorem-ipsum

## Ringkasan
Challenge ini berupa satu file PDF: `lorem_ipsum_dolor.pdf`.
Hint deskripsi bilang naskah sudah "dipotong" (cut down). Itu mengarah ke kemungkinan data lama masih tertinggal di file, walaupun tampilan PDF terbaru sudah berubah.

Flag berhasil didapat dari revisi PDF lama yang masih menempel di dalam file lewat mekanisme **incremental update** PDF.

## Langkah Analisis

### 1. Enumerasi awal
Cek isi direktori:
- hanya ada `lorem_ipsum_dolor.pdf`

Cek metadata cepat:
- file terlihat normal, tidak terenkripsi
- tidak ada attachment (`pdfdetach -list` = 0 file)

### 2. Cari indikasi data tersembunyi
Ekstrak teks langsung dari PDF terbaru pakai `pdftotext`.
Hasilnya hanya lorem ipsum + kalimat penutup, tidak ada flag.

Lalu cek struktur bagian akhir file (`tail -n ...`), ketemu hal penting:
- ada **dua** blok `xref/trailer/startxref/%%EOF`
- di antara blok itu ada catatan `Written by MuPDF ...`
- trailer kedua punya `/Prev ...`

Ini pola khas PDF yang pernah di-edit lalu disimpan sebagai incremental update.
Artinya: konten lama belum hilang, cuma ditimpa referensi objek baru.

### 3. Recovery revisi lama
Ambil byte file sampai `%%EOF` pertama saja.
Hasilnya jadi PDF revisi awal (sebelum update terakhir).

Setelah diekstrak teks dari revisi awal, flag muncul di bagian isi halaman:

`squ1rrel{d4n6_17_y0u_f0und_m3!}`

## Kenapa teknik ini berhasil
Format PDF mendukung append update: perubahan baru ditambahkan di belakang file, bukan selalu rewrite total.
Kalau editor hanya "memotong" konten versi terbaru, data versi lama masih bisa tertinggal dan dipulihkan dengan membaca revision sebelumnya.

## Solver
File solver final: `solve.py`

Cara pakai:
```bash
python3 solve.py
```

Output:
```text
squ1rrel{d4n6_17_y0u_f0und_m3!}
```

## Isi solve.py (ringkas)
1. Baca `lorem_ipsum_dolor.pdf` sebagai bytes.
2. Cari `%%EOF` pertama.
3. Simpan potongan bytes sampai titik itu sebagai `_rev0.pdf`.
4. Jalankan `pdftotext _rev0.pdf -`.
5. Regex `squ1rrel\{[^}]+\}` untuk ambil flag.

