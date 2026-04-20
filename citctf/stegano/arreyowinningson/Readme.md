# Writeup - Are ya winning, son?

Kategori challenge ini `misc`, tapi artefaknya berupa gambar `chall.jpg`, jadi pendekatan paling masuk akal adalah stegano/forensics file JPEG.

## 1. Enumerasi awal

Pertama cek isi folder:

```bash
ls -la
```

Hanya ada satu file: `chall.jpg`.

Lalu cek metadata:

```bash
file chall.jpg
exiftool chall.jpg
```

Hasilnya normal untuk JPEG (800x800), tidak ada EXIF aneh atau comment mencurigakan.

## 2. Cari anomali struktur JPEG

Lanjut cek dengan decoder JPEG verbose:

```bash
djpeg -verbose chall.jpg >/tmp/djpeg.ppm 2>/tmp/djpeg.err
cat /tmp/djpeg.err
```

Muncul indikator penting:

- `Corrupt JPEG data: 8462 extraneous bytes before marker 0xd9`

Artinya ada 8462 byte tambahan tepat sebelum marker akhir JPEG (`FFD9`). Ini red flag banget buat stego model "nyelipin data di entropy stream".

Cross-check pakai `jpegtran`:

```bash
jpegtran -copy all -outfile clean.jpg chall.jpg
ls -l chall.jpg clean.jpg
```

`clean.jpg` jadi lebih kecil, menandakan byte tambahan memang dibuang saat normalisasi.

## 3. Hipotesis dan validasi

Hipotesis: byte tambahan itu bukan noise random, tapi scan-data JPEG lain yang bisa dirender kalau dipasangkan dengan header yang sama.

Langkah validasi:

1. Parse struktur JPEG sampai marker `SOS` (start of scan).
2. Ambil entropy scan data dari setelah SOS sampai sebelum EOI.
3. Cari awal segmen tambahan (di challenge ini kelihatan jelas diawali run panjang pola `05 14 51 40`).
4. Bangun file JPEG baru:
   - pakai header asli sampai `SOS`
   - pakai segmen tambahan tadi sebagai scan data
   - tutup dengan `FFD9`

Waktu file hasil (`alt.jpg`) dibuka, langsung muncul teks flag di gambar tersembunyi.

## 4. Flag

Flag yang didapat:

```text
CIT{pls_d0nt_b3_l1k3_th1s_guy}
```

## 5. Automasi solve

Script final disimpan di `solve.py`.

Jalankan:

```bash
python3 solve.py
```

Output:

```text
CIT{pls_d0nt_b3_l1k3_th1s_guy}
```

Script melakukan full flow otomatis:

- parse marker JPEG untuk dapat offset `SOS`
- ekstrak scan data
- deteksi awal payload extraneous
- rebuild gambar tersembunyi (`recovered_hidden.jpg`)
- OCR dengan `tesseract`
- print flag

