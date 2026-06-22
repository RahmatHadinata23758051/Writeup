# sussy1 - Forensics Challenge

## Analisis
File `sussy` awalnya diidentifikasi sebagai file teks ASCII. Setelah dilakukan pemeriksaan awal menggunakan `strings` dan `head`, terlihat struktur perintah yang sangat mirip dengan G-code (perintah untuk printer 3D).

Contoh perintah dalam file:
```
G1 X12.252 Y90.632
G1 E2 F2400
G1 X33.531 Y87.755 E3.9525
```

Perintah `G1` dengan parameter `X` dan `Y` menunjukkan pergerakan koordinat, sedangkan `E` menunjukkan ekstrusi (pengeluaran filamen).

## Solusi
Karena ini adalah G-code, kemungkinan besar flag "digambar" oleh printer tersebut. Langkah yang diambil adalah memvisualisasikan pergerakan koordinat (X, Y) saat terjadi ekstrusi (E).

Dibuat script Python menggunakan `matplotlib` untuk mem-plot garis-garis tersebut. Fokus utama diberikan pada layer pertama (`Z=0.35`) agar gambar lebih bersih.

Setelah gambar di-render ke `plot.png`, tool OCR `tesseract` digunakan untuk membaca teks dari gambar tersebut.

Flag berhasil ditemukan: `sctf{id3n7ifying_fil3_typ3s}`.

## Flag
`sctf{id3n7ifying_fil3_typ3s}`
