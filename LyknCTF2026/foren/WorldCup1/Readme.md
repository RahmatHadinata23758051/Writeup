# World Cup 1 - Writeup

### Analisis File
1. Cek metadata file `worldcup1_challenge.png` menggunakan `exiftool`.
2. Ditemukan komentar metadata `The score was 3-2 after extra time` dan `Flag Hint: Look deeper in the red pixels`.
3. Terdapat data tambahan di bagian akhir file PNG (trailer data setelah IEND chunk).

### Ekstraksi Flag
Dengan hint `Look deeper in the red pixels` (cari lebih dalam di piksel merah), dilakukan analisis LSB (Least Significant Bit) pada channel warna merah (red channel).

Menjalankan `zsteg` untuk mengekstrak data LSB:
```bash
zsteg worldcup1_challenge.png
```

Hasil ekstraksi `zsteg` pada LSB channel merah (`b1,r,lsb,xy`) langsung menampilkan flag:
`LYKNCTF{Argentina3-2CaboVerde}`
