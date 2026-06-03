# Writeup - kanye? (Misc)

## Deskripsi
Challenge ini memberikan sebuah file gambar `sigma.png`. Deskripsi challenge "there something in kanye(maybe)" dan judul "kanye?" memberikan petunjuk tentang sesuatu yang tersembunyi.

## Analisis
1. **Pemeriksaan Awal**: 
   - File `sigma.png` adalah gambar PNG berukuran 1080x1080.
   - `exiftool` dan `binwalk` tidak menunjukkan adanya file yang disisipkan secara standar (seperti zip di akhir file).
   - `strings` tidak memberikan informasi yang berguna secara langsung.

2. **Identifikasi Masalah**:
   - Saat mencoba menjalankan `tesseract` pada gambar, muncul peringatan: `libpng warning: IDAT: Too much image data`.
   - Ini adalah indikasi kuat bahwa chunk `IDAT` (tempat data piksel disimpan) mengandung lebih banyak data daripada yang dibutuhkan untuk resolusi 1080x1080.
   - Teknik ini sering digunakan untuk menyembunyikan bagian bawah gambar dengan cara memanipulasi tinggi (height) gambar pada chunk `IHDR`.

3. **Eksploitasi**:
   - Saya mengekstrak dan mendecompress data `IDAT`. 
   - Ukuran data yang didekompresi adalah 5,253,661 bytes.
   - Untuk gambar 24-bit RGB, setiap baris memiliki 1 byte filter + (lebar * 3) bytes.
   - Ukuran baris = 1 + (1080 * 3) = 3241 bytes.
   - Jumlah baris sebenarnya = 5,253,661 / 3241 = 1621 baris.
   - Tinggi yang tertulis di `IHDR` hanya 1080, berarti ada 1621 - 1080 = 541 baris yang disembunyikan.

4. **Perbaikan Gambar**:
   - Saya membuat script `solve.py` untuk mengubah byte tinggi pada chunk `IHDR` dari 1080 (`00 00 04 38`) menjadi 1621 (`00 00 06 55`).
   - Selain mengubah tinggi, CRC dari chunk `IHDR` juga harus diperbarui agar file PNG tetap valid.
   - Hasil perbaikan disimpan sebagai `fixed.png`.

5. **Mendapatkan Flag**:
   - Setelah membuka bagian gambar yang tersembunyi, flag terlihat di bagian bawah.
   - Menggunakan OCR (`tesseract`) pada bagian bawah gambar tersebut menghasilkan:
     `THEM{m4yb3_yOu_shOuld_4lw4ys_tw34k_th3_png_f1l3_1ts3lf}`

## Flag
<FLAG>THEM{m4yb3_yOu_shOuld_4lw4ys_tw34k_th3_png_f1l3_1ts3lf}</FLAG>
