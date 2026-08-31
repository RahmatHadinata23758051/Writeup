# Sideband Surgery Writeup

## Ringkasan

Artefak challenge berupa `challenge.raw.xz`. Setelah diekstrak, isinya adalah sampel IQ complex64. Bagian real-nya membentuk audio 48 kHz jika diambil setiap 5 sampel dari stream 240 kHz. Audio tersebut berisi beberapa transmisi SSTV Robot36.

Isi gambar SSTV bukan flag langsung. Gambar membawa potongan QR yang rusak. Potongan ini perlu disusun ulang dari empat strip yang muncul di transmisi. Finder pattern kiri atas hilang, jadi QR harus diperbaiki sedikit sebelum didecode.

Flag yang keluar dari QR:

```
ASIS{3V3RY_W4V3_C4RR13S_4_53CR3T}
```

## File Challenge

```
challenge.raw.xz  XZ compressed data
challenge.raw     raw complex64 IQ samples setelah diekstrak
```

Ukuran raw sekitar 285 MiB. Formatnya bukan ELF, bukan script, dan tidak memiliki string flag langsung. Jadi pendekatan `strings` tidak membantu banyak, ya mengejutkan sekali, file radio tidak mau mengaku sebagai binary Linux.

## Analisis Awal

Pemeriksaan awal:

```
file challenge.raw.xz
xz -d -k challenge.raw.xz
file challenge.raw
```

`challenge.raw` berisi data numerik mentah. Saat dibaca sebagai complex64, panjangnya cocok dengan sinyal IQ. Bagian real dari sinyal bisa diturunkan ke audio 48 kHz dengan mengambil sampel setiap 5 langkah:

```python
iq = np.fromfile("challenge.raw", dtype=np.complex64)
audio48 = iq.real[::5]
```

Spectrogram audio menunjukkan pola khas SSTV, terutama tone sekitar 1200 Hz, 1500 Hz, 1900 Hz, dan 2300 Hz. Ini cocok dengan mode Robot36.

## Analisis Static

Tidak ada binary untuk dibongkar memakai `objdump`, `readelf`, atau GDB. Analisis statis difokuskan pada struktur data:

- File XZ diekstrak menjadi raw sample.
- Raw sample dibaca sebagai IQ complex64.
- Real channel diturunkan menjadi audio baseband 48 kHz.
- Spectrogram memperlihatkan beberapa blok transmisi SSTV.
- Hasil decode SSTV memperlihatkan potongan barcode QR yang tidak utuh.

Judul *Sideband Surgery* memberi arah bahwa masalahnya bukan hanya decode SSTV biasa. Bagian QR tersebar sebagai strip yang perlu "dioperasi", disusun, lalu diperbaiki.

## Analisis Dynamic

Karena artefaknya berupa sinyal, dynamic analysis dilakukan dengan pemrosesan audio lokal, bukan menjalankan program.

Langkah yang dipakai:

1. Ekstrak raw sample.
2. Konversi ke audio 48 kHz dari real channel.
3. Decode empat transmisi SSTV Robot36.
4. Ambil strip QR dari tiap transmisi.
5. Buang baris kosong dari strip.
6. Stack strip menjadi satu citra QR rusak.
7. Sampling ulang citra ke grid QR version 3 berukuran 29x29 modul.
8. Perbaiki struktur QR yang pasti: tiga finder pattern, timing pattern, dan dark module.
9. Decode QR dengan OpenCV.

## Algoritma Validasi atau Encoding

Tidak ada validasi flag dalam program. Flag disembunyikan sebagai isi QR.

Struktur QR yang ditemukan:

```
QR version 3
Ukuran modul: 29 x 29
Finder pattern kanan atas dan kiri bawah masih terlihat
Finder pattern kiri atas rusak atau hilang
```

Karena finder pattern adalah struktur tetap pada QR, bagian itu bisa direkonstruksi tanpa menebak isi flag. Timing pattern dan dark module juga tetap untuk QR version 3. Setelah struktur tetap diperbaiki, error correction QR cukup untuk membaca payload.

Payload hasil decode:

```
ASIS{3V3RY_W4V3_C4RR13S_4_53CR3T}
```

## Penyusunan Solve Script

`solve.py` melakukan bagian akhir secara otomatis:

1. Membaca stack QR jika sudah ada.
2. Jika `crop_0.png` sampai `crop_3.png` ada, script menyusun ulang stack dari crop tersebut.
3. Jika file sementara tidak ada, script memakai stack terkompresi yang sudah diekstrak dari sinyal challenge sebagai fallback.
4. Script melakukan pencarian parameter grid QR di sekitar posisi yang sesuai.
5. Script memperbaiki finder pattern dan timing pattern.
6. Script merender QR baru.
7. Script mendecode QR dengan `cv2.QRCodeDetector()`.
8. Script mencetak flag dalam format `<FLAG>...</FLAG>`.

Bagian penting di script:

```python
n = 29
set_finder(mat, 0, 0)
set_finder(mat, 0, n - 7)
set_finder(mat, n - 7, 0)
```

Ini memperbaiki tiga finder pattern QR. Finder kiri atas memang rusak di hasil transmisi, jadi tanpa repair decoder QR sering gagal.

## Cara Menjalankan

Jalankan dari folder challenge:

```
python3 solve.py
```

Output:

```
<FLAG>ASIS{3V3RY_W4V3_C4RR13S_4_53CR3T}</FLAG>
```

Script akan menyimpan `recovered_qr.png` sebagai bukti QR hasil rekonstruksi.

## Flag

```
ASIS{3V3RY_W4V3_C4RR13S_4_53CR3T}
```
