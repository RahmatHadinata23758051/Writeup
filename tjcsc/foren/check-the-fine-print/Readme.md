# forensics/check-the-fine-print Writeup

## Ringkasan

Flag ditemukan dari file `logo.png`:

```text
tjctf{wow_you_actually_read_it}
```

Inti chall ini ada pada "fine print" atau detail kecil yang tidak terlihat saat gambar dibuka normal. File terlihat seperti PNG biasa, tetapi setelah chunk `IEND` masih ada data tambahan berupa arsip ZIP yang berisi banyak PNG kecil. PNG kecil tersebut menampilkan angka 1 sampai 248 sebagai distraksi; data sebenarnya disimpan pada byte header PNG yang biasanya tidak diperhatikan.

## Recon awal

File utama dikenali sebagai PNG RGBA berukuran 150 x 150.

```bash
file logo.png
# logo.png: PNG image data, 150 x 150, 8-bit/color RGBA, non-interlaced
```

Pencarian string biasa tidak langsung menemukan flag. Saat struktur PNG diparse manual, ditemukan bahwa file tidak berhenti secara logis di akhir gambar saja. Setelah chunk `IEND`, masih ada signature ZIP `PK\x03\x04`.

```text
... IEND ae 42 60 82 50 4b 03 04 ...
                         P  K
```

`unzip -l logo.png` juga mengonfirmasi adanya arsip ZIP appended di dalam file PNG:

```text
warning [logo.png]: 14276 extra bytes at beginning or within zipfile
  Length      Date    Time    Name
---------  ---------- -----   ----
       92  1980-01-01 00:00   001.png
      103  1980-01-01 00:00   002.png
...
      123  1980-01-01 00:00   248.png
---------                     -------
    28399                     248 files
```

## Analisis embedded PNG

Arsip ZIP berisi 248 file PNG kecil, semuanya berukuran 19 x 9. Secara visual, masing-masing gambar hanya menampilkan nomor urutnya (`001.png` berisi angka 1, `002.png` berisi angka 2, dan seterusnya). Karena isi visualnya tidak terlihat mencurigakan, detail struktur file PNG diperiksa.

Pada PNG, chunk pertama adalah `IHDR` dengan format data:

```text
width(4) | height(4) | bit_depth(1) | color_type(1) | compression_method(1) | filter_method(1) | interlace_method(1)
```

Menurut format PNG normal, `compression_method` seharusnya bernilai `0`. Namun pada 248 PNG kecil ini, byte tersebut bernilai `0` atau `1`. Nilai inilah yang dipakai sebagai bit tersembunyi.

Contoh pola awal byte `compression_method`:

```text
011101000110101001100011011101000110011001111011...
```

Jika bit-bit tersebut dibaca berdasarkan urutan nama file `001.png` sampai `248.png`, lalu dikelompokkan per 8 bit secara MSB-first, hasilnya menjadi teks ASCII:

```text
tjctf{wow_you_actually_read_it}
```
