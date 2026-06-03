# PNG is a lie (part 1/2)

Challenge ini ternyata jauh lebih sederhana daripada ukuran filenya bikin curiga.

## Ringkasan

File `weird_file.thc` bukan PNG, bukan arsip, dan bukan file biner biasa. `file` langsung ngasih tahu kalau isinya cuma teks UTF-8 satu baris yang sangat panjang. Kalau dilihat hexdump awalnya, polanya kelihatan jelas:

- ada emoji `👍`
- ada emoji `👎`
- di sela-selanya ada potongan huruf acak

Awalnya kelihatan seperti noise, tapi distribusinya terlalu rapi. Karena judul challenge menyinggung PNG, pendekatan paling masuk akal adalah cari encoding paling simpel dulu.

## Langkah analisis

Saya cek beberapa hal dasar:

1. `file weird_file.thc`
2. `xxd -l 128 weird_file.thc`
3. hitung pola token dan karakter yang muncul

Hasil pentingnya:

- file cuma berisi pasangan `emoji + huruf`
- hurufnya tampak acak
- emoji cuma dua jenis, jadi kandidat paling natural buat bit `0/1`

Di titik ini saya coba decode paling sederhana: abaikan semua huruf, ambil emoji saja.

- `👍` dijadikan bit `1`
- `👎` dijadikan bit `0`
- setiap 8 bit digabung jadi 1 byte

Begitu 8 byte pertama hasil decode dicek, header-nya langsung cocok dengan magic PNG:

`89 50 4e 47 0d 0a 1a 0a`

Itu signature PNG yang valid.

## Ekstraksi

Setelah stream emoji di-pack ke byte, hasilnya adalah file PNG valid berukuran `1000x1000`.

Langkah verifikasi yang saya pakai:

- `file decoded_from_emoji.png`
- `pngcheck -v decoded_from_emoji.png`

Gambar hasil decode menampilkan tulisan flag langsung di pojok kanan atas:

`THC{PNG3D}`

Tulisan lain seperti `M4terM4xima` dan `much you dying, vewy fun` cuma bagian dari desain gambarnya, bukan flag.

## Automasi

Script final ada di `solve.py`.

Script itu melakukan tiga hal:

1. membaca `weird_file.thc`
2. mengubah stream emoji menjadi PNG
3. crop area flag dan pakai `tesseract` untuk mengambil teks `THC{PNG3D}` secara otomatis

Jalankan dengan:

```bash
python3 solve.py
```

Output yang diharapkan:

```text
THC{PNG3D}
```

## Flag

`THC{PNG3D}`
