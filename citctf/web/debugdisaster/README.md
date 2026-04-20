# Debug Disaster - Writeup

## Ringkasan
Challenge ini sengaja membiarkan Flask berjalan dalam mode debug di production. Dari situ traceback Werkzeug menampilkan potongan source code route handler, dan ternyata ada endpoint tersembunyi yang membaca file `.env` secara langsung.

Flag didapat tanpa brute force berat atau RCE debugger, cukup dari information disclosure.

## Informasi Target
- URL: `http://23.179.17.92:5002`
- Kategori: Web / Misc
- Fingerprint awal:
  - Header server: `Werkzeug/3.1.8 Python/3.11.15`
  - Halaman `/` hanya menampilkan: `Welcome to Startup Portal`

## Langkah Eksploitasi
1. Enumerasi endpoint sederhana.
   - Hasil menarik: `/admin` ada dan merespons `500` (bukan `404`).

2. Buka `/admin` dan baca debug traceback Werkzeug.
   - Di traceback, source snippet dari `/app/app.py` terlihat jelas:
     - Route `/admin` sengaja `raise Exception(...)`
     - Ada route lain: `/flg_bar`
     - Fungsi route itu melakukan `open(".env").read()` dan mengembalikannya sebagai plaintext.

3. Akses endpoint tersembunyi `/flg_bar`.
   - Response berisi isi file `.env`, termasuk variabel `FLAG`.

## Bukti Request
```bash
curl -s http://23.179.17.92:5002/flg_bar
```

Contoh output:
```text
SECRET_KEY=supersecret
FLAG=CIT{H1dd3n_D1r5_3v3rywh3r3}
DATABASE_URL=sqlite:///prod.db
```

## Flag
`CIT{H1dd3n_D1r5_3v3rywh3r3}`

## Dampak Kerentanan
- Debug mode aktif di production menyebabkan source/path internal bocor.
- Endpoint internal yang seharusnya tidak ada (`/flg_bar`) masih tertinggal.
- Sensitive file exposure: `.env` dapat diakses publik melalui route.

## Rekomendasi Perbaikan
1. Matikan debug mode di production (`debug=False`).
2. Hapus route debug/development sebelum deploy.
3. Jangan pernah expose isi `.env` lewat endpoint HTTP.
4. Tambahkan CI check untuk mencegah route/fitur debug ikut ter-deploy.

## Solver
File solver otomatis sudah disiapkan di:
- `solve.py`

Jalankan:
```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
# atau target lain:
python3 solve.py http://23.179.17.92:5002
```
