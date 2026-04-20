# Writeup CTF - web/blog

## Informasi Challenge
- Kategori: web misc
- Judul: `web/blog`
- Target: `http://blog.fraud.llc/`
- Deskripsi: `I spent so long securing my blog. hope you enjoy`

## Ringkasan Temuan
Aplikasi memakai React Router (SSR). Route `/admin` memang diproteksi Cloudflare Access (Zero Trust), tapi endpoint data route milik React Router yaitu `/admin.data` **tidak ikut diproteksi**. Dari endpoint ini, data sensitif loader admin tetap bisa diambil tanpa login.

Intinya: proteksi dipasang di UI route (`/admin`), tapi lupa menutup data endpoint alternatif (`/admin.data`).

## Langkah Eksploitasi

### 1) Recon awal homepage
Saya mulai dari:
```bash
curl -i http://blog.fraud.llc/
```

Dari HTML terlihat:
- Ini aplikasi React Router SSR.
- Ada link ke `/admin`.
- Ada file manifest/bundle JavaScript yang bisa diinspeksi.

### 2) Cek akses `/admin`
```bash
curl -i https://blog.fraud.llc/admin
```

Respons `302` redirect ke halaman Cloudflare Access login. Artinya route utama admin memang ditutup.

### 3) Enumerasi manifest dan route module
Dari manifest React Router, ketemu route:
- `routes/admin`
- module JS: `/assets/admin-<hash>.js`
- route ini punya `loader` (`hasLoader: true`)

Di module admin terlihat halaman merender string:
- `squ1rrel{zero_trust?` + data dari loader

Jadi flag dibentuk dari dua bagian:
1. Prefix statis di frontend admin module
2. Suffix dinamis dari loader route admin

### 4) Uji endpoint data route
Karena React Router data request sering pakai `*.data`, saya uji:
```bash
curl -i http://blog.fraud.llc/admin.data
```

Respons berhasil (`200`) dan mengembalikan data loader admin, termasuk suffix:
- `_still_have_to_trust_your_configuration}`

Jadi walaupun `/admin` ke-block Zero Trust, data sensitif tetap bocor lewat `/admin.data`.

### 5) Gabungkan potongan flag
- Prefix dari module admin: `squ1rrel{zero_trust?`
- Suffix dari loader: `_still_have_to_trust_your_configuration}`

Flag:
```text
squ1rrel{zero_trust?_still_have_to_trust_your_configuration}
```

## Solver
Saya simpan solver otomatis di file:
- `solver.py`

Cara jalanin:
```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py
```

Output solver akan langsung mencetak flag.

## Akar Masalah Teknis
Masalah utamanya bukan bypass cryptography/auth token, tapi **misconfiguration access control**:
- Proteksi cuma mengunci `/admin`
- Endpoint data framework (`/admin.data`) lupa disamakan policy-nya

Ini sering kejadian pada app modern (Next/Remix/React Router) karena satu halaman punya beberapa surface endpoint: HTML route, data route, kadang API route.

## Rekomendasi Perbaikan
1. Terapkan policy Zero Trust ke semua route turunan dan data endpoint terkait (`/admin*`, termasuk `*.data`, query `_data`, dsb).
2. Jangan kirim data sensitif dari loader tanpa validasi session di sisi aplikasi.
3. Tambahkan integration test untuk endpoint non-UI (data/API), bukan hanya test akses halaman HTML.
4. Audit seluruh route framework-generated endpoint setiap deploy.

