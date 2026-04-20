# Writeup - Hit Your Limit (Web Misc)

## Informasi Challenge
- Nama: `Hit Your Limit`
- Kategori: `web misc`
- URL: `http://23.179.17.92:5559`

## Ringkasan Inti
Aplikasi menyediakan endpoint validasi flag per prefix:
- Endpoint normal: `/api/flag?guess=...`
- Jika prefix benar: status `200`
- Jika salah: status non-`200`
- Ada rate limit ketat: `5 request / ~300 detik` (status `429`)

Masalah utama challenge ini bukan brute force biasa, tapi mencari cara melewati limiter.

## Tahap Recon
Pertama saya lihat source halaman utama pakai `curl`, lalu ketemu JavaScript berikut (inti logic):
- frontend memanggil `fetch('/api/flag?guess=...')`
- status `200` dianggap `correct prefix`
- status `429` dianggap `rate limited`

Setelah itu saya spam request ke endpoint normal dan benar muncul limiter:
- response JSON menampilkan `"limit": 5`
- `message` berisi `Retry in ...s`

Saya juga coba bypass umum:
- spoof IP header (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, dll)
- ganti method (`POST`, `HEAD`, `OPTIONS`)
- ganti cookie
- manipulasi host/header lain

Semua tetap kena `429`.

## Temuan Vulnerability
Saat uji variasi path, ada behavior menarik:
- `/api/flag?guess=a` -> `429`
- `/api/flag/?guess=a` -> kadang `500`, kadang tetap diproses

Setelah dicek lebih teliti:
- Endpoint **trailing slash** (`/api/flag/`) ternyata bisa menjadi oracle.
- Pada endpoint ini:
  - tebakan prefix benar -> `200`
  - tebakan salah -> `500`
- Dan yang paling penting: endpoint ini bisa dipakai untuk brute force karakter tanpa mentok limiter seperti endpoint normal.

Jadi bug-nya adalah perbedaan handling route `/api/flag` vs `/api/flag/` yang membuat limiter/logic error bisa dibypass.

## Strategi Eksploitasi
Karena flag panjangnya 32 karakter, langkahnya:
1. mulai dari prefix yang sudah terkonfirmasi: `CIT{`
2. untuk setiap posisi berikutnya, coba semua karakter printable (`chr(32..126)`)
3. kirim request ke `/api/flag/?guess=<prefix+candidate>`
4. jika status `200`, candidate benar -> append ke prefix
5. ulangi sampai panjang 32

Agar cepat, setiap posisi dites paralel dengan thread pool.

## Solver
File solver disimpan di:
- `solver.py`

Contoh pakai venv kamu:
```bash
source /home/nata/ctf_env/bin/activate
python solver.py
```

Opsional:
```bash
python solver.py --workers 64 --charset printable --prefix 'CIT{'
```

## Flag
`CIT{R@T3_L1m1t1nG_15_Bypass@ble}`

## Catatan Teknis
- Kenapa endpoint salah bisa `500`? Kemungkinan ada exception handler yang menutup error internal jadi JSON generic.
- Meskipun `500`, perbedaan status (`200` vs `500`) tetap cukup sebagai side-channel oracle.
- Ini contoh klasik bug kombinasi:
  - route inconsistency
  - rate-limiter scope tidak konsisten
  - oracle berbasis status code
