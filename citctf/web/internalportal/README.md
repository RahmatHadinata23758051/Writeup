# Writeup - Intern Portal (Web Misc)

## Ringkasan
Challenge ini rentan pada **broken access control**:
1. Kredensial lemah/default (`admin:admin`) masih aktif.
2. Endpoint report memakai parameter `id` yang bisa diakses lintas user (**IDOR / missing authorization check**).

Dengan login sebagai admin dan enumerasi `id` report, flag bisa diambil dari report milik user lain.

## Informasi Target
- URL: `http://23.179.17.92:5001`
- Halaman awal redirect ke `/login`
- Endpoint penting:
  - `POST /login`
  - `POST /register`
  - `GET /` (dashboard)
  - `POST /report` (buat report)
  - `GET /report?id=<id>` (lihat report berdasarkan ID)

## Langkah Eksploitasi

### 1. Recon awal
Gunakan curl untuk cek perilaku aplikasi:
```bash
curl -i http://23.179.17.92:5001/
```
Hasil: redirect ke `/login`.

### 2. Login dengan kredensial lemah
Coba beberapa default credential, ternyata `admin:admin` valid (HTTP 302 ke `/`).

Contoh:
```bash
curl -i -X POST http://23.179.17.92:5001/login -d 'username=admin&password=admin'
```

### 3. Identifikasi IDOR di report
Setelah login, dashboard menampilkan daftar report dengan link format:
- `/report?id=514`
- `/report?id=543`
- dst

Endpoint ini hanya bergantung pada `id` dan tidak melakukan validasi ownership yang benar.
Akibatnya, user login dapat membuka report user lain dengan mengganti nilai `id`.

### 4. Enumerasi ID report untuk cari flag
Lakukan brute force ID secara bertahap (misal 1..5000), parse konten report, lalu cari pola flag `CIT{...}`.

Flag ditemukan pada:
- `report id = 347`
- konten: `CIT{Acc355_C0ntr0l_M@tt3rs!}`

## Flag
`CIT{Acc355_C0ntr0l_M@tt3rs!}`

## Solver Otomatis
File solver sudah disediakan di:
- `solve.py`

Jalankan:
```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output sukses:
```text
[+] Flag ditemukan di report id=347
<FLAG>CIT{Acc355_C0ntr0l_M@tt3rs!}</FLAG>
```

## Dampak Kerentanan
- Kebocoran data antar akun.
- Data sensitif (termasuk flag/internal report) dapat diakses user yang tidak berhak.
- Menurunkan confidentiality secara penuh.

## Rekomendasi Perbaikan
1. Hapus default credential, paksa password kuat.
2. Terapkan authorization check di `GET /report?id=...`:
   - pastikan `report.owner_id == session.user_id` (atau role admin yang benar-benar tervalidasi).
3. Tambahkan monitoring percobaan enumerasi ID dan rate limit.
4. Gunakan UUID/ID non-sekuensial untuk mempersulit enumerasi.
