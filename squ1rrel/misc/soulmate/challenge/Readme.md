# Writeup - misc/soulmate

Challenge ini kelihatan seperti web app AI biasa, tapi inti bug-nya ada di **design API**.

## 1) Enumerasi

Saya mulai dengan baca source utama:
- `backend/app.py`
- `models/inference.py`
- frontend JS untuk melihat endpoint yang dipanggil.

Endpoint penting:
- `GET /generate-random` -> generate wajah dari seed tanggal lahir
- `POST /submit-u` -> menerima vektor kontrol `u` (dimensi PCA), lalu:
  1. `u` di-clip ke batas bawah/atas
  2. diubah ke latent `w`
  3. digenerate jadi image
  4. diskor classifier selebriti
  5. kalau `tom_score >= 0.15`, server mengembalikan `flag`

## 2) Akar masalah

`/submit-u` membuka akses langsung ke ruang kontrol latent (`u`) **dan mengembalikan nilai objektif** (`tom_score`) setiap request.

Artinya, endpoint ini jadi **oracle optimasi**. Kita tidak perlu ngerti model internal, cukup lakukan black-box optimization untuk memaksimalkan `tom_score` sampai melewati threshold.

Tambahan petunjuk dari artefak challenge:
- ada file `checkpoints/pca_basis_d8_tom_weighted.npz`
- ini mengindikasikan basis PCA memang sudah dibentuk agar arah tertentu lebih condong ke kelas Tom Cruise.

Jadi eksploit realistisnya: cari `u` yang mendorong score >= threshold.

## 3) Eksploitasi

Saya buat solver otomatis `solve.py`:
- query `GET /health` untuk ambil:
  - `control_dim`
  - `u_lower`, `u_upper`
  - `tom_score_threshold`
- inisialisasi `u` di tengah batas
- lakukan random local search + restart global:
  - sampling kandidat di sekitar best saat ini
  - clip ke range valid
  - kirim ke `/submit-u`
  - pakai `tom_score` sebagai feedback
- stop ketika response `success=true` dan `flag` muncul

Pendekatan ini murni black-box dan stabil untuk service yang ngasih score per request.

## 4) Hasil pada instance lokal

Pada environment lokal challenge ini, flag tersedia sebagai:

`squ1rrel{test_flag}`

## 5) Catatan keamanan

Fix yang benar (kombinasi):
- jangan expose endpoint latent-control mentah ke user publik,
- jangan kembalikan score kontinu yang bisa dipakai sebagai oracle,
- rate limit + anomaly detection untuk query optimasi,
- verifikasi challenge condition di sisi internal yang tidak bisa di-query berulang secara bebas.
