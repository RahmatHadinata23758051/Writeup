# Contoso Asset Portal

## Ringkasan

Endpoint `/Default.aspx` memakai ViewState buatan aplikasi yang ditandatangani HMAC-SHA1. Kunci validasinya bocor di file backup, sehingga state `role` dan `asset` dapat dipalsukan.

## Target dan File

- Target: `http://chal.thjcc.org:31249`
- Artefak: `/backup/2024-legacy-web.config~` dan `/backup/assets.csv.bak`
- Solver: `solve.py`

## Analisis Awal

`/robots.txt` mengungkap `/backup/`. Backup konfigurasi memuat `validationKey` aktif dan menyebut bahwa key belum dirotasi. Backup CSV memberi konteks format asset ID.

POST normal menghasilkan pesan `role=guest`. Field `q` tidak mengubah state yang ditampilkan; nilai role dan asset berasal dari ViewState.

## Source Code Review

Source code tidak tersedia karena challenge blankbox. Dari ViewState valid yang diterima aplikasi, format state dapat diamati sebagai:

```text
ff 01 0c 01 <len(role)> <role> 01 <len(asset)> <asset> <20-byte HMAC-SHA1>
```

HMAC atas seluruh body sebelum signature cocok dengan `validationKey` dari backup.

## Vulnerability

Kunci signing ViewState terekspos di `/backup/2024-legacy-web.config~`. Karena aplikasi mempercayai role dan asset dari state yang hanya dilindungi oleh kunci tersebut, attacker dapat membuat ViewState valid dengan `role=admin`.

## Eksploitasi

1. Ambil `validationKey` dari backup.
2. Buat body ViewState dengan `role=admin` dan asset `AST-4F2A9C0`.
3. Tambahkan HMAC-SHA1 menggunakan key tersebut.
4. Encode seluruh body dan signature dengan Base64.
5. POST ke `/Default.aspx` sebagai `__VIEWSTATE`.

Response berubah menjadi `Access granted` dan memuat flag. ID `AST-4F2A9C` dari CSV adalah decoy; oracle response menunjukkan ID yang valid adalah `AST-4F2A9C0`.

## Solve Script

`solve.py` membangun ViewState forged, mengirim satu POST, lalu mengekstrak flag dari response aplikasi.

## Cara Menjalankan

```bash
python3 solve.py
TARGET=http://chal.thjcc.org:31249 python3 solve.py
```

## Flag

`THJCC{f0rg3d_v13wst4t3_w1th_l34k3d_m4ch1n3k3y}`

## Catatan Stabilitas

Eksploitasi bergantung pada `validationKey` yang masih aktif, format ViewState yang diamati, dan asset ID `AST-4F2A9C0`.
