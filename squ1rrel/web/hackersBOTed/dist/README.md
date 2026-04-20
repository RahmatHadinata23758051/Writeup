# Writeup - hackersBOTted (web/misc)

Challenge ini punya flow:
- Upload foto ke `/api/spot`
- Backend pakai Google Vision OCR/label/face untuk ekstrak teks
- Tiap hasil deteksi dicek lewat fungsi `isAdmin(name)`

Masalah utamanya ada di query SQL pada `backend/db.js`:

```js
const query = `SELECT role FROM users WHERE name = '${cleaned}'`;
```

Input `name` tidak diparameterisasi. Sanitasi yang ada cuma hapus `--`, `/*`, `*/`, jadi masih bisa SQL injection pakai statement lain.

## Ide Eksploitasi

Karena `name` berasal dari OCR hasil gambar, payload SQL ditulis sebagai teks di dalam gambar lalu di-upload.

Tujuan exploit:
1. Bypass pengecekan admin supaya request lanjut.
2. Ubah username admin aktif (yang terus berotasi) jadi nilai yang kita tahu, misalnya `ownedadmin`.
3. Panggil `/api/flag` dengan username itu.

Payload yang dipakai:

```sql
x' UNION SELECT 'user'; UPDATE users SET name='ownedadmin' WHERE role='admin'; SELECT 'user
```

Kenapa ini jalan:
- `UNION SELECT 'user'` bikin baris pertama result punya role `user`, jadi fungsi `isAdmin` menganggap bukan admin.
- `UPDATE users SET name='ownedadmin' WHERE role='admin'` mengganti nama admin acak saat ini ke `ownedadmin`.
- Setelah itu, endpoint `/api/flag` menerima `ownedadmin` sebagai admin valid dan ngasih flag.

## Solver

File solver: `solve.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Atau pakai URL custom:

```bash
python solve.py http://hackersbotted.squ1rrel.dev
```

Script akan:
- generate gambar payload secara otomatis (Pillow)
- kirim ke `/api/spot`
- request `/api/flag` dengan username hasil takeover
- print flag

## Flag

`squ1rrel{g3t_sp0773d_b0z0_l0l}`
