Berikut versi `.md` yang sudah dirapikan dan dibuat konsisten sebagai writeup CTF.

````markdown id="58321"
# Writeup — Oops

## Deskripsi

Challenge memberikan clue:

> I am from the future! I accidentally forgot to link `chall.zip`! Surely you can find it and solve it right?

Pada halaman challenge, file `chall.zip` tidak tersedia secara langsung. Namun challenge berjalan di platform CTFd, sehingga metadata challenge dapat diperiksa melalui API untuk mencari informasi mengenai file dan lokasi penyimpanannya.

---

## 1. Recon Challenge

URL challenge:

```text
https://play.scriptsorcerers.xyz/challenges#Oops-74
```

Dari URL tersebut diketahui bahwa ID challenge adalah:

```text
74
```

Metadata challenge kemudian dapat diperiksa melalui API:

```javascript
fetch('/api/v1/challenges/74')
  .then(r => r.json())
  .then(j => console.log(JSON.stringify(j.data, null, 2)))
```

Bagian penting dari response:

```json
{
  "name": "Oops",
  "category": "Crypto",
  "files": []
}
```

Dari sini terlihat bahwa challenge memang tidak memiliki file yang terdaftar pada field `files`.

Namun clue menyebutkan bahwa `chall.zip` sebenarnya ada dan hanya "forgot to link".

---

## 2. Mencari File yang Hilang

Langkah berikutnya adalah memeriksa metadata challenge lain untuk mengetahui pola lokasi file yang digunakan oleh platform.

Browser console dapat digunakan untuk mencari seluruh referensi file:

```javascript
(async()=>{
  let cs=(await fetch('/api/v1/challenges').then(r=>r.json())).data;

  for(let c of cs){
    let d=await fetch('/api/v1/challenges/'+c.id)
      .then(r=>r.json())
      .catch(()=>null);

    let s=JSON.stringify(d?.data||{});

    let m=s.match(
      /\/files\/[^"'\\<>\s]+|chall[^"'\\<>\s]*\.zip|[^"'\\<>\s]+\.zip/gi
    );

    if(m)
      console.log(
        '---',
        c.id,
        c.name,
        c.category,
        '\n' + [...new Set(m)].join('\n')
      );
  }
})()
```

Dari challenge lain ditemukan pola penyimpanan file pada S3 bucket:

```text
https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/<Category>/<Challenge>/<file>
```

Challenge yang dicari memiliki:

```text
Category : Crypto
Name     : Oops
File     : chall.zip
```

Dengan mengikuti pola tersebut, path file menjadi:

```text
https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip
```

File kemudian berhasil di-download:

```bash
wget -O chall.zip \
'https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip'
```

Isi archive:

```bash
unzip chall.zip
```

Menghasilkan:

```text
chall.py
enc.txt
```

---

## 3. Analisis Source Code

Isi `chall.py`:

```python
import random
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

flag = open('flag.txt','rb').read()

random.seed(int(time.time())) # Preserves upto the MINUTE, not seconds ;)
key = random.randbytes(32)

cipher = AES.new(key, AES.MODE_ECB)

enc = cipher.encrypt(pad(flag,16)).hex()

open('enc.txt', 'w').write(enc)
```

Ciphertext pada `enc.txt`:

```text
d37cbce47f0c71a75d644badb77039e48ab1645f60ddebe928c0a3c417561345b4852636ecb388ec79417357100da120
```

---

## 4. Menemukan Vulnerability

Bagian paling penting dari source code adalah:

```python
random.seed(int(time.time()))
key = random.randbytes(32)
```

Key AES tidak dibuat menggunakan random number generator cryptographically secure. Sebaliknya, key berasal dari PRNG Python `random`, yang seed-nya ditentukan langsung oleh waktu UNIX:

```python
int(time.time())
```

Dengan kata lain:

```text
timestamp
    ↓
random.seed(timestamp)
    ↓
random.randbytes(32)
    ↓
AES key
```

Jika timestamp yang digunakan dapat diperkirakan, key dapat direproduksi.

Clue pada source code bahkan memberikan petunjuk langsung:

```python
# Preserves upto the MINUTE, not seconds ;)
```

Artinya informasi waktu yang relevan hanya perlu dicari dalam satu menit tertentu.

Secara teori terdapat sekitar:

```text
60 kemungkinan detik
```

untuk setiap menit.

---

## 5. Memanfaatkan Timestamp ZIP

Metadata ZIP menyimpan timestamp file sampai resolusi detik:

```python
zf = zipfile.ZipFile("chall.zip")
dt = zf.getinfo("enc.txt").date_time
```

Timestamp tersebut memberikan:

```text
year
month
day
hour
minute
second
```

Karena timezone metadata ZIP tidak selalu langsung jelas, solver mencoba beberapa kemungkinan offset timezone.

Untuk setiap kemungkinan timezone:

1. Ambil timestamp awal pada menit tersebut.
2. Coba seluruh `0..59` detik.
3. Gunakan timestamp tersebut sebagai seed.
4. Generate ulang AES key.
5. Dekripsi ciphertext.
6. Periksa apakah padding valid.
7. Periksa apakah plaintext memiliki format flag.

---

## 6. Solver

Solver lengkap:

```python
import zipfile
import random

from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


ct = bytes.fromhex(
    open("enc.txt").read().strip()
)

zf = zipfile.ZipFile("chall.zip")

dt = zf.getinfo("enc.txt").date_time

y, mo, d, h, mi, s = dt

print("[*] ZIP enc.txt time:", dt)


def try_seed(seed):
    random.seed(seed)

    key = random.randbytes(32)

    cipher = AES.new(
        key,
        AES.MODE_ECB
    )

    pt = cipher.decrypt(ct)

    try:
        pt = unpad(pt, 16)
    except ValueError:
        return None

    if b"scriptCTF{" in pt:
        return pt

    return None


base_naive = datetime(
    y,
    mo,
    d,
    h,
    mi,
    0
)


for off in range(-12, 15):

    tz = timezone(
        timedelta(hours=off)
    )

    base = base_naive.replace(
        tzinfo=tz
    )

    epoch0 = int(
        base.timestamp()
    )

    for sec in range(60):

        seed = epoch0 + sec

        pt = try_seed(seed)

        if pt:
            print("[+] Found!")
            print("seed =", seed)
            print("utc_offset =", off)
            print(pt.decode())

            raise SystemExit
```

Jalankan:

```bash
python3 solve.py
```

Output:

```text
[+] Found!
seed = ...
utc_offset = ...
scriptCTF{mY_buck37_1s_l34k1ng!}
```

---

## 7. Kenapa Brute Force Sangat Kecil?

Biasanya brute-forcing seed berbasis `time.time()` dapat menjadi sangat besar jika waktu eksekusi tidak diketahui.

Namun challenge memberikan beberapa petunjuk:

```text
I am from the future!
```

dan komentar:

```python
# Preserves upto the MINUTE, not seconds ;)
```

Selain itu, timestamp file di dalam ZIP memberikan perkiraan waktu pembuatan ciphertext.

Akibatnya search space dapat dipersempit menjadi:

```text
beberapa timezone × 60 detik
```

Jumlah tersebut sangat kecil untuk dicoba.

Setelah seed yang benar ditemukan, prosesnya deterministik:

```text
seed
 ↓
Python random PRNG
 ↓
32-byte AES key
 ↓
AES-ECB decrypt
 ↓
PKCS#7 unpad
 ↓
flag
```

---

## 8. Inti Kerentanan

Masalah utama challenge bukan pada AES-256 maupun mode ECB secara langsung.

Masalah utamanya adalah **key generation**:

```python
random.seed(int(time.time()))
key = random.randbytes(32)
```

`random` Python tidak dirancang untuk menghasilkan cryptographic key.

Untuk menghasilkan key kriptografis seharusnya digunakan CSPRNG seperti:

```python
import secrets

key = secrets.token_bytes(32)
```

Dengan pendekatan tersebut, key tidak dapat direproduksi hanya dengan mengetahui timestamp.

---

## Flag

```text
scriptCTF{mY_buck37_1s_l34k1ng!}
```

---

