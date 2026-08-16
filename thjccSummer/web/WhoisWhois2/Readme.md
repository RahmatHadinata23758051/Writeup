# Who is Whois? 2

## Ringkasan

Target menyediakan lookup WHOIS. Input query diteruskan ke binary `whois` dan option command-line tidak dibatasi dengan benar. Ini memungkinkan pengaturan host dan port tujuan.

## Target dan File

- Target: `http://chal.thjcc.org:5000`
- Challenge berupa blankbox; tidak ada source code lokal.
- File solusi: [solve.py](./solve.py)

## Analisis Awal

Endpoint utama adalah `POST /whois` dengan JSON `{"query":"..."}`. Query normal menghasilkan record WHOIS. Query `--help` membuktikan bahwa input diproses sebagai argumen binary WHOIS.

## Vulnerability

Option injection pada client WHOIS memungkinkan option `-h` dan `-p` dikendalikan user. Contoh koneksi ke Redis internal:

```text
-h 127.0.0.1 -p 6379 'KEYS *'
```

Redis merespons dan menampilkan key `pwn_flag`, sehingga ini juga membuktikan SSRF/TCP pivot ke service loopback challenge.

## Eksploitasi

Request WHOIS berikut mengirim command Redis `GET pwn_flag` ke `127.0.0.1:6379`:

```text
-h 127.0.0.1 -p 6379 'GET pwn_flag'
```

Response aplikasi berisi Redis bulk-string response dengan nilai flag.

## Solve Script

`solve.py` mengirim payload tersebut ke `/whois`, mengambil field `output`, lalu mencocokkan flag dari response yang benar-benar diterima.

## Cara Menjalankan

```bash
python3 solve.py
TARGET=http://chal.thjcc.org:5000 python3 solve.py
```

## Flag

```text
THJCC{Wh0_15_wH015???WH0_15_wh0_15:D}
```

## Catatan Stabilitas

Endpoint memiliki limiter/concurrency guard. Jalankan script satu kali dan tunggu bila response berstatus `busy`.
