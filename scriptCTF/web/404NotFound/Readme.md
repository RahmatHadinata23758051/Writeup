# 404 Found

## Ringkasan

Challenge ini adalah blankbox: tidak ada source code atau Dockerfile di direktori kerja. Aplikasi remote berupa toko Flask bernama Lumina.

## Target dan File

- Target: `https://7b5f0d66-18b4-4dbe-a0a2-b5cdb855dc5c.challs.scriptsorcerers.xyz`
- File solver: [solve.py](./solve.py)

## Analisis Awal

HTTP pada port 80 mengarahkan ke HTTPS. Homepage mengembalikan halaman toko Flask dan `robots.txt` tersedia.

Isi penting `robots.txt`:

```text
User-agent: *
Disallow: /the-best-robot
```

## Source Code Review

Tidak ada source code lokal untuk direview. JavaScript dan HTML yang dikembalikan aplikasi menunjukkan fitur toko biasa; tidak diperlukan untuk memperoleh flag.

## Vulnerability

Informasi sensitif diekspos melalui route yang secara eksplisit disembunyikan dari crawler menggunakan `robots.txt`. `robots.txt` bukan mekanisme access control, sehingga route tetap dapat diminta langsung.

## Eksploitasi

Request:

```http
GET /the-best-robot HTTP/1.1
Host: 7b5f0d66-18b4-4dbe-a0a2-b5cdb855dc5c.challs.scriptsorcerers.xyz
```

Response body:

```text
scriptCTF{r0b07s_4r3_t4k1ng_0v3r_84423053a8f0}
```

## Solve Script

`solve.py` meminta `/the-best-robot`, memeriksa status HTTP, lalu mengambil pola flag dari body response. Target dapat diganti melalui environment variable `TARGET`.

## Cara Menjalankan

```bash
python3 solve.py
TARGET="https://target-challenge" python3 solve.py
```

## Flag

`scriptCTF{r0b07s_4r3_t4k1ng_0v3r_84423053a8f0}`

## Catatan Stabilitas

Eksploitasi stabil selama route `/the-best-robot` tetap tersedia. Flag diambil langsung dari response aplikasi, bukan ditebak atau direkonstruksi.
