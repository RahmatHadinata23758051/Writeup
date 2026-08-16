# Writeup CTF Misc — TeaGod666

## Informasi Challenge

**Judul:** TeaGod666
**Kategori:** Misc / Web / Firmware Analysis
**Target:**

```text id="y8fqai"
http://chal.thjcc.org:7254/
```

Challenge ini menampilkan halaman admin router fiktif bernama **TeaGod666**. Dari deskripsi challenge, banyak petunjuk yang mengarah ke router, firmware update, default credential, dan sistem log.

---

## Recon Awal

Pertama, halaman utama diakses menggunakan `curl`:

```bash id="a0pbzm"
curl http://chal.thjcc.org:7254/
```

Dari source HTML/JavaScript, ditemukan beberapa endpoint API penting, yaitu:

```text id="aa4zpr"
/api/update/check
/api/update/package?channel=stable
/api/login
/api/session
/api/router
/api/system/logs?level=info
```

Endpoint tersebut terlihat langsung dari JavaScript frontend. Fungsi `checkVersion()` memanggil `/api/update/check`, lalu hasilnya menampilkan `package_url`. Selain itu, form login mengirim request ke `/api/login`, lalu setelah login berhasil frontend mengambil data router melalui `/api/router`.

---

## Mengecek Endpoint Update

Endpoint update dicek terlebih dahulu:

```bash id="da6hdp"
curl -s "$U/api/update/check" | jq
```

Output:

```json id="s19ko0"
{
  "current_version": "TG666-1.4.2",
  "latest_version": "TG666-1.4.2",
  "update_available": false,
  "package_url": "/api/update/package?channel=stable"
}
```

Meskipun tidak ada update baru, endpoint tetap memberikan URL package:

```text id="z3vk54"
/api/update/package?channel=stable
```

Package tersebut kemudian diunduh:

```bash id="sk02e8"
curl -sSL -D hdr.txt -o pkg.bin "$U/api/update/package?channel=stable"
file pkg.bin
wc -c pkg.bin
```

Output menunjukkan ukuran file sangat kecil:

```text id="xjhq5w"
pkg.bin: data
237 pkg.bin
```

Karena ukurannya kecil, file ini kemungkinan bukan firmware asli, melainkan data challenge yang disamarkan.

---

## Analisis File Package

File dicek dengan `xxd`:

```bash id="sy1gr4"
xxd -l 256 pkg.bin
```

Output awal:

```text id="xt67he"
00000000: 5445 4147 4f44 3636 0100 0b00 3600 4100  TEAGOD66....6.A.
...
00000030: 076f c151 5b4d 7465 6173 686f 702d 3636  .o.Q[Mteashop-66
00000040: 3644 3063 4d48 4177 4b48 4138 4d46 4749  6D0cMHAwKHA8MFGI
...
```

Terlihat ada magic header:

```text id="j7u5c8"
TEAGOD66
```

Kemudian ada string menarik:

```text id="v52hhz"
teashop-666
```

Setelah string tersebut, terdapat data berbentuk base64.

Pengecekan dengan `strings` juga memperlihatkan data yang sama:

```bash id="aer5ol"
strings -a pkg.bin | head -80
```

Output:

```text id="j83ipa"
TEAGOD66
XVmB0
Q[Mteashop-666D0cMHAwKHA8MFGIRBCYcDFlGGxQaFAEWBAEGDh1IFAwUFQEMGgZNXA9GV0UHEg4BDE1KD1lZWhsLBiwcChFyAAAAVklDHQcbFQ8MFHAVBhUcGhZQXlNEQB0GBFMJDBNCQ1hCWkUzHBwOBEgWV1AAABNTDgYCXkIWVBsKFV1KEg==
```

Awalnya data base64 dicoba langsung, tetapi hasilnya rusak. Ini menandakan bahwa base64 tersebut bukan plaintext langsung, melainkan ciphertext yang masih perlu didekripsi.

---

## Eksploitasi Package

Karena ditemukan string `teashop-666` tepat sebelum base64, string tersebut dicoba sebagai key XOR.

Script decode:

```python id="w25wm6"
import base64

d = open("pkg.bin", "rb").read()

key = b"teashop-666"

i = d.index(key) + len(key)

ct = base64.b64decode(d[i:])

pt = bytes(c ^ key[j % len(key)] for j, c in enumerate(ct))

print(pt.decode())
```

Jalankan:

```bash id="dawko3"
python3 solve_pkg.py
```

Output:

```json id="p49mpp"
{
  "model": "TeaGod666",
  "username": "admin",
  "password": "oolong_tea_666",
  "note": "Factory service account. Rotate after first boot."
}
```

Dari sini ditemukan credential factory service account:

```text id="pnbpeu"
username: admin
password: oolong_tea_666
```

---

## Login Sebagai Admin

Login dilakukan menggunakan credential yang ditemukan:

```bash id="edrs51"
curl -i -s -c c.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"oolong_tea_666"}' \
  "$U/api/login"
```

Output:

```http id="hy1x4n"
HTTP/1.0 200 OK
Set-Cookie: teagod_session=iHPIka4eVxy-92HpSgLLwwbppNx36IxZJGbJSTcxZmg; HttpOnly; SameSite=Lax; Path=/

{"ok": true}
```

Login berhasil dan server memberikan cookie session `teagod_session`.

Session kemudian dicek:

```bash id="f2mr9i"
curl -s -b c.txt "$U/api/session" | jq
```

Output:

```json id="sr4k7o"
{
  "authenticated": true
}
```

---

## Membaca Log Debug

Setelah login berhasil, endpoint log dapat diakses. Pertama dicek log level `info`:

```bash id="da02er"
curl -s -b c.txt "$U/api/system/logs?level=info" | jq
```

Namun log info hanya menampilkan event biasa seperti WAN link, DNS, client join, dan admin login.

Kemudian dicoba level `debug`:

```bash id="jvkoqi"
curl -s -b c.txt "$U/api/system/logs?level=debug" | jq
```

Output berisi event tambahan:

```json id="ain7z6"
{
  "time": "2026-08-15T05:42:27+00:00",
  "level": "DEBUG",
  "event": "factory_validation",
  "message": "maintenance note: THJCC{t3ag0d666_h77p5://y0u7u.b3/Dji_wUhFPvo?si=z1B9a-4nShzop-du&t=1577}"
}
```

Flag ditemukan pada log debug di event `factory_validation`.

---

## Flag

```text id="bqqug8"
THJCC{t3ag0d666_h77p5://y0u7u.b3/Dji_wUhFPvo?si=z1B9a-4nShzop-du&t=1577}
```

---

