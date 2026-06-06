# Simple Food Notifications - Writeup

## Gambaran Singkat

Target ini adalah aplikasi Flask yang menerima `url` notifikasi saat order makanan dibuat. Setelah beberapa detik, server akan melakukan request ke URL itu dan menyimpan body respons ke endpoint `/notification/<id>`.

Flag ada di endpoint tersembunyi `/vip-meal`, tapi endpoint ini hanya mau melayani request yang datang dari `127.0.0.1`.

## Temuan Utama

File yang paling penting ada di [`app/app.py`](/home/nata/ctf/GPNCTF2026/web/Simplefoodnotifications/simple-food-notifications/app/app.py).

Alur yang relevan:

1. User kirim `POST /order` dengan parameter `url`.
2. Server menyimpan status order.
3. Setelah delay 5-15 detik, server:
   - resolve hostname dengan `socket.getaddrinfo()`,
   - menolak kalau ada IP non-global,
   - lalu melakukan `urllib3.request('GET', url, ...)`.
4. Respons GET itu disimpan ke `/notification/<id>`.

Bagian pentingnya ada di sini:

```python
addresses = socket.getaddrinfo(urllib3.util.parse_url(url).host, 80)
for addr in addresses:
    if (not ipaddress.ip_address(addr[4][0]).is_global):
        notifications[id] = {
            "message": "Only staff is allowed to see mess in the kitchen, we don't want you to see the rats.",
            "status": "REJECTED"
        }
        return

r = urllib3.request('GET', url, redirect=False, timeout=urllib3.Timeout(30))
```

Artinya ada celah klasik DNS rebinding:

- validasi hostname dilakukan dulu,
- request aslinya dilakukan belakangan,
- ada jeda beberapa detik di antara dua langkah itu.

## Kenapa Bisa Bypass

Saya pakai domain rebinding publik `rbndr.us`.

Format hostname yang dipakai:

```text
7f000001.08080808.rbndr.us
```

Domain ini bisa berganti IP antar query. Target melihat IP global saat validasi, lalu saat request kedua domain sudah mengarah ke `127.0.0.1`.

Karena `/vip-meal` hanya membolehkan request dari localhost, ini cukup untuk membaca flag.

## Payload

Request yang dikirim ke target:

```text
http://7f000001.08080808.rbndr.us/vip-meal
```

Langkahnya:

1. Submit order dengan URL di atas.
2. Tunggu status order berubah dari `COOKING`.
3. Saat backend akhirnya fetch URL itu, rebinding membuat request mendarat di localhost.
4. `/vip-meal` mengembalikan HTML yang berisi flag.
5. Body itu muncul di `/notification/<id>`.

## Hasil

Flag yang didapat:

```text
GPNCTF{why_make_i7_cOMPl3x_when_yOu_CAn_MAkE_17_siMPL3}
```

## Catatan

Saya sempat coba beberapa variasi hostname dan beberapa kali hasilnya masih `REJECTED`, jadi exploit ini memang agak probabilistik. Yang penting adalah tetap pakai hostname rebinding yang sama dan ulangi order sampai validation + fetch akhirnya kena urutan yang benar.

