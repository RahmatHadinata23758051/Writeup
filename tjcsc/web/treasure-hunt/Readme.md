# Treasure Hunt Writeup

Challenge ini minta kita ngumpulin flag yang dipecah jadi 4 bagian. Dari deskripsi, panitia sudah kasih bagian pertama:

`tjctf`

Target:

`https://treasure-hunt.tjc.tf`

## 1. Enumerasi halaman utama

Pertama saya cek halaman utama:

```bash
curl -iLsS https://treasure-hunt.tjc.tf/
```

Isi HTML utamanya sederhana:

```html
<h1>Learn about pirates!</h1>
<form method="POST">
    <input type="submit" value="Learn More">
</form>
<p hidden>_and_</p>
```

Di sini sudah ada petunjuk penting:

- Ada form `POST`, berarti kemungkinan server punya perilaku berbeda kalau tombol ditekan.
- Ada elemen tersembunyi `<p hidden>_and_</p>`, yang sangat mungkin merupakan salah satu potongan flag.

Dari sini kita simpan dulu:

Potongan ke-3: `_and_`

## 2. Cek apa yang terjadi saat form di-submit

Karena ada form `POST`, langkah berikutnya adalah kirim request POST ke `/`:

```bash
curl -iLsS -X POST https://treasure-hunt.tjc.tf/
```

Respons server:

```http
HTTP/2 302
location: /extra_info
set-cookie: silver_coffer={s1lv3r; Path=/
```

Ini menarik karena:

- Server me-redirect kita ke `/extra_info`
- Server juga mengirim cookie `silver_coffer`
- Nilai cookie tersebut adalah `{s1lv3r`

Jadi ini jelas potongan flag berikutnya.

Potongan ke-2: `{s1lv3r`

Saya verifikasi sekali lagi dengan Python `requests` supaya parsing cookie-nya pasti benar:

```python
import requests
r = requests.post('https://treasure-hunt.tjc.tf/', allow_redirects=False)
print(r.cookies.get_dict())
```

Hasilnya:

```python
{'silver_coffer': '{s1lv3r'}
```

Jadi tidak ambigu, memang nilainya `{s1lv3r`.

## 3. Cek file yang sering bocor petunjuk

Di challenge web ringan seperti ini, `robots.txt` sering dipakai buat nyimpen hint. Saya cek:

```bash
curl -iLsS https://treasure-hunt.tjc.tf/robots.txt
```

Hasil:

```txt
User-agent: *
Disallow: /gold-coffer
Allow: /
```

Kalau sebuah path sengaja di-`Disallow`, hampir pasti itu patut dibuka.

Lalu saya akses endpoint tersebut:

```bash
curl -iLsS https://treasure-hunt.tjc.tf/gold-coffer
```

Responsnya cuma:

```txt
g0ld}
```

Ini jelas potongan terakhir.

Potongan ke-4: `g0ld}`

## 4. Rekonstruksi flag

Sekarang semua potongan yang terkumpul:

1. `tjctf`
2. `{s1lv3r`
3. `_and_`
4. `g0ld}`

Gabungkan berurutan:

```txt
tjctf{s1lv3r_and_g0ld}
```

## Flag

```txt
tjctf{s1lv3r_and_g0ld}
```

## Inti challenge

Challenge ini sebenarnya lebih ke arah teliti waktu enumerasi daripada eksploitasi berat. Semua bagian flag disebar di tempat-tempat yang sering kelewat:

- deskripsi challenge
- HTML tersembunyi
- cookie hasil POST
- `robots.txt` dan endpoint yang diarahkan dari sana

Kalau langsung cek source HTML, perilaku `POST`, dan file umum seperti `robots.txt`, challenge ini selesai sangat cepat.
