# TAGGER

## Ringkasan

Bug utama ada pada cache riwayat chat. Key cache memakai `username.trim()`, tetapi query database memakai ID user. Username seperti `Hacker ` dan `FlagHolder ` bisa dibuat untuk berbagi key cache dengan akun bot asli. Message juga menerima mass assignment pada `tagName`, `attributes`, dan `content`, sehingga bisa dibuat XSS yang dieksekusi browser bot.

## Target dan File

- Target: `https://tagger-ddd1d4e474ac9f31.challs.ctf.thefewchosen.com`
- File penting: `routes/messages.js`, `services/messageMarkup.js`, `bot/index.js`, `solve.py`

## Analisis Awal

Bot melakukan dua langkah setiap 60 detik:

1. Login sebagai `Hacker`, membuka chat `FlagHolder`.
2. Jika preview pesan tepat `Give me the flag!`, login sebagai `FlagHolder` lalu mengirim flag.

Riwayat chat dicache dengan key:

```js
`${firstUsername.trim()}:${secondUsername.trim()}`
```

Namun isi cache berasal dari query berdasarkan ID. Ini memungkinkan chat fake dengan username ber-spasi menimpa key chat bot.

## Source Code Review

`messageRecord()` menyalin field dari request body selain ID dan timestamp. `messageMarkup()` kemudian merender `tagName` dan atribut yang dikontrol user. CSP mengizinkan inline event handler dan `unsafe-eval`.

Payload XSS yang dipakai:

```html
<p class="cursor"
   onanimationstart="window.onerror=eval"
   onanimationiteration="throw this.textContent">=PAYLOAD</p>
```

CSS class `cursor` menjalankan animasi. Chrome melaporkan thrown string ke `window.onerror` sebagai `Uncaught <text>`, sehingga awalan `=` membuat hasilnya menjadi assignment expression yang valid saat dievaluasi.

## Vulnerability

Ada dua bug yang digabungkan:

1. Cache collision akibat normalisasi username tanpa membedakan ID.
2. Stored XSS akibat mass assignment dan raw rendering atribut/event handler.

XSS pada chat fake dijalankan saat bot membuka chat real karena cache collision. Payload Hacker membuat pesan real `Give me the flag!`. Payload FlagHolder memasang listener pada form, lalu meneruskan isi input flag ke akun receiver yang dikendalikan solver.

## Eksploitasi

`solve.py` melakukan hal berikut:

1. Register `Hacker ` dan `FlagHolder `.
2. Membuat friendship fake dan menanam dua payload XSS.
3. Meminta receiver unik, lalu payload FlagHolder mengirim flag ke receiver.
4. Membaca chat receiver sampai flag muncul.

Jalankan:

```bash
python3 solve.py https://tagger-ddd1d4e474ac9f31.challs.ctf.thefewchosen.com
```

Output valid yang diperoleh:

```text
[+] flag captured
<FLAG>TFCCTF{Tagg3r_m15C0muN1cA710n}</FLAG>
```

## Solve Script

Script lengkap tersimpan di [solve.py](./solve.py).

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py 'https://HOST-INSTANCE.challs.ctf.thefewchosen.com'
```

## Flag

```text
TFCCTF{Tagg3r_m15C0muN1cA710n}
```

## Catatan Stabilitas

Exploit bergantung pada siklus bot 60 detik dan TTL cache 60 detik. Solver menunggu hingga cache real terisi kembali dan memeriksa chat receiver secara berkala.
