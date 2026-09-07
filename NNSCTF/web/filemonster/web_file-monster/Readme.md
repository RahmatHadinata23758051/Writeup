# File Monster

## Ringkasan

Flag disisipkan backend ke isi file upload ketika konten memuat token `FLAG`.
MongoDB mengizinkan JavaScript server-side lewat operator `$where`, dan module
loader JavaScript dapat membaca file relatif dari `/tmp` dengan specifier
`../tmp/<nama-file>`. File JavaScript upload kemudian melempar flag sebagai
exception, sehingga flag muncul di response error MongoDB.

## Target dan File

- Web: `https://file-monster-bac4c2e3fb1d.chall.nnsc.tf`
- MongoDB TLS: `file-monster-db-bac4c2e3fb1d.chall.nnsc.tf:1337`
- Source utama: `src/index.ts`

## Analisis Awal

Endpoint upload menerima filename alfanumerik dengan ekstensi titik, lalu
menulis file ke `/tmp/<filename>`. Isi file dibersihkan dari quote dan token
`FLAG` pertama diganti dengan `process.env.FLAG`.

MongoDB hanya memberi user `viewer` role `read` pada database
`file-monster`, tetapi role tersebut tetap dapat menjalankan query `$where`.

## Source Code Review

Bug upload berada di `src/index.ts`:

```ts
const path = `/tmp/${file.name}`;
const txt = (await file.text())
  .replaceAll('"', '')
  .replaceAll("'", '')
  .replaceAll('`', '')
  .replace('FLAG', process.env.FLAG ?? 'nns{demo_flag}');
await Bun.write(path, txt);
```

MongoDB menerima query `$where`, yang mengeksekusi JavaScript dalam scope
Mongo. Scope ini tidak punya `db`, `process`, atau API file langsung, tetapi
`eval` dan dynamic `import()` tersedia.

## Vulnerability

Ada dua bagian yang dirangkai:

1. Upload arbitrary file ke `/tmp` dengan substitusi flag.
2. Dynamic import dari `$where` membaca dan mengevaluasi module lokal.

Specifier absolute `file:///tmp/...` ditolak, tetapi `../tmp/...` resolve ke
`/tmp` dari base module loader `/`.

## Eksploitasi

File pertama berisi:

```js
throw /FLAG/
```

Setelah upload, isinya menjadi regex berisi flag asli. Regex valid karena
karakter `{}` berada di dalam regex literal. Module import menghasilkan
Promise rejection yang nilainya adalah regex tersebut.

Query `$where` memasang rejection handler pada dokumen pertama, lalu melempar
`String(e)` pada dokumen kedua. MongoDB mengembalikan exception JavaScript
dalam response command, termasuk nilai flag.

## Solve Script

`solve.py` mengupload module payload dan file trigger, lalu menjalankan query
MongoDB TLS sebagai `viewer/viewer`. Script hanya memakai host challenge dari
environment atau nilai default instance ini.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Untuk instance lain:

```bash
WEB='https://host-challenge' \
MONGO='host-mongodb' \
python3 solve.py
```

## Flag

Flag diambil langsung dari exception response MongoDB, bukan ditebak atau
direkonstruksi.

## Catatan Stabilitas

Solver membuat filename unik setiap run dan mengupload dua dokumen agar ada
invokasi `$where` kedua untuk membaca hasil Promise rejection.
