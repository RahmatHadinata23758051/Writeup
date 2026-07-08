# Gold Hunters — Web CTF Writeup

**Challenge:** Gold hunters
**Kategori:** Web
**Flag:** `LYKNCTF{40673f5a25ca4839996af5d6464df643}`

## Deskripsi

> It looks like they intentionally or unintentionally put some gold in front of your eye. Can you find it?

Target: `http://<host>:8080/`

## Recon awal

Buka halaman utama dengan curl:

```
curl http://<host>:8080/
```

Responnya adalah halaman React (Vite build) biasa, tapi ada satu hal mencolok langsung di `<head>`:

```html
<script>
  window.API_KEY = "nqU5HIqRq0azdNGXo3fOl9cb57iksZ9Wt4IMrIjdDW4";
</script>
```

Sebuah API key ditaruh langsung di HTML, bisa dibaca siapa saja lewat "View Source". Ini jelas petunjuk utama — "gold di depan mata" secara harfiah.

## Membaca bundle JS

File JS di-load dari `/assets/index-B-T8Q2XM.js`. Di-download dan di-grep untuk endpoint API:

```
curl -s http://<host>:8080/assets/index-B-T8Q2XM.js -o app.js
grep -oE '"/api[^"]*"' app.js | sort -u
```

Hasil: hanya ada satu endpoint yang dipakai frontend, yaitu `/api/contact`. Kode React-nya ternyata form kontak sederhana (Chakra UI) yang POST ke endpoint ini. `window.API_KEY` yang bocor tadi tidak pernah dipakai di kode React manapun — jadi kemungkinan besar dia dipakai backend untuk endpoint tersembunyi yang tidak terhubung ke frontend.

## Menguji endpoint /api/contact

```
curl -X POST http://<host>:8080/api/contact \
  -H "Content-Type: application/json" \
  -d '{"name":"a","email":"a@a.com","message":"hi"}'
```

POST tanpa API key berhasil (201 Created), dan responnya mengembalikan `id` incremental. Karena id kita mulai dari 2 dan seterusnya, berarti sudah ada 1 baris data (`id=1`) sebelum kita mulai — kemungkinan data seed dari server.

Coba GET ke endpoint yang sama:

```
curl http://<host>:8080/api/contact
```

Hasilnya `401 Unauthorized — "Invalid or missing API key"`. Ini mengonfirmasi bahwa API key yang bocor di HTML memang dipakai untuk otorisasi endpoint GET (baca data), bukan untuk POST.

Coba lagi dengan header `x-api-key`:

```
curl http://<host>:8080/api/contact -H "x-api-key: nqU5HIqRq0azdNGXo3fOl9cb57iksZ9Wt4IMrIjdDW4"
```

Berhasil, dapat list semua submission. Tapi isi `id=1` cuma data dummy (`name: a, message: hi`), bukan flag — jadi flag-nya bukan di data ini.

## Menemukan endpoint tersembunyi via OpenAPI schema

Karena backend-nya terlihat seperti FastAPI (format error validasi 422 khas Pydantic), FastAPI biasanya otomatis expose schema OpenAPI. Path `/docs` dan `/openapi.json` di root domain ternyata selalu mengembalikan HTML SPA yang sama dengan status 200 — ini karena frontend/server melakukan catch-all routing untuk semua path yang bukan `/api/*`, jadi status 200 di path-path itu menyesatkan (bukan indikasi endpoint asli).

Backend asli hanya hidup di bawah prefix `/api/`. Maka openapi schema dicoba di:

```
curl http://<host>:8080/api/openapi.json -H "x-api-key: nqU5HIqRq0azdNGXo3fOl9cb57iksZ9Wt4IMrIjdDW4"
```

Berhasil, dan di dalam schema-nya ketemu path yang tidak pernah dipakai frontend:

```json
"/api/get-flag": {
  "get": {
    "summary": "Get Flag",
    "description": "Well done! You found the hidden flag endpoint."
  }
}
```

## Mengambil flag

```
curl http://<host>:8080/api/get-flag -H "x-api-key: nqU5HIqRq0azdNGXo3fOl9cb57iksZ9Wt4IMrIjdDW4"
```

Response:

```json
{"flag":"LYKNCTF{40673f5a25ca4839996af5d6464df643}"}
```

## Ringkasan alur solve

1. API key bocor di HTML halaman utama (`window.API_KEY`).
2. Bundle JS hanya memakai `/api/contact`, tidak ada petunjuk endpoint lain di frontend.
3. GET `/api/contact` butuh API key → konfirmasi key tadi valid untuk otorisasi.
4. Data di endpoint contact bukan flag, jadi cari endpoint tersembunyi lain.
5. `/docs` dan `/openapi.json` di root palsu (SPA catch-all), yang asli di bawah `/api/openapi.json`.
6. Schema OpenAPI membocorkan endpoint `/api/get-flag` yang tidak dipanggil dari frontend manapun.
7. Panggil endpoint tersebut dengan API key yang sama → flag didapat.

## Root cause

- API key sensitif ditaruh di kode client-side (exposed by design/mistake).
- Endpoint backend didaftarkan tanpa disembunyikan dari OpenAPI schema publik, sehingga endpoint "rahasia" tetap bisa ditemukan lewat introspeksi API standar FastAPI.
