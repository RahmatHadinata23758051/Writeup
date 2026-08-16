# Analisis Challenge: Ekstensi Browser Palsu

## Ringkasan

Artefak berisi ekstensi browser palsu. Isi pentingnya ada di `loader.js` dan `main.js`; keduanya di-obfuscate menggunakan Unicode escape, string reverse, dan Base64.

Ekstensi tidak perlu dijalankan di browser karena semua potongan flag dapat diambil langsung dari source.

**Flag yang didapat:**

```text
Thryve{br41nc4ntth_1nk4t4ll13467293}
```

## Analisis

`chal.zip` berisi beberapa file:

```text
mrrp/
├── img.GIF
├── loader.js
├── main.js
├── manifest.json
└── ui.html
```

`manifest.json` menunjukkan struktur yang menyerupai browser extension:

```json
"background": {
  "scripts": ["system/loader.js"]
},
"content_scripts": [{
  "matches": ["<all_urls>"],
  "js": ["core/main.js"]
}]
```

Namun, path yang tercantum di manifest sengaja tidak sesuai dengan isi ZIP:

* `system/loader.js` → file yang tersedia: `mrrp/loader.js`
* `core/main.js` → file yang tersedia: `mrrp/main.js`

Karena itu, fokus analisis bukan menjalankan extension, melainkan melakukan deobfuscation terhadap JavaScript.

## Deobfuscation

Source JavaScript penuh dengan Unicode escape, contohnya:

```javascript
"\u0056\u0047\u0068\u0079..."
```

Setelah dinormalisasi, mulai terlihat beberapa string penting.

### Bagian pertama

Di source terdapat:

```javascript
atob("VGhyeXZle2JyNDFuYzRudHRo")
```

String Base64 tersebut dapat didecode menjadi:

```text
Thryve{br41nc4ntth
```

Nilai ini juga digunakan sebagai AES key di `main.js`. Karena hasil decode sudah menyerupai prefix flag, bagian tersebut dicatat sebagai kandidat.

### Bagian kedua

Di `loader.js` terdapat literal Base64:

```text
XzFuazR0NGxsMTM0NjcyOTN9
```

Setelah di-decode:

```text
_1nk4t4ll13467293}
```

String yang sama juga muncul sebagai komentar di `main.js`:

```javascript
// _1nk4t4ll13467293}
```

## Rekonstruksi Flag

Gabungkan kedua bagian yang ditemukan:

```text
Thryve{br41nc4ntth
+
_1nk4t4ll13467293}
```

Hasil akhirnya:

```text
Thryve{br41nc4ntth_1nk4t4ll13467293}
```

## Menjalankan Solver

Solver dapat dijalankan dengan:

```bash
python3 solve.py chal.zip
```

Output:

```text
<FLAG>Thryve{br41nc4ntth_1nk4t4ll13467293}</FLAG>
```

## Final Flag

```text
Thryve{br41nc4ntth_1nk4t4ll13467293}
```
