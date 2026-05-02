# Writeup Challenge: Northstar

Challenge ini seru banget! Intinya kita harus nge-bypass sistem keamanan berlapis: ada Next.js di belakang dan Proxy Python di depan yang jagain input.

## Walkthrough: Dari Analisis Sampe Flag

### 1. Bedah Isi Perut (Analisis Source)
Pas pertama dapet source code-nya, gue langsung fokus ke dua hal:
*   **`proxy.py`**: Ini sistem filternya. Dia nge-block kata `proto` (nggak peduli gede-kecil hurufnya). Dia juga nge-parse `multipart/form-data` pake library bawaan Python.
*   **Next.js (Server Actions)**: Ada fungsi di `serverActions.ts` yang nerima data user. Versi Next.js-nya `16.0.6`, yang mana di challenge ini punya perilaku spesifik kalo kena **Prototype Pollution**.

### 2. Nyari Celah di Proxy
Gue sempet nyoba berbagai trik buat masukin `__proto__`:
*   Pake JSON aneh-aneh? Gagal, proxy-nya pinter.
*   Pake encoding UTF-16? Gagal juga, proxy-nya tetep bisa baca.
*   **Ketemu!** Gue nyoba teknik **Parameter Duplication** di header `Content-Disposition` pas kirim data `multipart`.

Di Python, library `email` bakal ambil parameter pertama yang dia liat. Tapi di Node.js (Next.js), dia malah ambil yang terakhir. 
Contoh header selundupan gue:
`Content-Disposition: form-data; name="aman"; name="__proto__[name]"`
*   **Proxy liat**: `name="aman"` -> "Oh, aman nih, lewat!"
*   **Next.js liat**: `name="__proto__[name]"` -> "Oke, gue proses ini buat polusi prototype!"

### 3. Eksekusi (The Kill Chain)
*   **Cari Target**: Gue inspeksi kode JS di browser buat nyari `Action ID` dari fungsi `processData`. Dapet ID-nya: `4041c5a7aa2f58ac1e5d773a90b4af6376b2ea1f26`.
*   **Kirim Payload**: Gue bikin script Python buat ngirim request `multipart` yang isinya dobel parameter tadi. Gue arahin buat nge-pollute `Object.prototype.name`.
*   **Ambil Flag**: Terakhir, gue pancing pake request Server Action biasa tapi isinya kosong `[{}]`. Karena server bingung nggak ada data nama, dia nyomot dari prototype yang udah gue kasih flag.

### 4. Hasil Akhir
Server ngejawab dengan string yang isinya flag:
`"Thanks CBC{6cc6abdf24b2ece791cff9c75f5fdddb}..."`

---

## Kesimpulan Singkat
Gue dapet flag lewat **Inconsistency Parser** antara Python (Proxy) dan Node.js (Next.js). Proxy-nya ngerasa udah aman, padahal kita bisa nyelundupin payload lewat parameter kedua di header multipart.

**Flag:** `CBC{6cc6abdf24b2ece791cff9c75f5fdddb}`
