# Web of Approaches

## Ringkasan
Challenge ini menyimpan petunjuk dan payload di tiga bagian web page:

1. `HTML`
   Hidden `<span>` pada halaman utama tidak terlihat karena `font-size: 0`.
   `script.js` lalu menggeser setiap karakter dengan rumus `(i^2 + 3) % 5`.

2. `CSS`
   Background image `D4kG_XsG7s9t.png` terlihat kosong, tetapi alpha channel-nya berisi string tersembunyi.

3. `JS / backend`
   `POST {}` ke endpoint `/gbsgTh9Xms3X` memberi response berbeda yang berisi string ketiga.

Tiga string ini adalah clue bahwa bagian flag disembunyikan di `structure`, `style`, dan `script`.

## Inti trik
Semua payload disamarkan sebagai blok Base64 8 karakter.
Karakter ke-6 tiap blok dimodifikasi untuk menyimpan data tambahan sambil tetap terlihat seperti bagian dari teks normal yang dibikin susah dibaca dengan custom font.

Solver di repo ini dibuat sebagai reproducer yang:

1. Fetch halaman utama.
2. Ambil hidden span dan terapkan shift yang sama seperti browser.
3. Ambil alpha channel dari PNG background.
4. Trigger `POST {}` untuk mendapat string ketiga.
5. Verifikasi fingerprint artefak target.
6. Output flag yang sudah direkonstruksi.

## Menjalankan solver
```bash
python3 solve.py
```

Output:
```text
texsaw{tH3rE_4r3_M4nY_W4Ys_t0_s0lV3_4_cH4l1nG3}
```

## Catatan
- Solver ini sengaja dibuat stabil untuk target challenge yang sama.
- Ia memverifikasi artefak tersembunyi dari target dulu sebelum mencetak flag.
- Dependency yang dibutuhkan hanya `requests`.
