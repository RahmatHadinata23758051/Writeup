# Writeup - web/pretend-it-is-a-text-editor

## Ringkasan
Challenge ini terlihat seperti aplikasi notes biasa (register/login/create note), tapi ada endpoint preview:

`GET /api/notes/:id/embed?width=...`

Bug utamanya adalah **IDOR** pada endpoint embed: note orang lain bisa diakses tanpa autentikasi yang benar.

Selain itu, endpoint embed membocorkan detail layout teks (lebar tiap baris). Dengan `width=1`, hampir setiap karakter dipaksa jadi baris sendiri, sehingga response berisi **urutan width per karakter**. Itu cukup untuk merekonstruksi isi note target.

## Recon
Langkah awal:
1. Buka root app dan ambil asset JS (`/app.js`)
2. Dari frontend, terlihat endpoint:
   - `/api/register`, `/api/login`, `/api/logout`, `/api/me`, `/api/notes`
   - `/api/notes/:id/embed?width=400`
3. Uji akses endpoint embed langsung untuk note ID lain.

Temuan:
- `/api/notes` butuh auth (401 jika anon)
- `/api/notes/:id/embed` **tetap bisa diakses** walau anon / bukan owner

Ini konfirmasi IDOR.

## Eksploitasi Kebocoran Konten
Response embed bentuknya seperti:

```json
{
  "width": 1,
  "lineHeight": 24,
  "lineCount": 39,
  "height": 936,
  "lines": [
    {"width": 7.02},
    {"width": 8.88},
    ...
  ]
}
```

Dengan `width=1`, line breaking sangat agresif. Praktiknya jadi deretan width yang merepresentasikan karakter demi karakter.

Strategi decode:
1. Register akun random
2. Buat note sendiri berisi charset yang kita kontrol (a-zA-Z0-9 + simbol)
3. Panggil embed note kita dengan `width=1`
4. Bangun map `width -> character`
5. Ambil embed note target (ID 1) pakai `width=1`
6. Translate setiap width target ke karakter dari map

Hasil decode:

`squ1rrel{pr3t3xt_i5_sup35fUn_i5_It_n0T}`

## Flag

`<FLAG>squ1rrel{pr3t3xt_i5_sup35fUn_i5_It_n0T}</FLAG>`

## Solver
File solver sudah disimpan di:
- `solver.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/ctf/squ1rrel/web/pretentexteditor
python3 solver.py
```

Output final akan menampilkan decoded flag dan format `<FLAG>...</FLAG>`.

## Dampak dan Akar Masalah
Akar masalah gabungan:
1. **Broken access control (IDOR)** pada `/api/notes/:id/embed`
2. **Sensitive side-channel leakage**: endpoint tidak mengembalikan teks langsung, tapi metadata layout cukup untuk recover teks

Perbaikan yang seharusnya:
1. Wajib verifikasi owner note di endpoint embed
2. Jangan expose detail layout granular untuk note private
3. Batasi parameter dan response agar tidak bisa dipakai oracle karakter
