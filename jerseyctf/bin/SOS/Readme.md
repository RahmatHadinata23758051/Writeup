# Writeup Challenge Rev - SOS

## Ringkasan
Challenge ini ngasih dua artefak utama: satu binary `astro_beacon` dan satu teks `sos_message.txt` yang kelihatannya biasa aja. Petunjuk dari deskripsi bilang pesan SOS asli disembunyikan di dalam "boring looking message".

Flag akhir yang didapat:

`jctf{lost_in_space}`

## Enumerasi Awal
Pertama cek isi folder:

- `astro_beacon`
- `sos_message.txt`
- `challenge_prompt.txt`

Lalu cek tipe file:

- `astro_beacon`: ELF 64-bit, not stripped
- `sos_message.txt`: UTF-8 text

Dari isi `sos_message.txt`, kelihatan ada karakter aneh (zero-width) nyelip di tengah kalimat. Ini indikasi kuat steganografi berbasis karakter unicode tak terlihat.

## Analisis Binary
String di binary menunjukkan fitur:

- mode `encode` dan `decode`
- output file `decode_result.txt`
- prompt: `Paste the weird space message:`

Jadi cara paling cepat dan aman: pakai decoder internal dari binary buat mengekstrak bit tersembunyi.

## Eksploitasi / Ekstraksi
Saya jalankan binary di mode decode (`d`) lalu feed isi `sos_message.txt`.

Hasilnya binary menulis `decode_result.txt`.

Isi file ini ternyata gabungan:

- teks biasa
- deretan bit `0` dan `1` (payload tersembunyi)

Langkah berikut:

1. Ambil hanya karakter `0` dan `1`.
2. Kelompokkan per 8 bit (1 byte).
3. Konversi dari biner ke ASCII.

Hasil decode langsung membentuk:

`jctf{lost_in_space}`

## Solver Otomatis
File `solve.py` dibuat untuk otomatisasi full flow:

1. Jalankan `astro_beacon` dalam mode decode.
2. Kirim input dari `sos_message.txt`.
3. Baca `decode_result.txt`.
4. Ekstrak bit `0/1`.
5. Decode ke string dan regex flag format `jctf{...}`.
6. Print flag.

Jalankan:

```bash
python3 solve.py
```

Output:

```text
jctf{lost_in_space}
```

## Catatan
Pendekatan ini tidak butuh brute force dan tidak perlu menebak mapping unicode manual, karena decoder asli dari challenge dipakai langsung untuk membongkar payload sebelum parsing final.
