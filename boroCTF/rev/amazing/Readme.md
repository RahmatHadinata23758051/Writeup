# Amazing - Writeup

Tantangan ini adalah game labirin Python sederhana yang menggunakan "stream cipher" berbasis LCG untuk menyembunyikan flag di dalam sebuah fungsi yang di-marshal.

## Analisis
Di dalam `chall.py`, terdapat fungsi `hope()` yang dipanggil setiap kali pemain bergerak. Fungsi ini menghitung nilai `mod` berdasarkan posisi pemain `(r, c)`:
```python
mod = (r ^ (c + c)) * r
```
Nilai `mod` ini digunakan sebagai seed awal untuk fungsi `rsa_encrypt` (yang sebenarnya bukan RSA, tapi stream cipher sederhana). Hasil dekripsi kemudian di-load menggunakan `marshal.loads()` dan dijalankan sebagai fungsi `impossible()`.

## Strategi
Karena ukuran labirin hanya 100x100, kita bisa melakukan brute force untuk semua kemungkinan posisi `(r, c)` (total 10.000 kombinasi) untuk menemukan nilai `mod` yang menghasilkan objek Python valid.

Beberapa kendala yang ditemukan:
1. `marshal.loads()` bisa menyebabkan crash jika diberikan data sampah.
2. Kita perlu memfilter `mod` yang menghasilkan bytecode valid (berawal dengan tag `0x63` untuk Python 3.12).

## Solusi
Dengan menggunakan script `solve.py` yang melakukan brute force pada nilai `mod`, kita menemukan bahwa `mod = 19201` menghasilkan objek kode (CodeType) yang valid. 

Setelah kita inspeksi konstanta (constants) dari objek kode tersebut, ditemukan string Base64: `Ym9yb0NURntlczRAcGVfd0E1XzFuZXYhdGFibGV9`.

Decoding Base64 tersebut menghasilkan flag:
`boroCTF{es4@pe_wA5_1nev!table}`

Flag: `<FLAG>boroCTF{es4@pe_wA5_1nev!table}</FLAG>`
