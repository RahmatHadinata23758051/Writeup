# MID

## Ringkasan

Service meminta pencarian password acak sepanjang 30 karakter. Jawaban perbandingan hanya jujur jika state yang dikirim cocok dengan mood service.

## File Challenge

- `chall.py`: implementasi service lokal.
- `solve.py`: solver binary search dengan pemulihan setelah mood switch.

## Analisis Awal

Password dibuat dari alphabet base62:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

Ukuran ruang pencarian adalah `62^30`, sehingga dibutuhkan 179 query binary search karena `ceil(log2(62^30)) = 179`.

Mood awal adalah `0` dan berpindah sekali ke `1` pada query acak antara 0 dan 195. Jika state yang dikirim tidak cocok dengan mood, service mengembalikan jawaban acak antara `smaller` dan `larger`.

## Temuan Penting

Solver memakai state `0` untuk 179 query pertama. Jika mood belum berpindah, binary search langsung menemukan password. Jika mood sudah berpindah cukup awal, riwayat interval sebelum switch masih bisa dipakai sebagai checkpoint, lalu pencarian dilanjutkan dengan state `1` menggunakan sisa query.

Karena titik switch acak, solver mengulang koneksi sampai salah satu percobaan mendapatkan interval yang masih valid. Host solver menggunakan target resmi dan dapat dioverride dengan environment variable `HOST` dan `PORT`.

## Proses Ekstraksi

Perintah yang dijalankan:

```bash
python3 -u solve.py
```

Pada attempt ketiga, solver menemukan flag setelah fallback pada checkpoint query 164.

## Solve Script

`solve.py` mengubah integer midpoint menjadi string base62 sepanjang 30 karakter, mengirim query melalui TLS, membaca respons `smaller`/`larger`, dan memperbarui interval binary search. Setelah mode switch terdeteksi secara implisit melalui kegagalan jalur awal, solver mencoba checkpoint yang masih muat diselesaikan oleh sisa query.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Target default:

```text
mid2-78e6619bb7eb02f0.challs.ctf.thefewchosen.com:1337
```

Override target jika diperlukan:

```bash
HOST="mid2-78e6619bb7eb02f0.challs.ctf.thefewchosen.com" PORT=1337 python3 solve.py
```

## Flag

```text
TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}
```

## Catatan

Beberapa koneksi awal tampak lambat karena service mengirim prompt secara tertunda. Solver perlu dibiarkan melakukan retry.
