# Escape Room Writeup

Challenge ini hanya memberi akses ke service `nc 10.42.5.10 9998`, jadi fokus utamanya adalah memahami protokol ASCII yang dipakai service lalu mengotomatiskan penyelesaiannya secepat mungkin.

## Ringkasan

Setelah konek, service menampilkan banner lalu menunggu `Enter`. Sesudah itu muncul maze ASCII ukuran `21x21` dengan:

- `#` sebagai dinding
- `X` sebagai posisi pemain
- `E` sebagai pintu keluar
- prompt `Move(s):` untuk menerima input

Setiap level bisa diselesaikan dengan mengirim string gerakan seperti `SSSDWW`. Tantangannya bukan eksploit memory corruption, tetapi menyelesaikan 20 maze acak dalam batas waktu sekitar 60 detik. Karena maze berubah tiap koneksi, solusi manual atau path hardcoded tidak cukup.

## Observasi Penting

- Output memakai ANSI clear-screen, jadi parser harus membuang escape sequence.
- Setelah satu string gerakan dikirim, service menganimasikan perpindahan pemain frame per frame.
- Karena animasi menghasilkan banyak redraw, parser yang hanya membaca sebagian output akan mudah salah menangkap grid.
- Yang stabil adalah prompt `Move(s):`. Jadi pendekatan yang aman adalah menunggu sampai prompt itu muncul, lalu mengambil frame lengkap terakhir sebelum prompt.

## Strategi Solusi

Solusi paling sederhana adalah:

1. Koneksi ke service.
2. Kirim `Enter` untuk mulai.
3. Tunggu sampai muncul `Move(s):`.
4. Ambil frame terakhir level aktif.
5. Parse maze menjadi grid 2D.
6. Jalankan BFS dari `X` ke `E`.
7. Kirim seluruh path sekaligus.
8. Ulangi sampai flag muncul.

BFS cukup karena semua edge bernilai sama dan ukuran maze kecil, jadi sangat cepat.

## Detail Parser

Service mengirim banyak frame seperti:

```text
--- Level 4/20 | Time Left: 56s ---
#####################
#X      #   #       #
...
Move(s):
```

Saya strip ANSI dengan regex:

```python
r"\x1b\[[0-9;]*[A-Za-z]"
```

Lalu saya ambil frame lengkap terakhir dengan regex yang mencari header level diikuti 21 baris maze dan prompt `Move(s):`.

## Algoritma Pathfinding

Untuk setiap grid:

- cari koordinat `X`
- cari koordinat `E`
- BFS dengan arah `W`, `A`, `S`, `D`
- simpan parent untuk rekonstruksi path
- kirim path hasil rekonstruksi dalam satu baris

Karena ukuran grid kecil, BFS selesai instan dan total 20 level masih jauh di bawah limit waktu.

## Hasil

Solver berhasil menyelesaikan semua 20 level dan service mengembalikan flag:

```text
RAM{35C4P3_r00M_C134r3D}
```

## File

- `solve.py`: solver otomatis end-to-end untuk challenge ini.

## Cara Menjalankan

```bash
python3 solve.py
```

Atau jika host/port berubah:

```bash
python3 solve.py <host> <port>
```
