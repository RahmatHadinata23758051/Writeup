# flagchecker6767 Writeup

Challenge ini adalah sebuah reverse engineering berbasis maze traversal. Kita diberikan sebuah script Python `chall.py` dan sebuah file teks `sixseven.txt` yang berisi grid karakter '6' dan '7'.

## Analisis Script
Di dalam `chall.py`, terdapat logika untuk mengacak sebuah list karakter (`seven`) berdasarkan seed tertentu (`67`). Karakter-karakter ini dipetakan ke jarak pergerakan di dalam maze.
- `six = "sctf{sixsevenSIXSEVEN6767}"`
- `seven` adalah list karakter unik dari `six` yang di-shuffle.
- Maze dimulai dari koordinat `(1, 1)` dan target akhirnya adalah `(247, 219)`.
- Pergerakan bergantian antara Horizontal dan Vertical.
- Jarak pergerakan ditentukan oleh index karakter input di dalam list `seven` + 1.
- Karakter '7' di dalam grid `sixseven.txt` berfungsi sebagai tembok. Jika koordinat perantara (antara titik awal dan akhir pergerakan) adalah '7', maka input dianggap salah.

## Solusi
Karena ini adalah masalah pencarian jalur di dalam maze dengan batasan pergerakan (alternating horizontal/vertical), kita bisa menggunakan algoritma Breadth-First Search (BFS).

Langkah-langkah:
1. Rekonstruksi list `seven` yang digunakan oleh script.
2. Load grid dari `sixseven.txt`.
3. Gunakan BFS dengan state `(x, y, is_horizontal)` untuk mencari jalur terpendek dari `(1, 1)` ke `(247, 219)`.
4. Setiap langkah di BFS mencoba semua kemungkinan karakter dari `seven` (jarak 1-19).
5. Gabungkan karakter-karakter yang membentuk jalur tersebut menjadi flag.

Setelah menjalankan solver, kita mendapatkan flag: `sctf{sIXxX67SevEnNn6767}`.

Validasi:
```bash
echo "sctf{sIXxX67SevEnNn6767}" | python3 chall.py
# Output: flag: good
```

Flag: `<FLAG>sctf{sIXxX67SevEnNn6767}</FLAG>`
