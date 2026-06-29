# Tiny — Reverse Engineering

Flag: `VIT{^}`

## Ringkasan

Binary `tini_rev` adalah ELF64 statically linked yang sengaja dibuat kecil dan section header-nya rusak. `objdump` tidak nyaman dipakai, tapi program header masih valid dan entry point ada di `0x400070`.

Program membaca maksimal 256 byte dari stdin, lalu menjumlahkan semua byte input sampai newline atau carriage return. Nilai checksum itu dipakai untuk mengurangi tabel `word` internal. Setelah itu hasilnya dirender sebagai RLE bitmap berisi karakter `0` dan `1`.

## Analisis

Struktur data penting ada di offset berikut:

- `0x1b8 .. 0x37e`: 227 word terenkripsi.
- `0x37e .. 0x388`: jumlah run per baris untuk 10 baris.
- output akhir: bitmap `140 x 10`.

Format tabel setelah didecode:

```text
[height, xscale, yscale]
[row_run_count, start_bit, run_1, run_2, ...]
[row_run_count, start_bit, run_1, run_2, ...]
...
```

Nilai checksum bisa dipulihkan tanpa brute force. Untuk setiap baris, jumlah semua run length harus menjadi 140. Jika `E_i` adalah run terenkripsi dan jumlah run pada baris adalah `n`, maka:

```text
sum(E_i - checksum) = 140
checksum = (sum(E_i) - 140) / n
```

Semua baris menghasilkan nilai yang sama:

```text
checksum = 625
```

Input apa pun yang byte-sum-nya 625 akan menghasilkan bitmap yang benar. Contoh sederhana: `aaaaaa+` karena `6 * 97 + 43 = 625`.

## Ekstraksi flag

Setelah tabel dikurangi 625, RLE menghasilkan 10 baris `0/1`. Bitmap itu masih terlalu lebar karena tiap piksel visual diperlebar 4 kolom. Jadi setiap 4 kolom dikompresi menjadi 1 piksel dengan threshold `>= 2`.

Hasil low-res-nya:

```text
#...#...#...#####...##....#....##..
#...#...#...#####...##....#....##..
#...#..##.....#.....#....#.#....#..
#...#..##.....#.....#....#.#....##.
#...#..##.....#...##....#...#...###
#...#...#.....#...##....#...#....##
.#.#....#.....#.....#...........#..
.#.#....#.....#.....#...........#..
..#....###....#.....##.........##..
..#....###....#.....##.........##..
```

Komponen glyph dibaca sebagai:

```text
V I T { ^ }
```

Flag final:

```text
VIT{^}
```

## Cara menjalankan solver

```bash
python3 solve.py ./tini_rev
```

Output:

```text
VIT{^}
```
                         
