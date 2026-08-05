# Fault Cartography

## Ringkasan

Flag ada di balik kombinasi file ELF `faultline` dan data `faultline.map`. Binary membaca map, membangun rute 16x16, lalu sengaja memicu fault (`SIGILL`, `SIGFPE`, `SIGSEGV`) sesuai record di map. Signal handler memutasi 6 blok `uint64` dari input. Setelah semua langkah selesai, hasil mutasi dibandingkan dengan target yang didekripsi dari map.

## File Challenge

- `faultline`: ELF 64-bit PIE, stripped, dynamically linked.
- `faultline.map`: data binary dengan magic `FLT2`.
- `solve_faultline.py`: solver final untuk membalik validasi.

## Analisis Awal

`strings -a ./faultline` menunjukkan nama file `faultline.map`, pesan gagal `lost`, dan pesan sukses `the map remembers you`.

Header map:

```text
magic     = FLT2
version   = 2
steps     = 104
input_len = 42
out_len   = 48
seed      = 0xf017ca4706a11e5d
```

Binary membaca 78 byte header, lalu 256 record berukuran 24 byte.

## Analisis Static

Fungsi utama berada mulai sekitar `0x1280`. Bagian pentingnya:

- `0x12b4`: membuka `faultline.map`.
- `0x132c` sampai `0x13bc`: validasi magic, versi, panjang output, dan digest header.
- `0x145d` sampai `0x14ff`: input 42 byte disalin ke buffer 48 byte dan di-XOR per blok dengan output `mix64(seed ^ i*GOLD ^ INIT_XOR)`.
- `0x17e5` sampai `0x18a3`: dekripsi record map.
- `0x194d`: memicu fault berdasarkan `record[0]`.
- `0x1ae0`: signal handler yang memutasi 6 blok input.
- `0x16b0` sampai `0x1702`: dekripsi target akhir.
- `0x1729` sampai `0x177f`: membandingkan target dengan buffer hasil mutasi.

## Analisis Dynamic

Input salah seperti string kosong, `AAAA`, atau `KCTF{test}` menghasilkan:

```text
lost
```

Setelah solver final dijalankan, binary menerima flag dan mencetak:

```text
the map remembers you
```

GDB juga dipakai untuk memastikan detail handler. GDB perlu meneruskan `SIGILL`, `SIGFPE`, dan `SIGSEGV` ke program karena fault tersebut memang bagian dari validasi.

## Algoritma Validasi atau Encoding

Record map didekripsi dengan:

```text
record_block[i] = encrypted_block[i] ^ mix64(seed ^ i*REC_STEP ^ pos*REC_POS_MUL ^ REC_XOR)
```

Rute awal:

```text
x = ((seed >> 8) & 0xf) ^ sx_mask
y = ((seed >> 20) & 0xf) ^ sy_mask
key = mix64(seed ^ BASE_XOR)
```

Arah gerak dari `.rodata`:

```text
dx = [0, 1, 0, -1]
dy = [-1, 0, 1, 0]
```

Setiap langkah memperbarui key:

```text
key = mix64(key ^ record_tail ^ y ^ (x << 8) ^ step*GOLD)
```

Signal handler memakai `record[0]` sebagai tipe fault dan `record[1]` sebagai subtype. Mutasi terjadi pada 6 blok `uint64`: add, xor, swap, rotate, permutation, dan perkalian modular dengan konstanta ganjil. Karena operasi ini invertible, solver mendekripsi target akhir lalu membalik semua fault dari langkah terakhir ke langkah pertama.

## Penyusunan Solve Script

`solve_faultline.py` melakukan:

1. Parse header dan record dari `faultline.map`.
2. Dekripsi semua record yang dilewati rute.
3. Hitung `final_key`.
4. Dekripsi target akhir.
5. Invert mutasi signal handler secara terbalik.
6. Undo transform awal input.
7. Jalankan `./faultline` dengan flag hasil recovery untuk validasi.

## Cara Menjalankan

```bash
python3 ./solve_faultline.py
```

Output:

```text
KaliTeam{faults_draw_the_only_honest_path}
the map remembers you
```

## Flag

```text
KaliTeam{faults_draw_the_only_honest_path}
```

## Catatan

Kesalahan yang mudah terjadi ada di dua titik. Dekripsi record memakai `seed`, bukan `current_key`. Selain itu tabel arah bukan urutan kiri/bawah/kanan/atas, tapi `dx=[0,1,0,-1]` dan `dy=[-1,0,1,0]`.
