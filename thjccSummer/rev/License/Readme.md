# License

## Ringkasan

`license_v2` adalah ELF 64-bit x86-64, statically linked, stripped, dan sangat kecil. Binary menerima satu argumen license. Input yang lolos format dipermutasi, ditransformasi per byte, lalu melewati empat round affine berbasis XOR dan rotate. Hasil 24 byte akhirnya dibandingkan dengan konstanta hardcoded.

Pipeline validator bisa dimodelkan sebagai sistem linear/affine 192 bit setelah tahap pre-transform. Rank sistemnya 178, jadi hanya ada 14 free bit. Semua 16.384 kemungkinan solusi affine dapat dienumerasi, lalu difilter dengan constraint bahwa karakter input asli harus berupa hex digit. Hasilnya tepat satu license valid.

License valid:

```
A9F3-1C7D-EE42-0B6A-5D91-7F20
```

Menjalankan binary dengan license tersebut menghasilkan:

```
THJCC{license_pipeline_rebuilt}
```

## File Challenge

```bash
file license_v2
```

Hasil:

```
license_v2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Ukuran file hanya sekitar 3.6 KB. Section yang relevan hanya `.rodata` dan `.text`.

```bash
readelf -S license_v2
```

Bagian penting:

```
.rodata  0x200120
.text    0x201230
```

Tidak ada symbol table karena binary sudah stripped.

## Analisis Awal

`strings` langsung memperlihatkan string kegagalan dan usage:

```bash
strings -a license_v2
```

Potongan hasil:

```
invalid license
usage: %s <license>
```

Flag tidak tersimpan sebagai plaintext.

Dump `.rodata` memperlihatkan beberapa konstanta SIMD, permutation table, string error, dan blob byte acak:

```bash
objdump -s -j .rodata license_v2
```

Data penting:

```
0x2001f0: 07 00 13 04 0c 17 02 10 09 05 15 0b 01 0e 12 06
0x200200: 14 03 0f 0a 08 16 0d 11

0x200210: 25 36 c1 db e6 c9 d3 a5 ba 83 9d 73 68 45 57 5d
0x200220: 31 2b 37 01 1b e7 d0 ee cc d4 b6 b9 b1 9e 8a
```

## Analisis Static

### Format input

Validasi dimulai di `0x201230`.

Binary mengecek `argc == 2`, lalu menghitung panjang `argv[1]`. Hasil panjang harus 29 karakter.

Pada loop berikutnya, posisi separator dipaksa menjadi `-`. Posisi yang valid adalah:

```
4, 9, 14, 19, 24
```

Jadi format license adalah enam grup berisi empat karakter:

```
XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

Karakter selain separator harus berada di salah satu range:

```
0-9
A-F
a-f
```

Setelah separator dibuang, tersisa tepat 24 karakter.

### Checksum decoy

Di `0x201398` ada state awal:

```
0x31415926
```

Program melakukan XOR dengan `index * char` dan rotate 32-bit untuk seluruh 24 karakter. Tetapi nilai akhirnya tidak dipakai dalam keputusan validasi berikutnya; register hasil segera ditimpa. Bagian ini berfungsi sebagai decoy.

### Permutasi

Permutation table berada di `.rodata` `0x2001f0`:

```python
PERM = [
    7, 0, 19, 4, 12, 23, 2, 16,
    9, 5, 21, 11, 1, 14, 18, 6,
    20, 3, 15, 10, 8, 22, 13, 17,
]
```

Jika 24 karakter tanpa dash disebut `raw`, maka byte ke-j berikutnya berasal dari:

```
raw[PERM[j]]
```

### Pre-transform per byte

Bagian `0x201410..0x2016e5` memakai SSE untuk 16 byte awal. Delapan byte sisanya dikerjakan secara scalar di `0x2016eb..0x201766`.

Keduanya merepresentasikan formula yang sama:

```python
y[j] = rol8(
    raw[PERM[j]] ^ ((0x31 + 0x11*j) & 0xff),
    j % 5
)
y[j] = (y[j] + 0x0b*j) & 0xff
```

Scalar tail membuat pola ini lebih mudah terlihat. Contohnya untuk `j=16`:

```asm
xor al, 0x41
rol al, 1
add al, 0xb0
```

Nilai tersebut cocok dengan:

```
0x31 + 0x11*16 = 0x141 -> 0x41
16 mod 5 = 1
0x0b*16 = 0xb0
```

### Empat round validator

Setelah pre-transform, state berukuran 24 byte diproses empat kali.

Setiap round mengikuti bentuk:

```python
v = state[i] ^ state[(i + 7) % 24]
v ^= (i + 0x1d*r) & 0xff
v ^= ROUND_KEYS[r][i % 4]
out[i] = rol8(v, (i + r) % 7)
```

Round key yang berasal dari immediate 32-bit di assembly:

```python
ROUND_KEYS = [
    [0xdf, 0x9b, 0x57, 0x13],  # 0x13579bdf
    [0xe0, 0xac, 0x68, 0x24],  # 0x2468ace0
    [0x0d, 0xf0, 0xad, 0x0b],  # 0x0badf00d
    [0xaa, 0x55, 0xaa, 0x55],  # 0x55aa55aa
]
```

Magic division dengan `0x2492492492492493` hanya dipakai untuk menghitung modulo 7 tanpa instruksi division. Setelah disederhanakan, rotate count masing-masing round memang `(i + r) % 7`.

### Target final

Mulai `0x201a34`, 24 output byte dibandingkan satu per satu dengan konstanta:

```
95 54 0c 2f 5a c7 a9 9f
bc a4 9a d2 96 c3 2d 88
3a 57 8b ad 1d 2f 2b 46
```

Jika salah satu byte tidak cocok, eksekusi masuk ke jalur:

```
invalid license
```

Jika semuanya cocok, kontrol masuk ke `0x201bc3`, yaitu decoder flag.

## Analisis Dynamic

Binary bisa diuji langsung dengan input format yang salah:

```bash
./license_v2 11111111111111111111111111111
```

Hasil:

```
invalid license
```

Setelah solver mendapatkan license valid:

```bash
./license_v2 A9F3-1C7D-EE42-0B6A-5D91-7F20
```

Hasil nyata dari binary:

```
THJCC{license_pipeline_rebuilt}
```

Exit code binary adalah 0.

## Algoritma Validasi atau Encoding

Empat round setelah pre-transform hanya terdiri dari XOR, pemilihan byte tetangga, dan rotate bit. Semua operasi tersebut affine terhadap 192 bit state.

Saya membangun transformasi linear dengan metode basis-vector:

1. Jalankan pipeline pada state nol untuk mendapatkan affine offset.
2. Untuk setiap 192 input bit, toggle satu bit lalu jalankan pipeline.
3. XOR output dengan affine offset untuk mendapatkan satu kolom matriks linear.
4. Susun sistem `A*x = target XOR offset` di GF(2).
5. Lakukan Gaussian elimination.

Rank matriks adalah:

```
178
```

Dengan 192 variabel, nullity-nya:

```
192 - 178 = 14
```

Artinya hanya ada:

```
2^14 = 16384
```

state pre-transform yang perlu dicoba.

Setiap kandidat kemudian difilter berdasarkan constraint byte pre-transform. Karena byte sebelum pre-transform harus berasal dari karakter hex yang valid, setiap posisi hanya punya 22 kemungkinan karakter:

```
0123456789ABCDEFabcdef
```

Setelah filtering, hanya satu kandidat yang tersisa:

```
A9F3-1C7D-EE42-0B6A-5D91-7F20
```

## Decoder Flag

Flag tidak disimpan plaintext. Blob di `0x200210` berisi 31 byte:

```
25 36 c1 db e6 c9 d3 a5 ba 83 9d 73 68 45 57 5d
31 2b 37 01 1b e7 d0 ee cc d4 b6 b9 b1 9e 8a
```

Jalur sukses memulai state byte:

```
cl = 0x7e
```

Byte diproses berpasangan:

```python
out[j]   = blob[j]   ^ ((cl - 0x0d) & 0xff)
out[j+1] = blob[j+1] ^ cl
cl = (cl + 0x1a) & 0xff
```

Hasil decoding:

```
THJCC{license_pipeline_rebuilt}
```

## Penyusunan Solve Script

`solve.py` tidak memakai Z3, angr, atau dependency eksternal. Solver:

1. Mereproduksi pre-transform dan empat round.
2. Membangun matriks affine 192-bit secara otomatis.
3. Menyelesaikannya dengan Gaussian elimination GF(2).
4. Mengenumerasi 14 free bit.
5. Memfilter kandidat berdasarkan alfabet hex.
6. Mengembalikan satu license valid.
7. Mendekode blob flag dari success path.
8. Menjalankan `license_v2` dengan license hasil solver jika binary executable tersedia.
9. Memastikan output binary sama dengan flag hasil decoding.

## Cara Menjalankan

```bash
chmod +x license_v2 solve.py
./solve.py
```

Output:

```
[+] license: A9F3-1C7D-EE42-0B6A-5D91-7F20
[+] decoded success flag: THJCC{license_pipeline_rebuilt}
[+] binary output: THJCC{license_pipeline_rebuilt}
[+] binary exit code: 0
<FLAG>THJCC{license_pipeline_rebuilt}</FLAG>
```

Bisa juga diverifikasi manual:

```bash
./license_v2 A9F3-1C7D-EE42-0B6A-5D91-7F20
```

## Flag

```
THJCC{license_pipeline_rebuilt}
```
