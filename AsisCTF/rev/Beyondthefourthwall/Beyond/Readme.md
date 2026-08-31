# Beyond the Fourth Wall — Write-up

## Ringkasan

Challenge ini berisi dua artefak utama:

```text
beyond.elf
scouting_report.c
```

Sekilas `scouting_report.c` terlihat seperti source C obfuscated yang sangat besar. Namun setelah dianalisis, file tersebut ternyata menjadi carrier steganografi. Data disembunyikan melalui pola:

1. jumlah leading spaces,
2. jumlah karakter `w` pada expression,
3. panjang comment.

Data tersembunyi tersebut membentuk container bertingkat yang berisi empat section. Section pertama adalah program VM, sedangkan tiga section sisanya berisi potongan flag dan patch terenkripsi untuk memodifikasi VM.

Flag akhir:

```text
ASIS{ioccc_g1v3s_c00l_1d34s}
```

---

## Analisis Awal

File `beyond.elf` adalah binary RISC-V stripped. Dari analisis static terlihat binary meminta satu argument candidate flag dengan panjang 28 byte.

Jika benar, program mencetak:

```text
The fourth wall opens.
```

Jika salah:

```text
The fourth wall remains closed.
```

Namun source `scouting_report.c` jauh lebih menarik. Isinya terdiri dari banyak statement berpola mirip:

```c
   (void)(...w...);/*xxxxxxx*/
```

Tiga bagian kecil pada tiap baris berubah secara terbatas:

```text
leading spaces : 0 sampai 7
jumlah 'w'     : 1 sampai 8
panjang comment: 3, 7, 11, atau 15
```

Ketiganya bisa digabung menjadi satu byte:

```python
byte = lead | ((nw - 1) << 3) | (((nx - 3) // 4) << 6)
```

Artinya:

```text
lead              -> bit 0..2
nw - 1            -> bit 3..5
(nx - 3) / 4      -> bit 6..7
```

Setelah semua baris diekstrak, didapat hidden stream berukuran:

```text
334767 bytes
```

Header awal hidden stream:

```text
magic   = 0xc47a19e3
version = 0x2001
```

Ini membuktikan bahwa source C tersebut memang menyimpan container tersembunyi.

---

## Struktur Container

Hidden stream memiliki outer container. Setelah header 12 byte, terdapat inner container dengan magic:

```text
0xec31a76d
```

Di dalam inner container terdapat empat section:

```text
section 1: size 0x20000 = 131072 bytes
section 2: size 0x14978 = 84344 bytes
section 3: size 0x0aabc = 43708 bytes
section 4: size 0x126ff = 75519 bytes
```

Section 1 tepat berukuran:

```text
32768 * 4 bytes
```

Jadi section ini adalah array berisi 32768 word 32-bit, yang kemudian dipakai sebagai program VM.

---

## Recover 21 Byte Pertama Flag

Section 2, 3, dan 4 masing-masing memiliki custom 64-bit hash checker.

Hash tersebut menggunakan operasi reversible:

```text
addition modulo 2^32
xor
rotate left/right
```

Karena semua operasi reversible, hash dapat dibalik dari output akhir untuk mendapatkan seed awal.

Konstanta utama yang dipakai:

```text
0x243f6a88
0x85a308d3
0x7f4a7c15
0x9e3779b9
0x6a09e667
0xbb67ae85
```

Setelah seed didapat, key section dihitung dengan:

```python
key = seed ^ 0x9e3779b97f4a7c15
```

Lalu tiap section memiliki satu value 64-bit lain pada offset 16. Potongan flag 7 byte dihitung dengan:

```python
chunk = (key ^ q1 ^ TABLE[index]).to_bytes(8, "little")[:7]
```

Dengan table:

```text
0x58670a15157776bc
0x91d45908ea83412d
0xe6e4a71330a9a77a
```

Hasil tiga chunk:

```text
section 2 -> ASIS{io
section 3 -> ccc_g1v
section 4 -> 3s_c00l
```

Gabungannya menghasilkan 21 byte pertama:

```text
ASIS{ioccc_g1v3s_c00l
```

---

## Patch WPT1

Payload pada section 2 sampai 4 terenkripsi menggunakan stream cipher custom berbasis ARX:

```text
addition
xor
rotation
```

Setelah key section diketahui, payload dapat didecrypt dan menghasilkan magic:

```text
WPT1
```

Patch format menggunakan ULEB128 dan ZigZag encoding.

Opcode patch:

```text
0 = end
1 = memmove
2 = xor range dengan konstanta
3 = add range dengan konstanta
4 = swap dua range
5 = tulis literal word
6 = zero range
```

Urutan eksekusi checker bukan sekadar apply semua patch sekaligus. Program menjalankan VM, lalu apply patch, lalu lanjut lagi:

```text
run stage 0
apply patch 1
run stage 1
apply patch 2
run stage 2
apply patch 3
run stage 3
```

Karena VM self-modifying, tiga stage pertama harus benar-benar diemulasi sebelum stage final bisa dianalisis.

---

## VM SUBLEQ-like

Program VM berasal dari section 1 sebagai array word 32-bit.

Satu instruksi terdiri dari tiga operand:

```text
destination, branch_target, source
```

Operand didecode seperti ini:

```python
operand = signed32(raw) >> 1
```

Jika bit terendah `raw` bernilai 1, operand direference sekali lagi secara indirect.

Special operand yang penting:

```text
-8 = secondary[secondary_cursor]
-7 = secondary_cursor
-6 = secondary_length
-5 = final trigger destination
-4 = output-byte destination
-3 = candidate[candidate_cursor]
-2 = candidate_cursor
-1 = candidate_length
```

Semantik instruksi utama:

```python
res = signed32(old_destination - source_value)
```

Lalu:

```text
res > 0  -> lanjut instruction berikutnya
res <= 0 -> branch ke target
```

Jika destination adalah cell biasa, hasil `res` ditulis kembali ke memory VM.

Destination `-5` adalah terminal checker. Candidate dianggap valid hanya jika:

```text
res == 1
```

---

## Pemecahan 7 Byte Terakhir

Setelah tiga stage awal dan tiga patch diterapkan, VM final memvalidasi 7 byte terakhir candidate.

Tujuh byte berarti:

```text
7 * 8 = 56 bit
```

Stage final memecah byte candidate menjadi 56 bit. Cell VM untuk bit-bit ini berada di range:

```text
24582 .. 24637
```

Program final terdiri dari 56 blok constraint. Setiap blok memilih subset dari 56 bit, menghitung parity, lalu membandingkannya dengan expected bit.

Bentuk constraint-nya linear di GF(2):

```text
x_a XOR x_b XOR x_c ... = rhs
```

Awal setiap blok constraint bisa dikenali dari instruksi yang membersihkan accumulator cell:

```text
24565
```

Static scan menemukan tepat:

```text
56 parity blocks
```

Untuk blok 0 sampai 54, expected RHS didapat dengan menjalankan blok secara terisolasi dua kali:

```text
parity = 0
parity = 1
```

Nilai yang tidak mengaktifkan mismatch flag adalah RHS yang benar.

Setelah semua subset dan RHS dikumpulkan, sistem diselesaikan dengan Gaussian elimination di GF(2).

Hasil eliminasi:

```text
jumlah variable = 56
rank            = 55
free bit        = bit 55
```

Karena rank 55 dari 56 variable, hanya ada dua kemungkinan solusi.

Kandidat pertama menghasilkan tail:

```text
_1d34s}
```

Kandidat kedua menghasilkan byte non-printable:

```python
b'#<\xf8\xe7\xe9V\xb7'
```

Tetap tidak dipilih berdasarkan asumsi printable. Keduanya diuji ulang ke VM final asli.

Hasil validasi:

```text
_1d34s}          -> trigger, res = 1
non-printable    -> reject
```

Jadi tujuh byte terakhir adalah:

```text
_1d34s}
```

---

## Solver

Solver melakukan semua proses secara otomatis:

```text
1. Extract hidden stream dari scouting_report.c
2. Parse outer dan inner container
3. Ambil 4 section
4. Invert custom 64-bit hash
5. Recover tiga chunk awal flag
6. Decrypt patch WPT1
7. Emulate VM stage 0 sampai stage 2
8. Apply patch setelah tiap stage
9. Analisis VM final sebagai sistem parity GF(2)
10. Solve dengan Gaussian elimination
11. Validasi kandidat tail ke VM asli
```

Command menjalankan solver:

```bash
python3 solve.py
```

Output:

```text
[+] extracted 4 hidden sections from scouting_report.c
[+] recovered first 21 bytes: ASIS{ioccc_g1v3s_c00l
[+] final GF(2) rank: 55 free bit(s): [55]
[+] recovered final 7 bytes: _1d34s}
[+] final VM validation: trigger res= 1 steps= 12753
<FLAG>ASIS{ioccc_g1v3s_c00l_1d34s}</FLAG>
```

---

## Flag

```text
ASIS{ioccc_g1v3s_c00l_1d34s}
```

---

