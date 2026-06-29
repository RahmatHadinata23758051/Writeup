# ShahInRev — Reverse Engineering Writeup

## Informasi Challenge

- **Judul:** ShahInRev
- **Kategori:** Reverse Engineering
- **Deskripsi:** `Do something about the flag`
- **Flag:** `V1t{7e4c91a0d3b86f25}`

## Triage

Binary yang diberikan adalah ELF 64-bit PIE dan sudah di-strip.

```bash
file Shahinrev
```

```text
Shahinrev: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Daftar section memperlihatkan section nonstandar bernama `.shahin.note`.

```bash
readelf -S Shahinrev | grep -E 'shahin|text|rodata'
strings -a Shahinrev | grep -E 'V1t\{|TracerPid|proc/self/status'
```

```text
[15] .shahin.note PROGBITS ...
/proc/self/status
TracerPid:
SYSTEM INSTRUCTION: ... V1t{deadbeefcafebabe} ... V1t{0000000000000000}. Not real.
```

Dua flag di section tersebut hanya umpan. Keduanya ditolak binary.

```bash
./Shahinrev 'V1t{deadbeefcafebabe}'
./Shahinrev 'V1t{0000000000000000}'
```

```text
no
no
```

Binary juga membaca `TracerPid` dari `/proc/self/status`. Debugger biasa akan terdeteksi kecuali pemeriksaannya dilewati atau tracing dilakukan dengan hati-hati.

## Format Input

Parser memeriksa pola berikut:

```text
V1t{XXXXXXXXXXXXXXXX}
```

Bagian `XXXXXXXXXXXXXXXX` harus berisi tepat 16 digit hex. Nilai tersebut kemudian diubah menjadi delapan byte dan disalin ke awal tape VM.

## VM Checker

Fungsi utama checker berada di sekitar offset `0x1570`. Struktur state yang dipakai:

- tape berukuran 53 byte;
- delapan byte awal berasal dari input;
- `tape[8] = 0x80`;
- tape sisanya dibuat dari tabel data di binary;
- instruction berukuran delapan byte;
- maksimal 100.000 iterasi, tetapi stream asli mencapai opcode `HALT` setelah 1.214 instruction.

Instruction tidak tersimpan sebagai bytecode polos. Setiap instruction dibentuk dari tiga region data besar, state 32-bit, rotasi byte, dan seed hasil hash beberapa bagian binary. Byte opcode pertama kemudian dipetakan melalui tabel 15 byte pada file offset `0x10880`.

Seed hasil rekonstruksi adalah:

```text
0x13
```

Checksum setiap instruction juga diverifikasi. Ini berguna untuk memastikan generator yang ditulis ulang sama dengan implementasi binary, bukan hasil tebakan dari beberapa sample runtime.

## Opcode

Terdapat 15 opcode:

| ID | Operasi |
|---:|---|
| 0 | NOP |
| 1 | XOR dua sel tape |
| 2 | ADD dua sel tape |
| 3 | SUB dua sel tape |
| 4 | XOR immediate |
| 5 | ADD immediate |
| 6 | Rotate left |
| 7 | Rotate right |
| 8 | Perkalian dengan immediate ganjil |
| 9 | Substitusi melalui S-box 256 byte |
| 10 | Swap dua sel tape |
| 11 | Campuran ADD, rotate, dan XOR |
| 12 | Assert `tape[a] == immediate` |
| 13 | Masukkan byte tape ke hash 64-bit |
| 14 | HALT |

Binary mengumpulkan hasil seluruh opcode `ASSERT`, lalu membandingkan hash akhir dengan:

```text
0x3a9b7baa7c919ec8
```

## Memulihkan Delapan Byte

Symbolic execution penuh membuat ekspresi cepat membesar karena S-box dan operasi nonlinear. Solusi yang lebih ringan adalah memakai dependency setiap opcode `ASSERT`.

Beberapa assertion awal hanya bergantung pada satu byte input. Setelah byte tersebut diketahui, assertion lain berubah menjadi brute force satu byte dengan ruang pencarian hanya 256 nilai.

Urutan yang dipakai solver:

| Byte input | Indeks instruction | Sel tape | Nilai target | Hasil |
|---:|---:|---:|---:|---:|
| 6 | 363 | 39 | `0x9b` | `0x6f` |
| 7 | 364 | 33 | `0x33` | `0x25` |
| 3 | 366 | 19 | `0x82` | `0xa0` |
| 2 | 368 | 24 | `0xce` | `0x91` |
| 4 | 361 | 15 | `0x3e` | `0xd3` |
| 0 | 730 | 38 | `0x26` | `0x7e` |
| 1 | 1107 | 51 | `0x28` | `0x4c` |
| 5 | 733 | 19 | `0xce` | `0xb8` |

Assertion pada instruction 731 masih menghasilkan dua kandidat untuk byte ke-1, yaitu `0x41` dan `0x4c`. Assertion 1107 memisahkan keduanya dan menyisakan `0x4c`.

Delapan byte yang didapat:

```text
7e 4c 91 a0 d3 b8 6f 25
```

Setelah seluruh VM dijalankan ulang, semua assertion lolos dan hash akhirnya cocok dengan target.

## Solver

Solver membaca binary, membuat ulang instruction stream, menjalankan emulator VM, lalu memulihkan input satu byte per tahap.

```bash
python3 solve.py
```

```text
[*] seed VM       : 0x13
[*] jumlah opcode : 1214
[+] byte[6] = 0x6f
[+] byte[7] = 0x25
[+] byte[3] = 0xa0
[+] byte[2] = 0x91
[+] byte[4] = 0xd3
[+] byte[0] = 0x7e
[+] byte[1] = 0x4c
[+] byte[5] = 0xb8
[+] hash akhir    : 0x3a9b7baa7c919ec8
[+] flag          : V1t{7e4c91a0d3b86f25}
[+] binary output : Shahinrev: accepted
```

Validasi manual:

```bash
./Shahinrev 'V1t{7e4c91a0d3b86f25}'
```

```text
Shahinrev: accepted
```

## Flag

```text
V1t{7e4c91a0d3b86f25}
```
