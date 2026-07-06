# Flag Checkers

- **CTF:** NHNC 2026
- **Category:** Reverse
- **Binary:** `flag_checkers`
- **Flag:** `NHNC{2b06cc91a6d35aa24e886394ab574e1c4b4f9eed7ad6d7aca7a3228a39cf318f0a3c523a72263b0995f6417f3b5fd56443d482fbd9b430a578c4038a451028b9}`

## Triage

Binary-nya ELF 64-bit statically linked, stripped, dan ukurannya cuma sekitar 10 KB.

```bash
file flag_checkers
readelf -h flag_checkers
objdump -d -M intel flag_checkers
objdump -s -j .data flag_checkers
```

Entry point langsung memakai syscall tanpa libc. Program melakukan `mmap` pada alamat tetap `0x30000000`, membaca input maksimal `0xc0` byte, lalu membuat dua child process. Total ada tiga proses yang sinkron memakai futex dan bergantian memproses round berdasarkan `round_index % 3`.

Fork dan futex cuma obfuscation alur. Transformasinya tetap deterministik dan bisa direplikasi tanpa meniru multiprocessing tersebut.

## Struktur checker

Checker memproses 17 blok berukuran 8 byte. Setiap blok melewati 15 round Feistel, jadi totalnya 255 round.

State awal chaining:

```text
0x0f1e2d3c4b5a6978
```

Saat round ke-0 dari sebuah blok, program membaca 8 byte input, melakukan byte swap, lalu XOR dengan chaining value sebelumnya:

```text
X_i = BE64(input_block_i) XOR chain_i
```

`X_i` dibagi menjadi dua word 32-bit dan masuk ke 15 round Feistel. Setelah round terakhir, hasil 64-bit disimpan sebagai ciphertext block sekaligus menjadi chaining value blok berikutnya.

Target ciphertext sepanjang `0x88` byte berada di `.data` pada virtual address `0x402480`.

## Konstanta dan tabel

Enam konstanta round tersimpan di `0x402020` dan di-obfuscate dengan XOR `0xa5a5a5a5`. Setelah didekode:

```text
0xa5a5f00d
0x1337beef
0x0badc0de
0xfaceb00c
0xdeadc0de
0x8badf00d
```

Empat S-box masing-masing berukuran 256 byte berada di:

```text
0x402080
0x402180
0x402280
0x402380
```

Untuk round `r`, fungsi round menggunakan:

```text
constant = constants[r % 6]
sbox     = sboxes[(3*r + 1) & 3]
rotation = ((7*r + 3) % 31) + 1
```

Input fungsi round:

```text
T = L XOR constant XOR ((r + 1) * 0x9e3779b9 mod 2^32)
```

Setiap byte `T` diganti lewat S-box terpilih, lalu hasil 32-bit di-rotate left.

```text
F(L, r) = ROL32(SBOX32(T), rotation)
```

Update Feistel-nya:

```text
new_L = R XOR F(L, r)
new_R = L
```

## Membalik Feistel

Feistel tidak membutuhkan inverse S-box. Dari pasangan `(new_L, new_R)`, state lama langsung didapat:

```text
old_L = new_R
old_R = new_L XOR F(old_L, r)
```

Round dibalik dari 14 sampai 0 untuk setiap target block. Sesudah memperoleh nilai sebelum Feistel:

```text
plaintext_block = pre_feistel XOR previous_ciphertext
```

Blok pertama memakai initial chain `0x0f1e2d3c4b5a6978`. Dua byte NUL terakhir hanya padding karena target berukuran 136 byte, sedangkan flag aslinya 134 byte.

## Solver

```bash
chmod +x flag_checkers solve.py
python3 solve.py
```

Output:

```text
NHNC{2b06cc91a6d35aa24e886394ab574e1c4b4f9eed7ad6d7aca7a3228a39cf318f0a3c523a72263b0995f6417f3b5fd56443d482fbd9b430a578c4038a451028b9}
```

Validasi manual tanpa newline:

```bash
python3 solve.py | tr -d '\n' | ./flag_checkers
```

```text
Correct
```
