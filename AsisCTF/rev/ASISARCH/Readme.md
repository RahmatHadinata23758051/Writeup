# ASISARCH

## Ringkasan

`qemu-asisarch` adalah emulator VM kecil yang menyamar seperti QEMU. ROM `challenge.rom` punya header `AARQ v2`, lalu body ROM dimuat ke memori VM 64 KB. Flag dibaca dari stdin, diproses sebagai 22 word little-endian, lalu hasil transformasinya dicek terhadap target di area data ROM.

Flag valid:

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```

## File Challenge

```
qemu-asisarch : ELF 64-bit PIE stripped, emulator custom
challenge.rom : ROM data, magic AARQ v2
```

ROM diawali header:

```
41 41 52 51 02 ...
```

`41 41 52 51` adalah ASCII `AARQ`. Body ROM dimulai dari offset `0x20`.

## Analisis Awal

Program dijalankan dengan:

```bash
chmod +x qemu-asisarch
./qemu-asisarch -M asisboard -kernel challenge.rom -nographic
```

Output awal:

```
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
```

String dari binary memperlihatkan error emulator seperti:

```
guest cycle limit exceeded
PC out of bounds
illegal instruction
ROM checksum mismatch
```

Ini mengarah ke VM custom, bukan native checker biasa.

## Analisis Static

Loader ROM di `qemu-asisarch` melakukan beberapa hal:

1. Mengecek magic `AARQ`.
2. Mengecek versi byte `0x02`.
3. Menyalin ROM body dari offset `0x20` ke memori VM.
4. Menghitung checksum body dengan seed `0x31415926`.
5. Mendecode PC awal dari header ROM.
6. Menjalankan loop fetch-decode-execute VM sampai halt.

State VM yang penting:

```
mem[0x0000..0xffff]       : RAM/ROM VM
mem[0x10000..0x1000f]     : 8 register 16-bit
mem[0x10010]              : SP 16-bit
mem[0x10012]              : PC 16-bit
mem[0x10018]              : cycle counter
```

Instruksi VM panjangnya 4 byte, tapi byte instruksi dipermutasi dan di-decode pakai key berbasis PC. Tabel penting dari emulator:

```
.rodata+0x140 / file offset 0x2140 : permutation table fetch instruksi
.rodata+0x160 / file offset 0x2160 : S-box 256 byte
```

Opcode yang kepakai di ROM:

```
0x15 movi
0x21 addi
0x32 xori
0x44 roli
0x4b mov
0x50 add
0x56 sub
0x5c xor
0x63 ld8
0x69 st8
0x71 ld16
0x77 st16
0x80 jmp
0x86 jz
0x8c jnz
0xa1 call
0xa7 ret
0xb3 getc
0xb9 putc
0xc2 sbox
0xfe halt
```

## Analisis Dynamic

Setelah emulator VM dibuat ulang di Python, trace awal ROM terlihat seperti ini:

```asm
0000: movi r6, 0x7c60
0004: call 0x7c04        ; print string banner
0008: movi r6, 0x7c86
000c: call 0x7c04        ; print prompt
0010: movi r6, 0xc000
0014: call 0x7c1c        ; read input ke 0xc000
0018: movi r1, 0x002c
001c: sub r1, r3
0020: jnz r1, 0x7bf8    ; length harus 44 byte
```

Routine `0x7c1c` membaca input sampai newline/null, menyimpan byte ke `0xc000`, lalu mengembalikan panjang input di `r3`. Panjang flag wajib `0x2c` atau 44 byte.

## Algoritma Validasi atau Encoding

Input diperlakukan sebagai 22 word little-endian:

```
w[0..21] = input[0..43] sebagai uint16 little-endian
```

Ada 10 round transformasi. Setiap round berisi tiga tahap:

### 1. S-box + XOR konstanta

Untuk setiap word:

```
w[i] = sbox16(w[i]) ^ round_const[i]
```

`sbox16()` menerapkan S-box byte per byte ke high byte dan low byte.

### 2. Circular prefix-add

```python
for i in range(22):
    prev = 21 if i == 0 else i - 1
    w[i] = (w[i] + w[prev] + 0x5a5a) & 0xffff
```

Karena jalan in-place, `w[i-1]` untuk `i > 0` adalah nilai yang sudah diupdate.

### 3. Mix XOR linear

```python
def f(x):
    return x ^ rol16(x, 5) ^ rol16(x, 11)

for i in range(22):
    w[i] ^= f(w[(i + 1) % 22]) ^ rol16(f(w[(i + 2) % 22]), round_rotation)
```

`round_rotation` naik dari 1 sampai 10.

Checker akhir mulai di `0x7874`. Program mengambil target dari area data `0x7cdb + offset`, tapi targetnya disimpan sebagai dua word yang di-XOR:

```
target[i] = u16(mem[0x7cdb + offset]) ^ u16(mem[0x7cdb + offset + 2])
```

Lalu program menjumlahkan semua hasil XOR antara `w[i]` dan `target[i]`:

```python
acc = 0
for i in range(22):
    acc = (acc + (w[i] ^ target[i])) & 0xffff

valid jika acc == 0
```

Solve script memakai target per-word yang natural, yaitu kondisi kuat `w[i] == target[i]` untuk semua `i`. Kondisi ini pasti membuat akumulator akhir nol dan menghasilkan flag yang meaningful.

## Penyusunan Solve Script

`solve.py` melakukan langkah ini:

1. Membaca `qemu-asisarch`.
2. Mengekstrak permutation table dan S-box dari `.rodata`.
3. Membaca `challenge.rom` dan memverifikasi checksum ROM.
4. Mendecode instruksi VM untuk mengambil konstanta 10 round dan target akhir.
5. Membalik transformasi dari round 10 ke round 1:
   - undo mix dari index 21 ke 0,
   - undo circular prefix-add dari index 21 ke 0,
   - undo S-box + XOR konstanta.
6. Menggabungkan 22 word hasil inverse sebagai byte little-endian.
7. Mencetak flag.

## Cara Menjalankan

```bash
cd /mnt/data/ASISARCH
python3 solve.py
```

Output:

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```

Validasi dengan emulator challenge:

```bash
./qemu-asisarch -M asisboard -kernel challenge.rom -nographic <<<'ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}'
```

Output:

```
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[+] Access Granted! Flag verified.
```

## Flag

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```
