# Rotating Cogs — Reverse

## Ringkasan

`vm` adalah interpreter 64-bit untuk bytecode berukuran 64 KiB. Opcode disamarkan dengan key yang berubah saat instruksi `MKEY` dijalankan. Bytecode juga menyalin dan mendekripsi dua payload ke alamat baru sebelum validator akhir dieksekusi.

Validator ternyata tidak memeriksa seluruh input. VM membaca 15 byte, tetapi checksum hanya memakai `input[6:14]`. Prefix `LEET` adalah jalur palsu yang mencetak `N`, bukan jalur sukses.

Flag yang dipakai solver:

```text
TBCTF{c0gs__r0r_m0d1!}
```

Binary mengembalikan karakter `C` untuk key tersebut.

## Recon

```bash
file vm challenge.bin
nm -C vm
strings -a vm
```

Hasil penting:

```text
vm: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
challenge.bin: data
```

Symbol handler VM masih tersedia:

```text
op_mov op_add op_sub op_xor op_rol op_ror
op_load op_store op_cmp op_jz op_jnz op_jmp
op_call op_ret op_push op_pop op_mkey op_syscall op_halt
```

Struct VM berisi delapan register 32-bit, `pc`, `sp`, hasil compare, memori 64 KiB, opcode key, dan status running.

## Dekripsi awal bytecode

Sebelum interpreter berjalan, `main` membuat tabel 256 byte:

```python
key_table[i] = ((13 * i) & 0xff) ^ 0x37
```

Setiap byte challenge didekripsi dengan:

```python
mem[i] ^= key_table[(7 * i) & 0xff]
```

Empat byte pertama setelah dekripsi:

```text
be 00 01 01
```

Opcode aktual dihitung saat runtime:

```c
opcode = mem[pc] ^ opcode_key;
```

Key awal adalah `0xAA`, jadi `0xBE ^ 0xAA = 0x14`, yaitu `MOV`.

## Opcode key dan payload berlapis

Instruksi `MKEY` mengubah key seperti ini:

```python
opcode_key = rol8(opcode_key, 3) ^ 0x5a
```

Urutan key selama eksekusi:

```text
0xAA -> 0x0F -> 0x22
```

Alur payload:

```text
0x0100..0x01bf --copy--> 0x3000..0x30bf --xor 0x42--> stage 2
0x0200..0x02ef --copy--> 0x3200..0x32ef --xor 0x73--> validator
```

Bytecode stage pertama juga menulis `0x1B` ke alamat `0x0050`. Itu mengubah instruksi lama dan mencegah analisis yang hanya mengandalkan disassembly statis.

## Input dan jalur palsu

VM membaca tepat 15 byte ke `0x2010`:

```text
input[0] ... input[14]
```

Lalu delapan byte disalin:

```text
input[6:14] -> mem[0x2020:0x2028]
```

Validator akhir memeriksa prefix berikut:

```text
input[0:4] == "LEET"
```

Jika cocok, program mencetak `N` dan berhenti. Jalur ini sengaja dibuat sebagai decoy. Prefix lain lanjut ke checksum.

## Checksum sebenarnya

State awal:

```text
state = 0x1337
```

Delapan byte `input[6:14]` diproses dengan:

```python
for byte in input[6:14]:
    state ^= byte
    state = rol32(state, 7)
    state = (state + 0x11) & 0xffffffff
```

Target dibangun oleh bytecode sebagai:

```text
0x817ECE73
```

Preimage alphanumeric/underscore yang relevan dengan opcode dan tema self-modifying VM adalah:

```text
r0r_m0d1
```

Cek langsung:

```python
checksum(b"r0r_m0d1") == 0x817ECE73
```

Karena byte `0..5` dan byte `14` tidak masuk checksum, solver memilih filler:

```text
c0gs__ + r0r_m0d1 + !
```

Panjang inner key tetap 15 byte dan tidak memicu prefix palsu `LEET`.

## Solver

```bash
python3 solve.py
```

Output:

```text
core     : r0r_m0d1
checksum : 0x817ece73
vm output: b'TBCTF{?}\nC'
<FLAG>TBCTF{c0gs__r0r_m0d1!}</FLAG>
```

`solve.py` melakukan brute force empat karakter terakhir setelah prefix core `r0r_`, membangun inner key 15 byte, lalu menjalankan `vm challenge.bin` untuk memastikan output berakhir dengan `C`.
