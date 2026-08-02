# Writeup — Cold Start / flightcomp

## Deskripsi Challenge

Pada challenge ini kita diberikan dua file utama:

```text
flightcomp
mission.rom
```

File `flightcomp` adalah binary ELF 64-bit yang berperan sebagai emulator atau flight computer. Sementara itu, `mission.rom` adalah ROM berisi program yang akan dijalankan oleh emulator tersebut.

Tujuan challenge adalah mencari launch code yang benar. Jika launch code valid, program akan menampilkan pesan:

```text
Arming gate released -- GO for launch.
```

Jika salah, program hanya akan menampilkan status `HOLD`.

Flag akhir harus dikirim dalam format:

```text
uctf{...}
```

---

## Analisis Awal

Pertama, binary dijalankan secara lokal:

```bash
./flightcomp mission.rom
```

Output-nya meminta input:

```text
Nereid flight computer online.
Cold start complete. Mission ROM mounted; arming gate engaged.
Launch code:
```

Jika input salah, hasilnya:

```text
Arming gate holds -- HOLD.
```

Dari sini terlihat bahwa `mission.rom` kemungkinan berisi logic validasi input. Jadi fokus utama bukan langsung reverse seluruh binary `flightcomp`, tetapi memahami format ROM dan instruksi yang dijalankan emulator.

---

## Struktur ROM

Dari hasil parsing ROM, bagian awal file memiliki header:

```text
43 53 30 31 01 4e 41 01 00 00 36 60 ea 37 00 08
```

Jika dibaca sebagai field:

```text
magic      = "CS01"
version    = 0x01
seed       = 0x4e
code_len   = 0x0141
entry      = 0x0000
crc32      = 0x37ea6036
```

Setelah 16 byte header, sisanya adalah bytecode program VM.

ROM juga memiliki validasi CRC. Jadi sebelum menjalankan logic utama, emulator memastikan isi program tidak rusak atau dimodifikasi sembarangan.

---

## Disassembly Bytecode

Challenge menyediakan script `disas.py`, sehingga bytecode dapat dilihat lebih mudah.

Bagian penting dari disassembly:

```asm
0000: li r1, 0x0000
0004: li r2, 0x0141
0008: li r3, 0x0705
000c: crc r1, r2, r3
...
0064: cmpz r4
0066: jif 0x0070
0069: li r0, 0x0048
006d: out r0
006f: halt
```

Bagian awal ini adalah gate pengecekan integritas. Jika gagal, program mengeluarkan byte `H`, yang berarti `HOLD`.

Jika lolos, eksekusi lanjut ke alamat `0x70`.

---

## Self-Modifying Code

Bagian berikutnya sangat penting:

```asm
0070: li r0, 0x0700
0074: ld8 r1, r0
0077: mov r2, r1
007a: rol r2, 5
007d: xori r2, 60
0080: li r0, 0x00cd
0084: st8 r0, r2
```

Instruksi ini mengambil seed dari ROM, yaitu:

```text
seed = 0x4e
```

Lalu menghitung nilai:

```python
imm = rol8(seed, 5) ^ 0x3c
```

Nilai ini kemudian ditulis ke alamat `0x00cd`.

Pada disassembly, alamat `0x00cd` berada di instruksi berikut:

```asm
00cb: xori r0, 0
```

Jadi sebenarnya immediate `0` pada instruksi `xori r0, 0` akan dipatch saat runtime. Dengan kata lain, bytecode melakukan self-modifying code.

---

## Dekripsi Key

Setelah patching, program mendekripsi key sepanjang 30 byte:

```asm
0089: mov r3, r1
008c: li r5, 0x0105
0090: li r6, 0x001e

0094: rol r3, 3
0097: xori r3, 91
009a: ld8 r0, r5
009d: xor r0, r3
00a0: st8 r5, r0
00a3: addi r5, 1
00a6: addi r6, -1
00a9: cmpz r6
00ab: jnif 0x0094
```

Logic-nya dapat ditulis ulang sebagai Python:

```python
x = seed

for i in range(30):
    x = rol8(x, 3) ^ 0x5b
    key[i] ^= x
```

Key terenkripsi disimpan di offset:

```text
0x105
```

Panjang key:

```text
0x1e = 30 byte
```

---

## Logic Validasi Input

Setelah key didekripsi, program mulai membaca input:

```asm
00b4: li r5, 0x0105
00b8: li r6, 0x0123
00bc: li r7, 0x001e
```

Artinya:

```text
key    = memory[0x105 : 0x105 + 30]
target = memory[0x123 : 0x123 + 30]
len    = 30
```

Bagian pengecekan tiap karakter:

```asm
00c0: in r0
00c2: ld8 r1, r5
00c5: xor r0, r1
00c8: rol r0, 3
00cb: xori r0, patched_imm
00ce: ld8 r2, r6
00d1: cmpeq r0, r2
```

Jika ditulis dalam bentuk rumus:

```python
transformed = rol8(input[i] ^ key[i], 3) ^ imm
```

Program membandingkan hasil tersebut dengan:

```python
target[i]
```

Maka persamaan validasinya adalah:

```python
rol8(input[i] ^ key[i], 3) ^ imm == target[i]
```

Karena semua operasinya reversible, input bisa langsung dibalik tanpa brute force.

---

## Membalik Rumus

Dari persamaan:

```python
rol8(input[i] ^ key[i], 3) ^ imm == target[i]
```

Balik tahap XOR immediate:

```python
rol8(input[i] ^ key[i], 3) == target[i] ^ imm
```

Balik rotasi kiri 3 bit menjadi rotasi kanan 3 bit:

```python
input[i] ^ key[i] == ror8(target[i] ^ imm, 3)
```

Balik XOR key:

```python
input[i] = ror8(target[i] ^ imm, 3) ^ key[i]
```

Jadi flag bisa didapat langsung dari ROM tanpa menjalankan brute force.

---

## Solver

Solver otomatis:

```python
#!/usr/bin/env python3
from pathlib import Path
import argparse
import struct
import subprocess
import sys
import zlib


def rol8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF


def solve_rom(path):
    rom = Path(path).read_bytes()

    if len(rom) < 16 or rom[:4] != b"CS01":
        raise ValueError("bad ROM magic")

    version = rom[4]
    seed = rom[5]
    code_len = struct.unpack_from("<H", rom, 6)[0]
    entry = struct.unpack_from("<H", rom, 8)[0]
    expected_crc = struct.unpack_from("<I", rom, 10)[0]

    code = bytearray(rom[16:16 + code_len])

    if version != 1 or entry != 0:
        raise ValueError("unexpected ROM header")

    got_crc = zlib.crc32(code) & 0xFFFFFFFF
    if got_crc != expected_crc:
        raise ValueError("CRC mismatch")

    imm = rol8(seed, 5) ^ 0x3C

    x = seed
    for i in range(30):
        x = rol8(x, 3) ^ 0x5B
        code[0x105 + i] ^= x

    key = bytes(code[0x105:0x105 + 30])
    target = bytes(code[0x123:0x123 + 30])

    flag = bytes(
        ror8(t ^ imm, 3) ^ k
        for k, t in zip(key, target)
    )

    return flag


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rom", nargs="?", default="mission.rom")
    parser.add_argument("--flightcomp", default="./flightcomp")
    args = parser.parse_args()

    flag = solve_rom(args.rom)
    print(flag.decode())

    if Path(args.flightcomp).exists():
        p = subprocess.run(
            [args.flightcomp, args.rom],
            input=flag,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        sys.stderr.write(p.stdout.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

---

## Menjalankan Solver

Command:

```bash
python3 solve_cold_start.py mission.rom --flightcomp ./flightcomp
```

Output:

```text
uctf{c0ld_st4rt_g0_f0r_l4unch}
Nereid flight computer online.
Cold start complete. Mission ROM mounted; arming gate engaged.
Launch code: Arming gate released -- GO for launch.
```

---

## Flag

```text
uctf{c0ld_st4rt_g0_f0r_l4unch}
```

---

## Kesimpulan

Challenge ini menggunakan binary `flightcomp` sebagai emulator VM sederhana dan `mission.rom` sebagai program validasi. Bagian menariknya ada pada self-modifying code, karena immediate pada instruksi `xori r0, 0` dipatch menggunakan seed dari header ROM. Setelah itu program mendekripsi key 30 byte dan memvalidasi input dengan kombinasi XOR serta rotasi bit.

Karena transformasi validasi hanya menggunakan operasi reversible, launch code dapat diperoleh dengan membalik rumus validasinya, tanpa perlu brute force.
