# Proteus Writeup

## Challenge

Challenge **Proteus** merupakan soal reverse engineering dengan sebuah binary ELF 64-bit. Deskripsi challenge menyebutkan bahwa binary ini menerima sebuah passphrase atau serial, lalu memprosesnya melalui beberapa transformasi reversible. Jika hasil akhir transformasi sama dengan nilai yang disimpan di dalam binary, maka serial dianggap benar.

Format flag yang diminta adalah:

```text
uctf{serial}
```

## Recon

Pertama dilakukan pengecekan file:

```bash
file proteus
```

Hasilnya:

```text
proteus: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

Binary kemudian dianalisis menggunakan `radare2`:

```bash
r2 -A proteus
```

Daftar fungsi:

```text
0x00401016   entry0
0x00401139   main
0x00401000   fcn.00401000
```

Fungsi `main` ternyata hanya berisi instruksi sederhana dan tidak menjadi logic utama. Logic pengecekan serial berada pada `entry0`.

## Analisis Program

Pada awal eksekusi, program menampilkan prompt:

```text
GIVE SERIAL NOW:
```

Kemudian program membaca input user ke area `.bss` sebanyak maksimal `0x100` byte.

Bagian penting berikutnya adalah loop parsing input:

```asm
0x00401059      lea rsi, section..bss
0x00401060      mov ecx, 8

0x00401065      movzx edx, byte [rsi]
0x00401068      call 0x4010df
0x0040106d      shl eax, 4
0x00401070      add eax, edx
0x00401072      inc rsi
0x00401075      dec ecx
0x00401077      jne 0x401065
```

Loop ini membaca tepat 8 karakter dari input. Setiap karakter diproses oleh fungsi di `0x4010df`.

Fungsi tersebut mengubah karakter hex menjadi nilai integer:

```asm
0x004010df      or dl, 0x20
0x004010e2      cmp dl, 0x30
0x004010e7      cmp dl, 0x39
0x004010ec      sub dl, 0x30

0x004010f0      cmp dl, 0x61
0x004010f5      cmp dl, 0x66
0x004010fa      sub dl, 0x57
```

Artinya input harus berupa 8 karakter hexadecimal, misalnya:

```text
deadbeef
```

Setelah 8 karakter hex diparse, program memastikan karakter berikutnya adalah newline atau null byte:

```asm
0x00401079      movzx edx, byte [rsi]
0x0040107c      cmp edx, 0xa
0x0040107f      je 0x401087
0x00401081      test edx, edx
0x00401083      je 0x401087
```

Jika karakter setelah 8 digit hex bukan newline atau null byte, program keluar dengan status gagal.

## Transformasi Serial

Setelah input berhasil diparse menjadi integer 32-bit, program menjalankan rangkaian transformasi berikut:

```asm
0x00401087      imul eax, eax, 0x9e3779b1
0x0040108d      add eax, 0x632be5ab
0x00401092      xor eax, 0x27d4eb2f
0x00401097      rol eax, 0xd
0x0040109a      imul eax, eax, 0x85ebca77
0x004010a0      cmp eax, 0x3dc4329
```

Jika ditulis sebagai pseudocode:

```c
x = input_hex;
x = x * 0x9e3779b1;
x = x + 0x632be5ab;
x = x ^ 0x27d4eb2f;
x = rol32(x, 13);
x = x * 0x85ebca77;

if (x == 0x03dc4329) {
    success();
} else {
    fail();
}
```

Semua operasi dilakukan pada register `eax`, sehingga nilainya berada dalam ruang 32-bit.

Target akhirnya adalah:

```text
0x03dc4329
```

## Strategi Penyelesaian

Karena transformasi yang digunakan bersifat reversible, serial dapat dicari dengan membalik urutan operasi dari nilai target.

Urutan forward:

```text
input
 -> multiply 0x9e3779b1
 -> add 0x632be5ab
 -> xor 0x27d4eb2f
 -> rol 13
 -> multiply 0x85ebca77
 -> target 0x03dc4329
```

Maka urutan reverse:

```text
target
 -> inverse multiply 0x85ebca77
 -> ror 13
 -> xor 0x27d4eb2f
 -> subtract 0x632be5ab
 -> inverse multiply 0x9e3779b1
 -> serial
```

Operasi perkalian dapat dibalik karena konstanta multiplier bernilai ganjil, sehingga memiliki modular inverse terhadap modulo `2^32`.

## Solver

```python
#!/usr/bin/env python3

MOD = 2**32

target = 0x03dc4329

mul1 = 0x9e3779b1
add1 = 0x632be5ab
xor1 = 0x27d4eb2f
mul2 = 0x85ebca77

def ror32(x, r):
    return ((x >> r) | (x << (32 - r))) & 0xffffffff

def inv32(x):
    return pow(x, -1, MOD)

x = target

x = (x * inv32(mul2)) % MOD
x = ror32(x, 13)
x ^= xor1
x = (x - add1) % MOD
x = (x * inv32(mul1)) % MOD

serial = f"{x:08x}"

print("[+] serial:", serial)
print("[+] flag:", f"uctf{{{serial}}}")
```

## Output

Saat solver dijalankan, didapatkan serial berikut:

```text
5d9f2a13
```

Sehingga flag menjadi:

```text
uctf{5d9f2a13}
```

## Verifikasi

Serial dapat diverifikasi langsung ke binary:

```bash
./proteus
```

Kemudian masukkan:

```text
5d9f2a13
```

Program menerima serial tersebut dan menghasilkan output sukses.

## Flag

```text
uctf{5d9f2a13}
```

