# Writeup CTF Reverse Engineering — Because There is no one Make Reverse So I Create This Chal

## Informasi Challenge

**Judul:** Because There is no one Make Reverse So I Create This Chal
**Kategori:** Reverse Engineering
**File:** `chal`

Challenge memberikan sebuah binary bernama `chal`. Setelah dicek menggunakan `file`, binary tersebut terdeteksi sebagai Mach-O 64-bit arm64 executable, sehingga tidak bisa langsung dijalankan di Linux x86_64 dan menghasilkan `exec format error`.

## Recon Awal

Pertama dilakukan pengecekan file dan string:

```bash
file chal
strings chal
```

Output penting dari `strings`:

```text
flag>
No input.
Nope.
Payload error.
Correct!
```

String tersebut menunjukkan bahwa program meminta input flag, lalu memberikan output `Correct!` jika input benar.

Karena binary tidak bisa dijalankan langsung di environment Linux, analisis dilakukan menggunakan `radare2`.

```bash
r2 -A chal
```

Fungsi yang ditemukan:

```text
main
sym.func.1000008dc
sym.func.100000ab0
```

## Analisis Main Function

Pada fungsi `main`, program mencetak prompt:

```text
flag>
```

Kemudian membaca input menggunakan `fgets`. Program juga membersihkan newline menggunakan `strcspn`.

Setelah input dibaca, program melakukan alokasi buffer sebesar `0x2c4` byte:

```asm
movz w0, 0x2c4
bl sym.imp.malloc
```

Buffer ini nantinya dipakai sebagai hasil decrypt payload atau bytecode VM.

Program kemudian memanggil fungsi:

```asm
bl sym.func.100000ab0
```

Fungsi ini menghasilkan key dengan cara XOR dua konstanta 16 byte dari section `__const`.

Key hasil XOR:

```text
0x2580f501
0xd194e025
0x9f48ceeb
0x05488ea6
```

## Dekripsi Bytecode

Di dalam `main`, terdapat proses decrypt data dari section `__const` pada alamat `0x100000b98` sepanjang `0x2c4` byte. Proses decrypt menggunakan algoritma mirip TEA/XTEA untuk menghasilkan keystream, lalu hasilnya di-XOR dengan data terenkripsi.

Setelah decrypt, program menghitung hash terhadap hasil bytecode:

```asm
h = (h ^ byte) * 0x01000193
```

Nilai awal hash:

```text
0x811c9dc5
```

Nilai target:

```text
0x4b9fb9f7
```

Jika hash tidak cocok, program masuk ke jalur `Payload error` atau `Nope`. Jika cocok, program lanjut ke VM validator.

Awalnya implementasi decrypt sempat salah karena `sum += delta` ditambahkan dua kali per round. Setelah disesuaikan dengan assembly, ternyata `sum` hanya naik satu kali per round. Setelah diperbaiki, hash bytecode menjadi benar:

```text
0x4b9fb9f7
```

## Analisis VM

Setelah bytecode berhasil didecrypt dan hash valid, program memanggil:

```asm
sym.func.1000008dc
```

Fungsi ini adalah VM interpreter yang menerima:

```text
arg1 = bytecode hasil decrypt
arg2 = input user
arg3 = panjang input
```

VM memiliki beberapa opcode penting:

```text
0xcd = cek panjang input
0x97 = pilih index input
0x86 = load karakter input pada index tertentu
0x15 = XOR immediate
0x18 = ADD immediate
0xe5 = SUB immediate
0x74 = ROL immediate
0x8f = compare accumulator dengan immediate
0x5b = jump
0x5a = halt / success
```

Opcode-opcode tersebut terlihat dari percabangan pada fungsi VM, di mana VM membaca bytecode, memodifikasi accumulator, lalu membandingkan hasilnya.

Karena setiap karakter flag divalidasi secara independen dengan operasi sederhana seperti XOR, ADD, SUB, dan ROL, kita bisa menulis solver untuk meniru VM lalu mencari karakter printable yang memenuhi setiap constraint.

## Solver

Solver berikut melakukan:

1. Ekstrak data terenkripsi dari section `__const`.
2. Ekstrak dua konstanta key.
3. XOR dua konstanta untuk mendapatkan key asli.
4. Generate keystream TEA-like.
5. XOR ciphertext dengan keystream untuk mendapatkan bytecode VM.
6. Validasi hash bytecode.
7. Interpret bytecode dan recover flag.

```python
#!/usr/bin/env python3
import subprocess
import struct
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "chal"
MASK = 0xffffffff

def r2p8(addr, size):
    out = subprocess.check_output(
        ["r2", "-q", "-c", f"p8 {size} @ {addr}", "-c", "q", BIN],
        text=True
    )
    hx = "".join(out.split())
    return bytes.fromhex(hx)

def u32(x):
    return x & MASK

def rol8(x, n):
    x &= 0xff
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xff

enc = r2p8("0x100000b98", 0x2c4)
ka = r2p8("0x100000e5c", 0x10)
kb = r2p8("0x100000e6c", 0x10)

key = [
    struct.unpack_from("<I", ka, i)[0] ^ struct.unpack_from("<I", kb, i)[0]
    for i in range(0, 16, 4)
]

def stream_block(block_index):
    v0 = u32(block_index + 0xafd9e340)
    v1 = 0x1e403058
    s = 0
    delta = 0x9e3779b9

    for _ in range(32):
        t = u32(((v1 << 4) ^ (v1 >> 5)))
        t = u32(t + v1)
        t ^= u32(s + key[s & 3])
        v0 = u32(v0 + t)

        s = u32(s + delta)

        t = u32(((v0 << 4) ^ (v0 >> 5)))
        t = u32(t + v0)
        t ^= u32(s + key[(s >> 11) & 3])
        v1 = u32(v1 + t)

    return struct.pack("<II", v0, v1)

code = bytearray()

for off in range(0, len(enc), 8):
    ks = stream_block(off >> 3)
    for a, b in zip(enc[off:off+8], ks):
        code.append(a ^ b)

code = bytes(code[:0x2c4])

h = 0x811c9dc5
for b in code:
    h = u32((h ^ b) * 0x01000193)

print("[+] key =", [hex(x) for x in key])
print("[+] vm hash =", hex(h))

def apply_ops(ch, ops):
    x = ch & 0xff

    for op, imm in ops:
        if op == "xor":
            x ^= imm
        elif op == "add":
            x = (x + imm) & 0xff
        elif op == "sub":
            x = (x - imm) & 0xff
        elif op == "rol":
            x = rol8(x, imm)
        else:
            raise ValueError(op)

    return x

def solve_constraints(code):
    ip = 0
    fuel = 0x589
    idx = 0
    length = None
    ops = []
    chars = {}

    while fuel > 0:
        fuel -= 1
        old = ip
        op = code[ip]
        ip += 1

        if op == 0x5a:
            break

        elif op == 0xcd:
            imm = code[ip]
            ip += 1
            length = imm

        elif op == 0x97:
            idx = code[ip]
            ip += 1

        elif op == 0x86:
            ops = []

        elif op == 0x15:
            ops.append(("xor", code[ip]))
            ip += 1

        elif op == 0x18:
            ops.append(("add", code[ip]))
            ip += 1

        elif op == 0xe5:
            ops.append(("sub", code[ip]))
            ip += 1

        elif op == 0x74:
            ops.append(("rol", code[ip]))
            ip += 1

        elif op == 0x8f:
            target = code[ip]
            ip += 1

            sols = [
                c for c in range(32, 127)
                if apply_ops(c, ops) == target
            ]

            if not sols:
                sols = [
                    c for c in range(256)
                    if apply_ops(c, ops) == target
                ]

            if not sols:
                raise RuntimeError(
                    f"no solution at ip={old:x}, idx={idx}, target={target:02x}, ops={ops}"
                )

            chars[idx] = sols[0]

        elif op == 0x5b:
            imm = code[ip]
            ip = old + imm + 2

        else:
            raise RuntimeError(f"unknown opcode {op:02x} at {old:x}")

    if length is None:
        length = max(chars) + 1

    flag = bytearray(b"?" * length)

    for i, c in chars.items():
        if i < length:
            flag[i] = c

    return flag.decode(errors="replace")

def vm(code, s):
    s = s.encode()
    ip = 0
    fuel = 0x589
    acc = 0
    err = 0
    idx = 0

    while fuel > 0:
        fuel -= 1
        old = ip
        op = code[ip]
        ip += 1

        if op == 0x5a:
            return err == 0

        elif op == 0xcd:
            err |= (len(s) ^ code[ip])
            ip += 1

        elif op == 0x97:
            idx = code[ip]
            ip += 1

        elif op == 0x86:
            acc = s[idx] if idx < len(s) else 0

        elif op == 0x15:
            acc ^= code[ip]
            acc &= 0xff
            ip += 1

        elif op == 0x18:
            acc = (acc + code[ip]) & 0xff
            ip += 1

        elif op == 0xe5:
            acc = (acc - code[ip]) & 0xff
            ip += 1

        elif op == 0x74:
            acc = rol8(acc, code[ip])
            ip += 1

        elif op == 0x8f:
            err |= (acc ^ code[ip])
            ip += 1

        elif op == 0x5b:
            imm = code[ip]
            ip = old + imm + 2

        else:
            return False

    return False

flag = solve_constraints(code)

print("[+] flag =", flag)
print("[+] vm ok =", vm(code, flag))
```

## Eksekusi Solver

Jalankan solver:

```bash
python3 solve_rev.py ./chal
```

Output:

```text
[+] key = ['0x2580f501', '0xd194e025', '0x9f48ceeb', '0x5488ea6']
[+] vm hash = 0x4b9fb9f7
[+] flag = THJCC{1_w0nd3r_h0w_l0n6_41_50lv35_17_>w<}
[+] vm ok = True
```

## Flag

```text
THJCC{1_w0nd3r_h0w_l0n6_41_50lv35_17_>w<}
```
