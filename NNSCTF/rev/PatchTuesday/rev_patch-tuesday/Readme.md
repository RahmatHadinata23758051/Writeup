# Writeup CTF: Patch Tuesday

- **Kategori:** Reverse Engineering
- **Tingkat Kesulitan:** Medium
- **Artefak:** `free-flag.exe`, `solve.py`
- **Flag:** `NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}`

---

# 1. Deskripsi Tantangan

Diberikan sebuah binary Windows x86-64:

```
free-flag.exe
```

Program meminta input dari user kemudian menentukan apakah masuk ke jalur:

```
Correct
```

atau:

```
Sorry
```

Namun pemeriksaan dibuat agar jalur sukses hampir mustahil dicapai melalui input normal.

Program memeriksa jumlah byte yang berhasil dibaca oleh fungsi:

```
ReadFile
```

kemudian membandingkannya dengan nilai:

```
0x1337
```

Solusi challenge adalah melakukan patch terhadap conditional jump sehingga program selalu masuk ke jalur decode flag.

---

# 2. File Challenge

File utama:

```
free-flag.exe
```

Informasi binary:

```
PE32+ executable, x86-64
```

Image base:

```
0x140000000
```

Entry point:

```
0x140001000
```

Section penting:

| Section | RVA |
|---|---|
| `.text` | `0x1000` |
| `.rdata` | `0x2000` |
| `.data` | `0x3000` |

---

# 3. Analisis Awal

## String yang Ditemukan

Hasil pencarian string:

```
Press ENTER to get a free NNS{ flag:
```

```
Correct! Here is your free flag:
```

```
Sorry, no free flag for you.
```

---

## Import API

Program menggunakan beberapa fungsi Windows API:

```
GetStdHandle
ReadFile
WriteFile
ExitProcess
```

Alur program:

```
GetStdHandle(stdin)
        |
        v
WriteFile(prompt)
        |
        v
ReadFile(input)
        |
        v
check(bytes_read)
        |
        v
Correct / Sorry
```

---

# 4. Analisis Static

Setelah fungsi:

```
ReadFile
```

dipanggil, jumlah byte yang berhasil dibaca disimpan di stack.

Potongan assembly:

```asm
140001065:
lea    r9,[rsp+0x34]

14000106a:
mov    rcx,rsi

14000106d:
mov    r8d,0x10

140001073:
call   [ReadFile]
```

Nilai jumlah byte kemudian digunakan:

```asm
140001079:
mov    ecx,DWORD PTR [rsp+0x34]

14000107d:
call   0x140001160
```

---

# 5. Fungsi Check

Fungsi:

```
0x140001160
```

berisi:

```asm
140001160:
xor    eax,eax

140001162:
cmp    ecx,0x1337

140001168:
sete   al

14000116b:
ret
```

Secara logika:

```c
return bytes_read == 0x1337;
```

Nilai:

```
0x1337 = 4919
```

Namun:

```asm
ReadFile(...,0x10,...)
```

hanya meminta membaca:

```
16 byte
```

Sehingga:

```
bytes_read == 4919
```

tidak mungkin terjadi melalui input normal.

---

# 6. Analisis Conditional Branch

Setelah fungsi pengecekan selesai:

```asm
14000107d:
call   0x140001160

140001082:
test   eax,eax

140001084:
je     0x140001088

140001086:
jmp    0x14000108d
```

Logika:

```
check() == 0

    |
    v

JE 0x140001088

    |
    v

jalur gagal
```

Sedangkan:

```
check() != 0

    |
    v

JMP 0x14000108d

    |
    v

decode + print flag
```

Jadi instruksi:

```
0x140001084
```

merupakan titik patch.

---

# 7. Patch Instruction

Instruksi asli:

```
JE 0x140001088
```

Opcode:

```
74 02
```

Karena:

```
0x74 = JE rel8
```

maka diubah menjadi:

```
75 02
```

Dimana:

```
0x75 = JNE rel8
```

Patch:

```
JE  -> JNE
```

---

## Efek Setelah Patch

Sebelum:

```
check() == 0

    |
    v

JE diambil

    |
    v

jalur gagal
```

Sesudah:

```
check() == 0

    |
    v

JNE tidak diambil

    |
    v

lanjut ke JMP

    |
    v

decode flag
```

---

# 8. Offset Patch File

Instruksi berada pada:

```
RVA 0x1084
```

Mapping section:

```
raw .text = 0x400
```

Perhitungan:

\[
0x400+(0x1084-0x1000)
\]

hasil:

```
0x484
```

Sehingga perubahan raw file:

```
offset 0x484:

74 -> 75
```

File hasil patch:

```
free-flag-patched.exe
```

---

# 9. Flag Decoder

Setelah branch sukses, program menjalankan decoder XOR.

Buffer berada pada:

```
0x140003000
```

Assembly:

```asm
14000108f:
lea    rcx,[rip+0x1f6a]

1400010a0:
xor    BYTE PTR [rax+rcx],0x5a

1400010a4:
inc    rax

1400010a7:
cmp    rax,0x4c

1400010ab:
jne    0x1400010a0
```

---

## Algoritma Decode

Setiap byte:

```
ciphertext XOR 0x5a
```

Jumlah byte:

```
0x4c = 76 byte
```

Formula:

```python
flag = bytes(
    x ^ 0x5a
    for x in encrypted
)
```

---

# 10. Ciphertext `.data`

Data terenkripsi:

```
14 14 09 21 6b 05 32 6a 2a 69 05 23 6a 2f 05 2a
6e 6d 39 32 69 3e 05 6d 32 69 05 6a 2a 39 6a 3e
69 05 3e 2f 28 6b 34 3d 05 28 2f 34 6d 6b 37 69
05 30 34 20 05 6b 6f 05 37 2f 39 32 05 38 69 6d
6d 69 28 05 6d 32 6e 34 05 30 20 27
```

Setelah XOR:

```
NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}
```

---

# 11. Cara Manual Menggunakan Debugger

Menggunakan x64dbg:

Breakpoint:

```
0x140001084
```

Saat berhenti:

Instruksi:

```
JE 140001088
```

ubah menjadi:

```
JNE 140001088
```

Kemudian lanjutkan eksekusi.

Program akan melewati validasi dan menjalankan decoder.

---

# 12. Solve Script

```python
#!/usr/bin/env python3

from pathlib import Path


p = Path("free-flag.exe")

b = p.read_bytes()


# .data raw offset 0x800
# RVA 0x3000

blob = b[
    0x800:
    0x800 + 0x4c
]


flag = bytes(
    x ^ 0x5a
    for x in blob
)


print(flag.decode())
```

---

# 13. Cara Menjalankan

```bash
python3 solve.py
```

Output:

```text
NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}
```

---

# 14. Kesimpulan

Challenge ini memanfaatkan kesalahan sederhana pada logika branch.

Program tidak memiliki masalah pada algoritma decode, tetapi jalur menuju decoder sengaja dibuat tidak dapat dicapai.

Kerentanan utama:

1. Pemeriksaan jumlah byte:

```
bytes_read == 0x1337
```

tidak mungkin terpenuhi.

2. Conditional jump:

```
JE
```

menghalangi jalur sukses.

3. Patch:

```
JE -> JNE
```

memaksa program masuk ke jalur decode.

Setelah patch diterapkan, buffer `.data` dapat didecode menggunakan XOR:

```
0x5a
```

Flag berhasil diperoleh:

```
NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}
```
