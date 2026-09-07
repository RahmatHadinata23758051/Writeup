# Scratch Space

## Ringkasan

Flag tidak disimpan sebagai plaintext di binary.

Program menerima input, lalu:

1. melakukan `mmap()` untuk membuat scratch page;
2. mendecode passphrase ke page tersebut;
3. membandingkan input dengan isi page menggunakan loop manual;
4. menghapus isi page dengan zeroing;
5. memanggil `munmap()`;
6. baru mencetak `correct` atau `rejected`.

Jadi `strings`, `ltrace`, dan `strace` tidak memberikan flag secara langsung.

Inti challenge adalah menangkap atau merekonstruksi isi memory scratch page sebelum dihapus.

## File Challenge

File:

```text
scratch-space
```

Tipe:

```text
ELF 64-bit LSB executable, x86-64
```

Binary masih menyimpan symbol dan tidak stripped.

## Analisis Awal

`strings` hanya memberikan string seperti:

```text
guess:
checking...
correct
rejected
```

Tidak ada plaintext flag.

Fungsi library yang terlihat:

```text
mmap
read
write
munmap
```

Ini sudah memberikan petunjuk bahwa program memang membuat memory region sementara.

## Analisis Static

Fungsi utama berada di:

```text
0x401166 <main>
```

Program terlebih dahulu membaca input ke buffer global:

```asm
lea    rax,[rip+0x2f04]        # 4040a0 <input>
mov    edx,0x7f
mov    rsi,rax
mov    edi,0x0
call   read@plt
```

Input kemudian diakhiri dengan `NULL`.

### Membuat Scratch Page

Program memanggil:

```asm
mov    r9d,0x0
mov    r8d,0xffffffff
mov    ecx,0x22
mov    edx,0x3
mov    esi,0x1000
mov    edi,0x0
call   mmap@plt
```

Parameter pentingnya menghasilkan sebuah mapping berukuran:

```text
0x1000 bytes
```

Pointer hasil `mmap()` disimpan di:

```text
[rbp-0x8]
```

Jadi region inilah yang digunakan sebagai scratch page.

## Decoder

Seed awal disimpan di:

```asm
mov    DWORD PTR [rbp-0x1c],0x311023df
```

Setiap iterasi menjalankan LCG:

```asm
imul   eax,eax,0x343fd
add    eax,0x269ec3
mov    DWORD PTR [rbp-0x1c],eax
```

Secara matematis:

```text
state = (state * 0x343fd + 0x269ec3) mod 2^32
```

Kemudian program mengambil byte dari bagian tengah state:

```asm
mov    eax,DWORD PTR [rbp-0x1c]
shr    eax,0x10
```

Byte tersebut digunakan sebagai XOR key terhadap byte pada blob:

```asm
movzx  ecx,BYTE PTR [rax+rdx*1]
...
shr    eax,0x10
...
xor    ecx,esi
mov    BYTE PTR [rax],dl
```

Blob berada di:

```text
0x404040 <blob>
```

Data yang tersimpan:

```text
54 81 f7 8c 0b 8e 37 d2
13 52 ac b1 a9 4e c5 ba
20 46 81 3a 17 10 49 bb
f6 7c 7f 91 12 0c 3e 20
09 b8 c7 ab 8b f3 33 c7
53 e0 00
```

Loop berjalan dari index `0` sampai `0x29`, sehingga 43 byte dihasilkan.

Setelah decoding, byte pada offset `0x2a` dibuat `NULL`:

```asm
mov    rax,[rbp-0x8]
add    rax,0x2a
mov    BYTE PTR [rax],0x0
```

Dengan kata lain, string yang relevan panjangnya 42 byte.

## Recover Passphrase

Decoder dapat direproduksi dengan Python:

```python
blob = bytes.fromhex(
    "5481f78c0b8e37d21352acb1a94ec5ba"
    "2046813a171049bbf67c7f91120c3e20"
    "09b8c7ab8bf333c753e000"
)

state = 0x311023df
out = bytearray()

for b in blob:
    state = (state * 0x343fd + 0x269ec3) & 0xffffffff
    key = (state >> 16) & 0xff
    out.append(b ^ key)

print(out[:0x2a].decode())
```

Hasilnya:

```text
NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}
```

## Analisis Dynamic

Setelah passphrase dibangun di scratch page, program tidak menggunakan `strcmp()` atau `memcmp()`.

Perbandingan dilakukan byte-per-byte:

```asm
movzx  edx,BYTE PTR [rax+rdx]
...
movzx  eax,BYTE PTR [rax]
cmp    dl,al
je     ...
mov    DWORD PTR [rbp-0x14],0x0
```

Loop ini berjalan untuk index:

```text
0 .. 0x29
```

Jadi debugger dapat digunakan untuk berhenti sebelum loop zeroing dan melihat:

```text
[rbp-0x8]
```

sebagai pointer scratch page.

Di `pwndbg`, pointer tersebut dapat diinspeksi menggunakan:

```text
telescope $rbp-0x8
```

atau langsung dump memory yang ditunjuk pointer tersebut.

## Memory Wipe

Setelah comparison selesai, program menghapus seluruh string:

```asm
mov    DWORD PTR [rbp-0x18],0x0

...

mov    rax,[rbp-0x8]
add    rax,rdx
mov    BYTE PTR [rax],0x0
```

Loop berlangsung sampai:

```text
0x2a
```

Jadi seluruh passphrase dihapus dari scratch page.

Setelah itu page dilepas:

```asm
mov    rax,[rbp-0x8]
mov    esi,0x1000
mov    rdi,rax
call   munmap@plt
```

Ini menjelaskan kenapa mencoba memeriksa memory setelah program selesai sudah terlambat.

## Penyusunan Solve Script

Flag tidak perlu diekstrak menggunakan brute force.

Cukup meniru LCG dan XOR decoder:

```python
#!/usr/bin/env python3

blob = bytes.fromhex(
    "5481f78c0b8e37d21352acb1a94ec5ba"
    "2046813a171049bbf67c7f91120c3e20"
    "09b8c7ab8bf333c753e000"
)

state = 0x311023df
decoded = bytearray()

for b in blob:
    state = (state * 0x343fd + 0x269ec3) & 0xffffffff
    decoded.append(b ^ ((state >> 16) & 0xff))

print(decoded[:0x2a].decode())
```

## Cara Menjalankan

Simpan script sebagai:

```text
solve.py
```

lalu:

```bash
python3 solve.py
```

Output:

```text
NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}
```

## Flag

```text
NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}
```
