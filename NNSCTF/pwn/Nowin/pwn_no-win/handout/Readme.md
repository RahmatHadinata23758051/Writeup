# Writeup: No-Win Scenario

## Informasi Challenge

* **Kategori:** Pwn
* **Judul:** No-Win Scenario
* **Host:** `no-win-scenario-e5f380bca44e.chall.nnsc.tf`
* **Port:** `1337`
* **Flag:** `NNS{n0_win_fUNCtion_s0_Y0u_bUi17_yoUR_oWn_5Ysc411}`

## Ringkasan

Challenge ini memberikan binary pwn sederhana dengan pesan awal:

```text
no win(), so good luck
>
```

Sesuai namanya, binary tidak menyediakan fungsi `win()`. Artinya, exploit tidak bisa diselesaikan dengan teknik klasik seperti overwrite return address langsung ke `win()`. Solusinya adalah membangun syscall sendiri menggunakan ROP/SROP, lalu membaca file flag secara manual.

Eksploitasi dilakukan dengan memanfaatkan buffer overflow untuk mengambil alih RIP, lalu memakai teknik **SROP** atau **Sigreturn-Oriented Programming**. Dengan SROP, register dapat dikontrol penuh untuk memanggil syscall yang dibutuhkan.

Strategi akhir:

1. Trigger buffer overflow.
2. Gunakan `rt_sigreturn` untuk memanggil `read(0, .bss, size)`.
3. Kirim stage kedua ke area `.bss`.
4. Gunakan SROP lagi untuk memanggil `mprotect()` agar `.bss` menjadi executable.
5. Lompat ke shellcode.
6. Shellcode melakukan `open("/flag.txt")`, `read()`, dan `write()`.

## Proteksi Binary

Dari analisis awal, binary memiliki karakteristik berikut:

```text
Architecture: amd64
Canary: disabled
PIE: disabled
NX: enabled
```

Dampaknya:

* **No canary** membuat buffer overflow lebih mudah dieksploitasi.
* **No PIE** membuat alamat gadget dan area `.bss` stabil.
* **NX enabled** membuat stack tidak bisa langsung menjalankan shellcode.
* Karena tidak ada fungsi `win()`, exploit harus memakai syscall sendiri.

## Root Cause

Vulnerability utama adalah buffer overflow pada input user. Program membaca input ke buffer stack tanpa validasi panjang yang aman, sehingga return address dapat dioverwrite.

Offset ke RIP ditemukan sebesar:

```text
offset = 72
```

Setelah 72 byte padding, kita bisa mengontrol RIP.

## Gadget Penting

Karena binary static dan no PIE, alamat gadget stabil. Gadget yang digunakan:

```python
POP_RAX_RET = 0x427eeb
SYSCALL_RET = 0x410f46
```

Gadget `pop rax; ret` dipakai untuk mengisi `rax = 15`, yaitu syscall number untuk `rt_sigreturn`.

Gadget `syscall; ret` dipakai untuk mengeksekusi syscall.

## Kenapa SROP?

ROP biasa membutuhkan banyak gadget untuk mengontrol register seperti `rdi`, `rsi`, `rdx`, `rax`, dan `rip`.

Pada challenge ini, pendekatan yang lebih simpel adalah SROP. Dengan memanggil syscall `rt_sigreturn`, kernel akan memulihkan register dari fake signal frame yang kita susun di stack. Ini memungkinkan kita mengatur register secara penuh hanya dengan sedikit gadget.

Syscall `rt_sigreturn` pada amd64 memakai:

```text
rax = 15
syscall
```

Setelah itu, kernel membaca fake frame dan mengisi register sesuai nilai yang kita buat.

## Alur Exploit

Exploit dibuat dalam dua stage.

### Stage 1: Membaca Stage 2 ke `.bss`

Payload pertama dikirim ke input awal program. Isinya:

```text
padding 72 byte
pop rax; ret
rax = 15
syscall; ret
fake sigreturn frame
```

Fake frame pertama mengatur syscall menjadi:

```c
read(0, BSS, 0x3000)
```

Register yang disiapkan:

```text
rax = 0          // SYS_read
rdi = 0          // stdin
rsi = BSS
rdx = 0x3000
rsp = BSS
rip = syscall_ret
```

Tujuannya adalah membaca payload stage kedua ke area `.bss`, lalu memindahkan stack ke `.bss`.

### Stage 2: Membuat `.bss` Executable

Stage kedua juga memakai SROP, kali ini untuk memanggil:

```c
mprotect(0x4ab000, 0x3000, 7)
```

Register yang disiapkan:

```text
rax = 10         // SYS_mprotect
rdi = 0x4ab000   // page-aligned address
rsi = 0x3000     // size
rdx = 7          // PROT_READ | PROT_WRITE | PROT_EXEC
rip = syscall_ret
```

Setelah `mprotect()` berhasil, area `.bss` menjadi RWX sehingga shellcode bisa dijalankan.

### Stage 3: Shellcode ORW

Karena tidak ada `win()`, shellcode menjalankan syscall secara manual:

```c
open("/flag.txt", 0, 0);
read(fd, buf, 0x100);
write(1, buf, n);
exit(0);
```

Shellcode tidak mengasumsikan file descriptor hasil `open()` selalu bernilai `3`. Nilai return dari `open()` langsung dipakai sebagai argumen `read()`.

Ini penting karena pada remote environment, file descriptor bisa berbeda tergantung konfigurasi service.

## Catatan Transport

Remote service berjalan dengan TLS/SSL. Karena itu exploit perlu dikirim menggunakan koneksi SSL, bukan plain TCP.

Command yang digunakan:

```bash
python3 solve.py no-win-scenario-e5f380bca44e.chall.nnsc.tf 1337 --transport ssl --debug --raw
```

Pada beberapa percobaan, output raw terlihat seperti TLS application data:

```text
\x17\x03\x03...
```

Namun exploit tetap valid, dan flag berhasil didapatkan.

## Flag

Flag yang berhasil diperoleh:

```text
NNS{n0_win_fUNCtion_s0_Y0u_bUi17_yoUR_oWn_5Ysc411}
```

