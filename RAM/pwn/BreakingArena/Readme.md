# CTF Writeup — Breaking Arena

**Event:** RMCTF  
**Category:** PWN  
**Difficulty:** Medium  
**Flag:** `RMCTF{AI-imitation}`

---

## Challenge Description

> The Gibson has challenged people all over the world. It has claimed to be able to do anything we people can do and more. So far, it seems to have been right. Can you find a loophole in the competition and gain a competative edge over the Gibson?

**Target:** `10.42.5.10:1337`

---

## Reconnaissance

### Step 1 — Identify Binary Protections

Langkah pertama adalah cek tipe binary dan mitigasi yang aktif.

```bash
file challenge
checksec --file=challenge
```

Hasil pentingnya:

- `ELF 64-bit`, arsitektur `amd64`
- `PIE enabled`
- `No canary found`
- `Stack executable`
- `RWX segments`
- Binary `not stripped`

Ini langsung menarik, karena kombinasi:

- ada **format string**
- ada **stack overflow**
- stack **bisa dieksekusi**

berarti shellcode kemungkinan jauh lebih simpel daripada ROP/ret2libc penuh.

### Step 2 — Observe Program Behavior

Saat dijalankan, program hanya meminta satu input:

```text
Welcome to the Breaking arena! Gonna start you off with a simple competition. You make a move, and I'll do it right back!
Give us your move:
```

Dari kalimat "I'll do it right back", saya curiga input akan dicetak balik memakai `printf(buf)` tanpa format string yang aman.

---

## Static Analysis

### Step 3 — Inspect `main()` and `vuln()`

Disassembly fungsi `vuln()` menunjukkan bug utama:

```c
read(0, buf, 0x60);
printf(buf);
```

Padahal buffer di stack hanya `0x40` byte. Artinya ada dua primitive sekaligus:

- **Format string vulnerability** karena `printf(buf)`
- **Stack buffer overflow** karena `read()` membaca `0x60` byte ke buffer `0x40`

Offset stack-nya juga enak:

- buffer mulai di `[rbp-0x40]`
- saved RIP berada `0x48` byte dari awal buffer

Jadi payload 72 byte sudah cukup untuk overwrite RIP.

### Step 4 — Analyze the Seccomp Filter

Di `main()`, binary memuat daftar syscall yang diizinkan dari `./filter.txt`.

Isi awal file:

```text
1
2
60
231
262
```

Kalau diterjemahkan:

- `1`  -> `write`
- `2`  -> `open`
- `60` -> `exit`
- `231` -> `exit_group`
- `262` -> `newfstatat`

Yang penting: **`read(0, ...)` tidak diizinkan setelah seccomp aktif**. Itu menjelaskan kenapa exploit biasa untuk ORW langsung gagal. Kita butuh jalan memutar.

---

## Exploitation

### Step 5 — Leak Stack Address and Re-enter `vuln()`

Karena ada format string, saya pakai payload untuk leak:

- alamat buffer stack
- alamat return ke `main+0x13a7`

Payload leak:

```python
(b"%1$p.%15$p\n\x00").ljust(72, b"A") + b"\xa7"
```

Idenya:

- `%1$p` leak pointer stack yang kebetulan menunjuk ke buffer
- `%15$p` leak return address di dalam binary
- byte terakhir `\xa7` mengubah low byte saved RIP agar return ke `main+0x13a7`, yaitu call `vuln()` lagi

Jadi satu input memberi dua hasil:

1. dapat alamat stack untuk shellcode
2. program masuk lagi ke `vuln()` sehingga kita bisa kirim payload tahap berikutnya

### Step 6 — Abuse Executable Stack

Karena stack executable, saya tidak perlu gadget libc atau ret2libc panjang. Cukup:

- taruh shellcode di buffer
- overwrite RIP dengan alamat buffer hasil leak

Payload umum:

```python
payload = shellcode.ljust(72, b"\x90") + p64(buf_addr)
```

Setelah `ret`, eksekusi langsung lompat ke shellcode di stack.

### Step 7 — Patch `filter.txt` to Allow `read`

Masalah utama exploit adalah seccomp. Syscall `read` diblok, jadi shellcode ORW biasa tidak akan bisa membaca file flag.

Solusinya adalah memanfaatkan fakta bahwa:

- `open` diizinkan
- `write` diizinkan
- target membaca filter dari file lokal `./filter.txt` tiap proses baru

Maka shellcode tahap pertama hanya melakukan:

1. `open("./filter.txt", O_WRONLY | O_TRUNC, 0)`
2. `write(fd, "0\n1\n2\n60\n231\n262\n", 17)`
3. `exit(0)`

Isi baru `filter.txt` menambahkan syscall `0`, yaitu `read`.

Setelah koneksi berikutnya dibuat, proses baru memuat filter yang sudah dipatch. Mulai saat itu exploit bisa melakukan ORW normal.

### Step 8 — Verify the Patch Remotely

Sesudah patch, saya uji baca `./filter.txt` di remote. Output-nya berubah jadi:

```text
0
1
2
60
231
262
```

Artinya patch berhasil dan persisten antar-koneksi.

### Step 9 — Enumerate the Root Directory

Ternyata flag tidak berada di `/flag.txt`. Saat mencoba beberapa path umum, hasilnya kosong.

Karena `read` sudah berhasil di-whitelist, saya naikkan lagi whitelist menjadi:

```text
0
1
2
60
217
231
262
```

Angka `217` adalah syscall `getdents64`, yang bisa dipakai untuk listing direktori.

Dengan shellcode kecil:

1. `open("/", O_DIRECTORY)`
2. `getdents64(fd, buf, 0x1000)`
3. `write(1, buf, nbytes)`

saya bisa parse isi root filesystem remote.

Nama file yang menarik muncul di `/`:

```text
flagm5eJllzNN3E3DIBAmwuiWWDyWcqnsOpGz3pannFU.txt
```

Jadi flag memang disimpan di root, tapi dengan nama acak panjang.

### Step 10 — Bypass the 72-byte Path Limit

Ada masalah baru: string path flag terlalu panjang untuk dimasukkan langsung ke shellcode 72 byte bersama logic ORW.

Solusinya adalah split jadi dua tahap:

#### Stage 0

Shellcode mini di stack:

1. `read(0, stage2_addr, 0x400)`
2. `jmp stage2_addr`

Karena `read` sekarang sudah allowed, stage kecil ini cukup pendek untuk muat dalam 72 byte.

#### Stage 1

Setelah stage 0 berjalan, saya kirim shellcode kedua yang lebih panjang berisi:

1. `open("/flagm5eJllzNN3E3DIBAmwuiWWDyWcqnsOpGz3pannFU.txt", O_RDONLY)`
2. `read(fd, outbuf, 0x200)`
3. `write(1, outbuf, nbytes)`
4. `exit(0)`

Hasilnya flag tercetak ke socket.

---

## Flag

```text
RMCTF{AI-imitation}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Format String** | `printf(buf)` memungkinkan leak alamat stack dan code pointer |
| 2 | **Stack Buffer Overflow** | `read(0, buf, 0x60)` ke buffer `0x40` memberi kontrol RIP |
| 3 | **Executable Stack** | Shellcode bisa dijalankan langsung tanpa ROP rumit |
| 4 | **Writable Seccomp Policy Source** | `filter.txt` dibaca dari filesystem setiap proses dan bisa ditimpa lewat syscall yang sudah diizinkan |
| 5 | **Predictable Re-entry Primitive** | Satu-byte overwrite di saved RIP cukup untuk kembali memanggil `vuln()` |

---

## Remediation

1. **Jangan pernah pakai `printf(user_input)`** — selalu gunakan format string tetap seperti `printf("%s", buf)`
2. **Batasi panjang input sesuai ukuran buffer** — gunakan `read(fd, buf, sizeof(buf)-1)` atau wrapper yang aman
3. **Nonaktifkan executable stack** — aktifkan NX dengan benar dan hilangkan segment RWX
4. **Jangan simpan policy seccomp di file yang bisa diubah proses target** — whitelist harus hardcoded atau dimuat dari lokasi read-only
5. **Tambahkan stack canary dan full RELRO** — ini tidak menyelesaikan semua bug, tapi menaikkan biaya exploit secara signifikan

---

## Tools Used

- `checksec` — identifikasi mitigasi binary
- `objdump` — baca disassembly `main` dan `vuln`
- `pwntools` — leak, shellcode assembly, dan automasi exploit
- `python` — parsing output `getdents64`
- `nc` / remote socket via pwntools — interaksi dengan service

---

## Attack Flow

```text
Start binary
      │
      ▼
Find format string + overflow in vuln()
      │
      ▼
Leak stack address with %1$p
Leak return into main with %15$p
      │
      ▼
One-byte RIP overwrite -> re-enter vuln()
      │
      ▼
Jump to shellcode on executable stack
      │
      ▼
Stage 1: overwrite ./filter.txt so syscall read(0) is allowed
      │
      ▼
Reconnect to service
      │
      ▼
Patch again to allow getdents64
      │
      ▼
List "/" and discover randomized flag filename
      │
      ▼
Use tiny loader shellcode: read bigger stage from socket
      │
      ▼
Stage 2: open/read/write randomized flag file
      │
      ▼
Print flag -> RMCTF{AI-imitation}
```
