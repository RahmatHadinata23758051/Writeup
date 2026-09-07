# Time Lock

## Ringkasan

Binary bergantung pada fungsi libc `time()` untuk mendapatkan waktu saat ini.

Program mengubah timestamp menjadi jumlah hari sejak Unix epoch dan hanya melanjutkan jika hasilnya sama dengan:

```text
0x2cbf34
```

Nilai tersebut adalah jumlah hari dari:

```text
1970-01-01
```

hingga:

```text
9999-01-01
```

Jadi tanggal yang diharapkan program adalah 1 Januari 9999.

Mengubah system clock tidak diperlukan. Binary bersifat dynamically linked dan hanya mengimpor `time()` dari libc, sehingga `LD_PRELOAD` dapat digunakan untuk mengganti implementasi `time()` dengan fungsi buatan sendiri.

## File Challenge

File:

```text
time-lock
```

Tipe:

```text
ELF 64-bit LSB executable, x86-64
dynamically linked
not stripped
```

Import penting:

```text
time@GLIBC_2.2.5
write@GLIBC_2.2.5
_exit@GLIBC_2.2.5
```

Dari sini langsung terlihat bahwa `time()` adalah target untuk `LD_PRELOAD`.

## Analisis Awal

`strings` hanya memberikan string seperti:

```text
sealed
flag
```

Tidak ada plaintext flag.

`objdump -T` menunjukkan:

```text
0000000000000000 DF *UND* 0000000000000000 (GLIBC_2.2.5) time
```

Artinya binary mengambil `time()` dari libc melalui dynamic loader.

## Analisis Static

Entry point berada di:

```text
0x401040
```

Program memanggil:

```asm
40104e: call 401030 <time@plt>
```

Return value dari `time()` berada di:

```text
RAX
```

Selanjutnya nilainya digunakan untuk menghitung jumlah hari sejak Unix epoch.

Bagian pentingnya:

```asm
mov    rcx,rax
imul   rdx
sar    rcx,0x3f
sar    rdx,0xd
sub    rdx,rcx
cmp    edx,0x2cbf34
jne    4010f7
```

Nilai pembanding:

```text
0x2cbf34
```

dalam desimal:

```text
2932532
```

Jumlah hari antara 1970-01-01 dan 9999-01-01 juga:

```text
2932532
```

Jadi kondisi sukses adalah:

```text
time() = timestamp untuk 9999-01-01
```

Timestamp Unix untuk 9999-01-01 UTC:

```text
253370764800
```

atau hexadecimal:

```text
0x3afe130e00
```

## Kenapa Patch Check Saja Tidak Cukup

Program tidak sekadar melakukan:

```c
if (date == 9999)
    print_flag();
```

Setelah check berhasil, program mendecode data flag.

Buffer ciphertext berada di:

```text
0x404020
```

dan terdiri dari 46 byte yang akan didecode.

State awal decoder:

```text
0x4db55fbe
```

Setiap byte menggunakan LCG:

```text
state = state * 0x15a4e35 + 1
```

dengan arithmetic 32-bit.

Byte key diambil dari:

```text
(state >> 16) & 0xff
```

kemudian:

```text
plaintext[i] = ciphertext[i] ^ key
```

Perlu diperhatikan bahwa jalur decoding baru dicapai setelah hasil `time()` lolos pemeriksaan.

Dengan kata lain, memaksa branch condition saja tidak memberikan hasil yang benar; program memang mengandalkan execution path yang sama setelah mendapatkan nilai waktu yang benar.

## LD_PRELOAD

Karena binary memanggil:

```text
time()
```

melalui dynamic loader, kita dapat menyediakan implementasi sendiri.

Source shim sederhana:

```c
#define _GNU_SOURCE
#include <time.h>

time_t time(time_t *t)
{
    time_t fake = 253370764800LL;

    if (t)
        *t = fake;

    return fake;
}
```

Fungsi ini menggantikan `time()` milik libc saat binary dijalankan dengan:

```bash
LD_PRELOAD=./libtime.so ./time-lock
```

Sekarang program melihat timestamp 9999-01-01 tanpa mengubah system clock.

## Penyusunan Library

Compile:

```bash
gcc -shared -fPIC -o libtime.so time.c
```

Kemudian:

```bash
LD_PRELOAD=./libtime.so ./time-lock
```

Program masuk ke success path.

## Recover Flag

Ciphertext pada `.data`:

```text
ca d0 1b 6e c3 ae 20 e4
e9 ff 98 8e 97 53 81 aa
58 09 15 66 2e 8b 55 31
a7 d0 35 cf c2 4d e3 01
3a 8b 96 24 5c b8 c1 2f
d5 00 8c fb d1 a8 00
```

Decoder yang direkonstruksi:

```python
cipher = bytes.fromhex(
    "cad01b6ec3ae20e4"
    "e9ff988e975381aa"
    "580915662e8b5531"
    "a7d035cfc24de301"
    "3a8b96245cb8c12f"
    "d5008cfbd1a800"
)

state = 0x4db55fbe
out = bytearray()

for b in cipher[:46]:
    state = (state * 0x15a4e35 + 1) & 0xffffffff
    key = (state >> 16) & 0xff
    out.append(b ^ key)

print(out.decode())
```

Hasil:

```text
NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}
```

## Cara Menjalankan

Buat shim:

```c
#define _GNU_SOURCE
#include <time.h>

time_t time(time_t *t)
{
    time_t fake = 253370764800LL;

    if (t)
        *t = fake;

    return fake;
}
```

Compile:

```bash
gcc -shared -fPIC -o libtime.so time.c
```

Jalankan:

```bash
LD_PRELOAD=./libtime.so ./time-lock
```

## Flag

```text
NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}
```

