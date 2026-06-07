# Slot Machine

Challenge ini ternyata sederhana begitu binary-nya dibongkar:

- ELF 64-bit AMD64
- No PIE
- No canary
- Stack executable
- Binary tidak stripped

Jadi target utamanya bukan ROP yang rumit, tapi `ret2win` lewat stack overflow di `gets()`.

## Temuan

Di `game_loop()` ada:

```c
char cmd[32];
gets(cmd);
```

Itu langsung memberi kontrol ke stack buffer tanpa batas panjang. Dari disassembly, buffer ada di `[rbp-0x20]`, jadi offset ke saved RIP adalah:

- `0x20` byte buffer
- `+ 8` byte saved RBP
- total `40` byte ke saved RIP

Fungsi yang kita tuju adalah `jackpot()` di alamat `0x401206`.

## Kenapa partial overwrite

Karena binary ini non-PIE, alamat return dari `game_loop()` dan alamat `jackpot()` sama-sama ada di area:

`0x000000000040xxxx`

Return address asli dari `game_loop()` adalah `0x4017a5`, sedangkan `jackpot()` ada di `0x401206`.

Artinya kita cukup mengubah 3 byte terbawah return address:

- dari `a5 17 40`
- jadi `06 12 40`

Dengan begitu kita tidak perlu menulis byte `0x00`, yang berguna kalau transport remote atau wrapper TTY mempersulit byte NUL.

## Alur Exploit

1. Kirim payload:
   - `A` sebanyak 40 byte
   - lalu 3 byte alamat `jackpot`
2. Tutup sisi kirim socket agar `gets()` mendapat EOF
3. `game_loop()` return
4. Control flow lompat ke `jackpot()`
5. Program membuka `flag.txt` dan mencetak flag

## File

- [`exploit.py`](./exploit.py)

## Cara Jalan

Local:

```bash
python3 exploit.py
```

Remote:

```bash
python3 exploit.py REMOTE
```

Kalau mau set host/port sendiri:

```bash
HOST=instancer.dalctf2026.com PORT=49480 python3 exploit.py REMOTE
```

Script akan coba beberapa pola kirim payload:

1. Overflow 1 line lalu `exit`
1. `exit\x00` + overflow penuh
1. Overflow penuh lalu EOF socket

## Catatan

Local test di folder ini memakai `flag.txt` dummy supaya jalur `jackpot()` bisa langsung dibuktikan. Saat remote hidup lagi, script yang sama tinggal dijalankan tanpa perubahan.
