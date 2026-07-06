# SROP Detector

Challenge ini ternyata bukan soal bypass detector yang rumit, tapi soal memanfaatkan buffer overflow yang sangat jelas di fungsi input.

Binary `slop_detector` adalah ELF 64-bit non-PIE dengan NX aktif, tanpa stack canary, dan hanya punya gadget yang sangat minim di binary. Vulnerability utamanya ada di fungsi `srop_detector()`: program menyiapkan buffer stack sebesar `0x40`, lalu memanggil `read(0, buf, 0x200)`. Jadi kita bisa overwrite saved `rbp` dan return address dengan mudah.

Offset ke return address adalah `72` byte. Proteksi CET memang tertulis di ELF (`SHSTK` dan `IBT`), tapi pada runtime challenge alur return masih bisa kita kendalikan.

## Ringkasan exploit

Tahap pertama dipakai untuk leak alamat `puts` dari GOT:

- pakai gadget `pop rdi; ret` di `0x401311`
- panggil `puts@plt(puts@got)`
- balik lagi ke `main`

Dari leak itu, base libc bisa dihitung dengan akurat. Saya cocokkan libc challenge dengan image `ubuntu:22.04` dari Dockerfile, dan offset-offset simbolnya memang sesuai.

Tahap kedua tidak langsung ret2libc biasa ke `system("/bin/sh")`, karena saya ingin jalur yang lebih stabil. Saya pivot stack ke `.bss`, lalu jalankan chain libc untuk:

- set `rdi = "/bin/sh"`
- set `rsi = argv`
- set `rdx = 0`
- panggil `execve("/bin/sh", argv, NULL)`

`argv` saya siapkan sendiri di `.bss` sebagai array:

- `argv[0] = "/bin/sh"`
- `argv[1] = NULL`

Pivot ke `.bss` dilakukan dengan:

- overwrite `rbp` menjadi alamat `.bss`
- return ke blok `read` di `0x4012f0`
- blok itu membaca stage kedua ke area `rbp-0x40`
- saat fungsi selesai, `leave; ret` otomatis memindahkan stack ke `.bss`

Setelah shell aktif, script tinggal mengirim:

```sh
cat /flag.txt
```

dan flag keluar.

## Flag

```text
dalctf{1_r34lly_h0p3_u_d1dnt_sl0p_1t}
```

## Menjalankan solver

Remote:

```sh
python3 exploit.py
```

Lokal dengan runtime Ubuntu 22.04 yang sudah saya salin:

```sh
python3 exploit.py LOCAL=1
```
