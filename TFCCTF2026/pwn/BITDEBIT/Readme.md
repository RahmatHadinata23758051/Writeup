# BITDEBIT³

## Ringkasan

Binary memberikan primitive arbitrary bit flip: alamat 64-bit dan nomor bit dikontrol user, lalu program menjalankan `*(unsigned char *)addr ^= 1 << bit`. Program juga membocorkan base libc melalui `dladdr()`. Bit flip dipakai untuk memperbesar `_IO_buf_end` milik `stdin`, sehingga `fgets()` berikutnya membaca payload besar ke area libc dan memungkinkan FSOP.

## Proteksi Binary

Output `file` dan `checksec`:

```text
ELF 64-bit LSB pie executable, dynamically linked
RELRO: Full RELRO
Stack: Canary found
NX: NX enabled
PIE: PIE enabled
SHSTK: Enabled
IBT: Enabled
Stripped: No
Debuginfo: Yes
```

Binary memakai `ld-2.35.so` dan `libc.so.6` yang disediakan di direktori challenge.

## Analisis Program

`setup()` membuat `stdin`, `stdout`, dan `stderr` unbuffered. `leak_libc_base()` mencetak base libc dan alamat `puts`.

Alur rentan di `main()`:

```asm
fgets(address_string, 0x80, stdin)
strtoull(address_string, NULL, 0)
fgets(bit_string, 0x80, stdin)
strtoul(bit_string, NULL, 0)
...
movzx edx, BYTE PTR [address]
shl   esi, cl
xor   edx, esi
mov   BYTE PTR [address], dl
```

Validasi hanya membatasi bit ke rentang 0 sampai 7. Tidak ada validasi alamat, sehingga alamat writable libc dapat dipilih langsung setelah base leak.

## Primitive

Primitive yang terbukti:

```text
Arbitrary one-bit write ke alamat byte yang diketahui.
Libc base leak dari output program.
```

Pada libc challenge, layout `stdin` yang relevan adalah:

```text
_IO_2_1_stdin_       + 0x00
_IO_buf_base         + 0x38
_IO_buf_end          + 0x40
_IO_wide_data        + 0xa0
vtable               + 0xd8
_IO_list_all         0x21b680
```

`_IO_buf_base` mengarah ke short buffer di `stdin + 0x83`. Dengan membalik bit positif pada byte tinggi `_IO_buf_end`, rentang buffer menjadi besar. `fgets(name, 0x100, stdin)` kemudian memicu read besar ke buffer tersebut.

## Strategi Exploit

Payload ditempatkan mulai dari `libc_base + 0x21aaa0 + 0x83`. Isinya terdiri dari:

1. Pemulihan field penting `stdin`, agar cleanup libc tidak crash terlalu awal.
2. Fake `FILE` dengan `_mode > 0`, fake `wide_data`, dan fake wide vtable.
3. Callback `system` pada slot `_IO_WDOALLOCATE`.
4. `_IO_list_all` diarahkan ke fake `FILE`.

Saat program exit, `_IO_flush_all_lockp()` memproses fake stream. Jalur `_IO_wfile_overflow()` lalu memanggil callback `system` dengan string ` sh`, sehingga shell terbuka pada koneksi challenge.

Ada race pada koneksi remote jika command shell dikirim langsung setelah payload. `solve.py` sekarang menunggu marker `See you around traveler` terlebih dahulu, baru mengirim:

```text
cat flag 2>/dev/null; cat /flag 2>/dev/null; exit
```

Mode remote memakai TLS Python `ssl`, setara dengan `ncat --ssl`.

## Exploit Final

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py --remote
```

Atau tentukan host dan port secara langsung:

```bash
python3 solve.py bitdebit3-chal-ed99e3e34bc6016d.challs.ctf.thefewchosen.com 1337
```

Validasi remote menghasilkan:

```text
See you around traveler
TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}
```

## Hasil

<FLAG>TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}</FLAG>

## Catatan Stabilitas

- Solver menggunakan offset libc challenge dan menghitung semua alamat dari libc base leak.
- TLS certificate verification dimatikan karena endpoint challenge memakai sertifikat yang tidak perlu dipercaya oleh solver.
- Mode lokal menjalankan binary dengan loader dan libc challenge. Container lokal tidak memiliki file flag, jadi flag hanya tervalidasi dari service remote.
