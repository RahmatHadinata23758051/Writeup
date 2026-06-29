# Legacy Ledger

Binary ini punya bug format string di menu `deposit` dan `withdraw`. Input dipassing langsung ke `printf(buf)` tanpa format tetap, jadi kita dapat arbitrary write dengan `%n`.

Banner awal juga ngebocorin alamat stack:

```text
%p, %p
```

Pointer pertama adalah alamat buffer input di stack (`rbp-0x410`). Dari situ lokasi saved return address bisa dihitung langsung:

```text
saved_rip = buf_addr + 0x418
```

`checksec` nunjukin dua hal yang bikin jalurnya simpel:

- PIE aktif, jadi alamat code acak.
- Stack executable karena binary di-build dengan `-z execstack`.

Jadi tidak perlu ret2libc. Cukup:

1. Ambil leak alamat `buf` dari banner.
2. Masuk ke menu `deposit`.
3. Kirim format string payload untuk overwrite saved RIP ke shellcode yang kita taruh di buffer yang sama.
4. Shellcode diletakkan agak ke belakang supaya input `exit` berikutnya tidak merusak byte awal shellcode.
5. Kirim `exit` supaya `main()` return dan lompat ke shellcode.
6. Setelah dapat shell, baca `/app/flag.txt`.

Disassembly bagian vulnerable:

```asm
12c7: call fgets@plt
12cc: lea  rax,[rbp-0x410]
12d3: mov  rdi,rax
12db: call printf@plt
```

Itu cukup untuk arbitrary write dengan `fmtstr_payload(12, ...)`.

Payload final pakai `write_size="short"` buat nulis alamat shellcode ke saved RIP, lalu append `shellcraft.sh()` ke buffer.

Run exploit:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE
```

Output:

```text
TBCTF{b0rg3d-5t@ck}
```
