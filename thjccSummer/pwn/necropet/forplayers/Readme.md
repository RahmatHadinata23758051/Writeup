# necropet

## Ringkasan

Bug ada di state `desk` dan alur `release`/`revise`. Setelah record di-release, pointer object di `desk` tidak ikut dihapus. `revise` masih menulis ke chunk yang sudah di-free, sehingga didapat primitive UAF write ke entry tcache. Primitive ini dipakai untuk menimpa handler command `cook` dengan `system`, lalu `cook sh` menjalankan command shell.

Flag remote diperoleh langsung dari output service:

```text
THJCC{Tell_me,_Linguini,_about_your_interests...D0_u_1ik3_anima1s?The_u5ua1,_d0gs,_cats,_h0r535,_guinea_pigs...RATS~~}
```

## Proteksi Binary

```text
ELF 64-bit LSB PIE, x86-64, dynamically linked, not stripped
RELRO: Full RELRO
Canary: found
NX: enabled
PIE: enabled
SHSTK: enabled
IBT: enabled
FORTIFY: enabled
```

Binary memakai `libc.so.6` dan loader yang disediakan challenge. `solve.py` selalu memakai keduanya pada mode lokal maupun GDB.

## Analisis Program

`admit <slot> <kind> <note_cap> <note_len>` mengalokasikan object dengan ukuran `note_cap + 0x28`. Entry `kennels[slot]` menyimpan pointer object, ukuran allocation, dan case id. `select` menyalin pointer dan metadata tersebut ke global `desk`.

`release` memanggil `free(kennels[slot].object)` dan mengosongkan pointer serta ukuran di `kennels`, tetapi case id di entry dan pointer object di `desk` tidak dibersihkan. Validasi di `revise`, `show`, dan `visit` hanya mencocokkan case id serta slot, sehingga object freed masih dapat diakses melalui `desk`.

## Vulnerability

`revise` memakai ukuran allocation yang tersimpan di `desk`, lalu membaca data mulai dari `desk.object`:

```asm
mov rdi, [desk]
mov rax, [desk+8]
...
call read_exact
```

Ukuran yang diizinkan adalah ukuran chunk penuh, jadi setelah `release` fungsi ini menulis langsung ke user area chunk tcache yang sudah dibebaskan. Ini memberi arbitrary tcache forward-pointer overwrite dengan batas panjang chunk.

`visit` juga memanggil `printf("%s the %s...", object, object->species)`. Field `species` dapat diubah lewat `revise`, sehingga pointer ke `kennels` dan GOT dapat dibaca sebagai raw string. Leak yang dipakai:

- pointer object pada `kennels` untuk heap address;
- pointer `puts` dari GOT untuk libc base;
- pointer species awal untuk PIE base.

## Strategi Exploit

1. Buat dua object dengan `note_cap=0x20`, sehingga ukuran request malloc adalah `0x48` dan masuk tcache bin yang sama.
2. Pilih slot 0 dan gunakan `show` untuk memperoleh pointer species, lalu hitung PIE base.
3. Ubah species pointer dan gunakan `visit` untuk leak pointer slot 0 di `kennels` serta pointer libc dari GOT.
4. Release slot 1 lalu slot 0. Dua entry tcache diperlukan agar counter bin tetap memungkinkan malloc kedua mengambil poisoned entry.
5. Dengan UAF `revise`, tulis `target ^ (chunk >> 12)` sebagai safe-linked tcache forward pointer.
6. Target berada di `commands + 0x90`, yaitu awal entry `cook` pada `commands+0xb0`; target dikembalikan sebagai pointer malloc yang aligned.
7. Alokasi slot 0 mengambil chunk asli dan alokasi slot 1 mengambil target command table. Ukuran minimum `0x48` membuat memset object berhenti sebelum global stdio di `.bss`.
8. Pilih slot 1 dan revisi object target. Tulis ulang nama `cook` pada offset 0 dan alamat `system` pada offset `0x10`, yaitu field handler.
9. Kirim `cook sh`, kemudian command `cat ./thisisratratratrat_puipui.txt` dibaca oleh shell.

## Exploit Final

`solve.py` menghitung semua base address dari leak runtime. Mode yang tersedia:

```bash
python3 solve.py
python3 solve.py GDB
python3 solve.py REMOTE HOST=chal.thjcc.org PORT=1024
```

Output penting saat remote berhasil:

```text
PIE base: 0x701f7b7d6000
heap chunk: 0x555574e3e2a0
libc base: 0x701f7b5c2000
command output: ... THJCC{Tell_me,_Linguini,_about_your_interests...D0_u_1ik3_anima1s?The_u5ua1,_d0gs,_cats,_h0r535,_guinea_pigs...RATS~~}
```

## Catatan Stabilitas

Exploit tidak memakai alamat ASLR hardcoded. Safe-linking dihitung dari pointer chunk yang bocor. Dua chunk tcache dengan ukuran sama wajib dipertahankan; satu chunk saja membuat libc challenge mengabaikan entry kedua karena counter tcache tidak konsisten.
