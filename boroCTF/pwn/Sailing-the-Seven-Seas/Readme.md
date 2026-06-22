# Sailing the Seven Seas

Binary ini ngasih empat aksi ke array `fleet[10]`: allocate, free, show, dan edit. Bug utamanya ada di opsi `2` dan `4`.

- `free(fleet[index])` dipanggil tapi pointer-nya tidak pernah di-`NULL`.
- Chunk yang sudah di-`free` masih bisa di-`show` dan di-`edit`.

Itu cukup buat dua primitive:

- leak libc dari unsorted bin
- tcache poisoning ke `__free_hook`

## Recon

`checksec`:

- Arch: amd64
- Full RELRO
- NX enabled
- PIE enabled
- No canary

Libc yang dibundel challenge adalah `sinbad.so.6`, versi `glibc 2.31`. Ini penting karena tcache di 2.31 belum pakai safe-linking.

## Bug

Potongan yang relevan:

```c
free(fleet[index]);
```

Pointer `fleet[index]` dibiarkan dangling. Setelah itu program masih mengizinkan:

```c
printf("Inspection Results: %s\n\n", fleet[index]);
read(0, fleet[index], SHIP_SIZE);
```

Jadi ada use-after-free read dan write.

## Leak libc

Ukuran chunk selalu `0x88`, jadi masuk ke tcache bin yang sama.

Langkah leak:

1. Alokasikan 9 chunk.
2. `free` 7 chunk pertama buat memenuhi tcache.
3. `free` chunk ke-8. Karena tcache penuh dan masih ada satu chunk di belakangnya, chunk ini masuk ke unsorted bin.
4. `show` chunk tersebut. Isi awal user data sekarang adalah pointer `fd` unsorted bin, yang menunjuk ke `main_arena`.

Leak yang dipakai:

```python
libc.address = leak - 0x1ECBE0
```

Offset `0x1ecbe0` adalah `main_arena+96` untuk libc challenge ini.

## Tcache poisoning

Karena glibc 2.31 belum ada safe-linking, forward pointer tcache bisa ditulis mentah.

Langkahnya:

1. Pilih satu chunk yang sudah ada di tcache, lalu `edit` chunk freed itu.
2. Tulis `__free_hook` ke field `fd`.
3. `malloc` sekali untuk pop chunk asli dari tcache.
4. `malloc` kedua mengembalikan pointer ke `__free_hook`.
5. Tulis alamat `system` ke sana.

Payload terakhir bukan `/bin/sh`, tapi string command langsung:

```sh
cat flag* 2>/dev/null || cat /flag 2>/dev/null
```

Setelah `__free_hook = system`, `free(chunk_berisi_command)` akan berubah jadi:

```c
system("cat flag* 2>/dev/null || cat /flag 2>/dev/null");
```

## Exploit

Solver final ada di [solve.py](/home/nata/ctf/boroCTF/pwn/Sailing-the-Seven-Seas/solve.py).

Jalankan remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE
```

Output penting:

```text
[*] libc leak   = 0x7ffff7fb5be0
[*] libc base   = 0x7ffff7dc9000
[*] __free_hook = 0x7ffff7fb7e48
[*] system      = 0x7ffff7e1b290
boroCTF{Sp1a5h#_w!th_Tcache3}
```

## Flag

`boroCTF{Sp1a5h#_w!th_Tcache3}`
