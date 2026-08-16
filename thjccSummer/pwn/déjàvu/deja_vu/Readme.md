# déjà vu

## Ringkasan

Challenge PWN ini memiliki dangling pointer pada channel message. Refcount message hanya disimpan dalam satu byte, sehingga subscribe ke 256 channel membuat refcount wraparound ke nol. Setelah slot di-discard, pointer pada channel masih tersisa dan bisa dipakai sebagai UAF.

UAF dipakai untuk mendapatkan leak libc, leak stack melalui `environ`, arbitrary read, lalu arbitrary write ke saved RIP. Payload final menjalankan ROP syscall `openat`, `read`, dan `write` untuk membaca flag.

## Proteksi Binary

Hasil pemeriksaan binary:

```text
Architecture: amd64
Linking:      dynamically linked
PIE:          enabled
RELRO:        Full RELRO
Canary:       enabled
NX:           enabled
CET:          SHSTK dan IBT aktif
Symbols:      stripped
libc:         Ubuntu GLIBC 2.35
```

Binary dijalankan memakai loader dan libc yang disediakan:

```bash
./ld-linux-x86-64.so.2 --library-path . ./deja_vu
```

## Analisis Program

Message memiliki field penting berikut:

```text
message +0x20 : pointer body
message +0x28 : panjang body
message +0x30 : refcount satu byte
```

Saat subscribe, refcount dinaikkan dengan operasi byte. Tidak ada pengecekan overflow:

```text
refcount = 0xff
subscribe sekali lagi
refcount = 0x00
```

Ketika slot di-discard, program membebaskan body dan object message karena mengira refcount sudah nol. Pointer yang tersimpan pada channel tidak dibersihkan. Channel tersebut kemudian menjadi dangling pointer.

## Mendapatkan Leak libc

Pesan dengan body `0x500` byte dibuat dan disubscribe ke channel `0..255`. Setelah discard, body masuk ke unsorted bin, tetapi channel 0 masih menunjuk ke chunk yang sudah dibebaskan.

Replay channel 0 menghasilkan pointer unsorted-bin pada delapan byte pertama. Untuk libc yang disediakan, perhitungannya:

```text
libc_base = unsorted_fd - 0x21ace0
```

Leak ini divalidasi dengan memastikan base address page-aligned.

## Leak Stack melalui environ

Chunk object message yang sudah dibebaskan direclaim dengan compose message berukuran `0x30`. Body-nya diisi sebagai fake message:

```text
fake +0x20 = libc.sym['environ']
fake +0x28 = 8
```

Replay channel stale kemudian membaca isi `environ`, yaitu pointer ke area stack.

## Arbitrary Read dan Write

UAF kedua dibuat dengan cara yang sama memakai channel `256..511`. Fake message kedua diarahkan ke area stack.

Pada binary lokal, saved RIP berada di:

```text
environ - 0x1a8
```

Pada service remote, frame stack berbeda dan saved RIP berada di:

```text
environ - 0x180
```

Karena itu `solve.py` otomatis memakai offset `0x1a8` untuk lokal dan `0x180` untuk remote, serta bisa dioverride dengan argument `OFFSET`.

Payload amend kemudian menulis ROP chain ke saved RIP. Gadget yang dipakai berasal dari libc:

```text
pop rdi ; ret
pop rsi ; ret
pop rdx ; pop r12 ; ret
pop rax ; ret
syscall ; ret
```

## ROP ORW

ROP chain final melakukan:

```text
close(3..9)
fd = openat(AT_FDCWD, path, O_RDONLY, 0)
read(fd, buffer, 0x400)
write(1, buffer, 0x400)
exit(0)
```

Menutup descriptor 3 sampai 9 lebih dulu memastikan hasil `openat` menjadi fd 3 pada service remote.

Service remote menjalankan proses dari `/home/ctf/deja_vu`. Path flag yang dipakai solver remote adalah `/flag.txt` sesuai deployment challenge.

## Exploit Final

Semua tahapan sudah diimplementasikan pada [solve.py](solve.py). Solver mendukung mode lokal, GDB, dan remote.

Jalankan lokal:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Jalankan remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE
```

Output remote menghasilkan flag langsung dari service:

```text
THJCC{s0_wh1ch_AI_d1d_y0u_us3_t0_s0lv3_th1s???}
```

## Catatan Stabilitas

- Leak unsorted bin digunakan untuk menghitung libc base secara dinamis.
- Alamat gadget tidak di-hardcode; alamat dihitung dari libc base hasil leak.
- Offset saved RIP berbeda antara proses lokal dan remote, sehingga solver menyediakan `OFFSET` override.
- Binary remote memakai seccomp. `openat`, `read`, dan `write` tetap tersedia, sehingga flag dibaca langsung tanpa shell.
- `flag.txt` lokal hanya dummy untuk pengujian dan bukan flag remote.

## Flag

```text
THJCC{s0_wh1ch_AI_d1d_y0u_us3_t0_s0lv3_th1s???}
```
