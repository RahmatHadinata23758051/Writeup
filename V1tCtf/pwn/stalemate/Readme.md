# StaleMate

## Info

- Category: Pwn
- Binary: `pbuf_remap`
- Protections: Full RELRO, Canary, NX, PIE
- Target: `nc pwn.v1t.site 31337`

## Ringkasannya

Bug utamanya ada di alur `IORING_REGISTER_PBUF_RING -> mmap pbuf ring -> IORING_UNREGISTER_PBUF_RING`.

Page pbuf yang sudah di-`unregister` dibalikin ke allocator, tapi mapping userland untuk page itu masih dianggap valid. Jadi page yang sama bisa dipakai ulang untuk objek lain, sementara menu `io_uring_buf_ring_add` dan `inspect mapped ring entry` masih bisa baca/tulis lewat mapping lama.

Primitive itu cukup buat:

1. Melepas 2 page pbuf.
2. Memaksa allocator ngasih 2 page itu lagi ke `create mm context`.
3. Dapat stale write ke page table VM yang baru dibuat.
4. Remap slot VM ke page fisik mana pun.
5. Cari page `cred`, nolkan field uid/gid, set capability mask ke `-1`.
6. Panggil `open flag`.

## Recon

`checksec`:

```text
Full RELRO | Canary found | NX enabled | PIE enabled
```

String menu langsung ngasih operasi penting:

```text
1. IORING_REGISTER_PBUF_RING
2. mmap pbuf ring
3. IORING_UNREGISTER_PBUF_RING
4. io_uring_buf_ring_add
5. inspect mapped ring entry
6. create mm context
7. vm alloc user page
8. vm read
9. vm write
10. open flag
```

`open flag` ngecek struktur credential di sebuah page yang diawali string `CREDv1`. Field yang dicek:

- qword `+0x08` harus `0`
- qword `+0x10` harus `0`
- qword `+0x18` harus `-1`
- qword `+0x20` harus tetap cocok dengan hash internal

Hash itu cuma diverifikasi, bukan dihitung dari uid/gid. Jadi cukup ubah field `+0x08..+0x1f` dan biarin hash tetap.

## Analisis Bug

### 1. Stale pbuf mapping

`IORING_REGISTER_PBUF_RING` bikin region pbuf di allocator internal.

`mmap pbuf ring` nyimpen metadata mapping ke tabel map terpisah.

`IORING_UNREGISTER_PBUF_RING` ngebebasin page pbuf ke buddy allocator, tapi entri map yang dibuat oleh `mmap pbuf ring` tidak dihapus. Akibatnya:

- `inspect mapped ring entry` masih bisa leak isi page yang sudah dipakai ulang.
- `io_uring_buf_ring_add` masih bisa nulis 16 byte per entry ke page yang sudah dipakai ulang.

### 2. Reuse page jadi objek MM

Kalau register pbuf dengan `entries=512`, ukuran ring jadi `512 * 16 = 0x2000`, alias 2 page.

Setelah di-`unregister`, 2 page ini direalokasi saat `create mm context`:

- satu page jadi page table VM
- satu page jadi scratch page yang dipetakan di slot virtual 7

Leak lokal nunjukin pola ini dengan jelas:

```text
idx 3   -> encoded PTE di offset 0x38
idx 256 -> "SLOT7_MAGIC:pbuf"
```

Jadi stale mapping order-1 tadi sekarang mengarah ke:

- page 0: pgtable
- page 1: scratch

### 3. Ambil kendali page table

`io_uring_buf_ring_add` nulis struktur 16 byte:

```c
struct io_uring_buf {
    u64 addr;
    u32 len;
    u16 bid;
    u16 resv;
};
```

Karena stale map sekarang menunjuk ke page table, entry index `0` di map berarti offset `0x0` di pgtable. Itu pas buat overwrite 2 PTE pertama sekaligus.

PTE slot 7 yang valid bisa dileak dari `inspect mapped ring entry` index `3`, karena PTE itu berada di offset `0x38`.

Trik yang dipakai:

- Ambil encoded PTE slot 7 dari stale map.
- XOR dengan `(guess << 12)` lalu tulis ke slot 0.
- Efeknya slot 0 akan memetakan page fisik `(real_scratch_page xor guess)`.

Karena `guess` bisa 0..0x1ff, kita bisa jalanin semua 512 page fisik tanpa perlu tahu page index asli.

### 4. Cari page credential

Setelah slot 0 bisa diarahkan ke seluruh physical memory:

1. Tulis encoded PTE baru ke slot 0.
2. Pakai `vm read` di VA `0x0`.
3. Cari page yang diawali hex `4352454476310000`, alias `CREDv1`.

Begitu ketemu, slot 0 sudah memetakan page credential.

## Exploit

Payload akhirnya pendek:

1. Register ring 2 page.
2. `mmap` ring.
3. `unregister` ring.
4. `create mm context`.
5. Leak encoded PTE slot 7 dari stale map.
6. Brute-force `guess` sampai `vm read(0, 0, 8)` mulai dengan `CREDv1`.
7. `vm write` ke offset `0x8` dengan:

```text
00 * 16 + ff * 8
```

Itu mengubah:

- uid/gid block -> `0`
- capability block -> `0xffffffffffffffff`

8. Panggil `open flag`.

## Solver

File exploit final ada di:

- `solve.py`

Run lokal:

```bash
source /home/kali/tools/ctf/bin/activate
python3 solve.py LOCAL=1
```

Run remote:

```bash
source /home/kali/tools/ctf/bin/activate
python3 solve.py
```

Solver ini juga otomatis ngerjain Proof-of-Work dari service.

## Flag

```text
v1t{pfnmap_pbuf_pages_should_outlive_the_mmap}
```
