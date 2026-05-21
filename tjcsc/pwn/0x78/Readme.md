# Writeup pwn/Ox78

Challenge ini kelihatannya sederhana, tapi sebenarnya jebakannya ada di detail perilaku `FILE` glibc. Binarinya sengaja memberi kita pointer `FILE *` dan leak libc, lalu berharap fungsi `prevent_fsop()` cukup untuk mematikan serangan FSOP. Ternyata tidak.

## Recon

Binary adalah ELF 64-bit PIE dengan:

- Full RELRO
- NX
- No canary
- libc custom disediakan

Program melakukan hal berikut:

1. `malloc(0x78)` ke `testbuf`
2. `fopen("/tmp/test.txt", "r")` ke global `fp`
3. leak alamat `fp`
4. leak alamat `puts`
5. `read(0, fp, 0x78)` sehingga 0x78 byte awal dari `FILE` bisa kita overwrite
6. panggil `prevent_fsop(fp)`
7. `fread(testbuf, 1, 0x78, fp)`
8. panggil `prevent_fsop(fp)` lagi

Inti bug-nya jelas: kita bisa menulis langsung ke struktur `FILE` di heap sebelum `fread()` dipakai.

## Kenapa `prevent_fsop()` gagal

Fungsi itu hanya menyentuh sangat sedikit field:

- membaca `fp->_wide_data`
- membaca `fp->_wide_data->_wide_vtable`
- mengosongkan `fp->_chain`

Dia tidak memvalidasi vtable, tidak mengunci mode stream, dan tidak menghentikan manipulasi field penting lain. Jadi selama layout yang kita kirim masih cukup valid untuk dilewati `fread()`, eksekusi berikutnya tetap bisa diarahkan.

## Primitive pertama: arbitrary write

Dengan overwrite 0x78 byte pertama `FILE`, saya ubah field buffer read milik stream sehingga `fread()` berikutnya melakukan `read(0, target, size)` ke alamat yang saya pilih sendiri.

Field penting yang dipakai:

- `_flags`
- `_IO_buf_base`
- `_IO_buf_end`
- `_fileno = 0`

Setelah dicoba, target yang aman bukan `fp` dari awal struct, karena itu membuat `fread()` meledak terlalu cepat. Yang stabil adalah mulai menulis dari tail struct, tepatnya dari `fp + 0xa0`.

## Primitive kedua: FSOP lewat `_IO_wfile_overflow`

Langkah berikutnya adalah memaksa cleanup path glibc memanggil helper wide-file:

- stage 1 mengatur `_flags = 0xfbad8000`
- stage 2 menaruh:
  - `_mode = 1`
  - `vtable = _IO_wfile_jumps`
  - fake `_wide_data`
  - fake wide vtable

Saat proses `exit()`, glibc masuk ke `_IO_wfile_overflow()`, lalu ke `_IO_wdoallocbuf()`. Di sana ada call penting ini:

```c
call [wide_vtable + 0x68]
```

Jadi begitu `_wide_data->_wide_vtable` bisa kita arahkan, kita dapat indirect call yang rapi.

## Kenapa `setcontext` dipakai

Tujuan saya bukan shell interaktif panjang, tapi eksekusi satu command yang pasti mencetak flag. Untuk itu saya pakai `setcontext` agar bisa pivot stack ke heap dan langsung menjalankan ROP kecil:

1. `pop rdi; ret`
2. pointer ke command string
3. `ret`
4. `system`

Awalnya saya mencoba fake stack terlalu dekat ke `FILE`, hasilnya `system()` sempat jalan tapi crash sebelum selesai karena ruang stack-nya terlalu sempit. Solusinya adalah menaruh fake stack lebih jauh di arena heap:

- `wide = fp + 0x1000`
- `fpuenv = fp + 0x1100`
- `fakevt = fp + 0x1380`
- command string = `fp + 0x1500`

Setelah digeser sejauh itu, `system()` bisa menyelesaikan command dengan stabil walaupun proses utama tetap SIGSEGV setelah return. Itu tidak masalah, karena output flag sudah keluar duluan.

## Strategi final

Command yang saya jalankan dulu di remote adalah:

```sh
find / -maxdepth 4 -iname "*flag*" -type f 2>/dev/null | head -n 50
```

Hasilnya menunjukkan path flag:

```text
/app/flag.txt
```

Lalu saya ganti command final menjadi:

```sh
cat /app/flag.txt
```

dan proses mencetak flag dengan sukses.

## Payload final

Payload akhir dipecah jadi dua tahap:

1. overwrite 0x78 byte awal `FILE` untuk membentuk arbitrary write
2. overwrite tail `FILE` untuk memasang:
   - fake `_wide_data`
   - fake wide vtable
   - fake stack
   - command string
   - callback ke `setcontext`

Implementasi final ada di `exploit.py`.

## Catatan penting

- Leak `puts` dipakai untuk hitung base libc
- Leak `fp` dipakai untuk hitung semua alamat fake structure
- Exploit tidak butuh interactive shell; cukup one-shot `system("cat /app/flag.txt")`
- SIGSEGV setelah command selesai itu normal untuk solusi ini

## Flag

```text
tjctf{d0uBl3_FSoP_1s_fUN_29391}
```
