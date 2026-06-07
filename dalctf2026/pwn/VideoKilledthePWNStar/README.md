# Video Killed the PWN Star

Challenge ini kelihatannya seperti web upload biasa untuk membaca metadata video, tapi inti bug-nya ada di binary `video_processor`.

## Ringkasan bug

Di `parse_uuid_raw()` ada stack buffer `uuid_buffer[256]`. Program membaca box `uuid` dari file MP4, lalu kalau UUID-nya cocok dengan `TARGET_UUID`, ukuran data dihitung dari field ukuran box:

```c
uint32_t data_len = box_size - 24;
fread(uuid_buffer, 1, data_len, fp);
```

Tidak ada pengecekan bahwa `data_len <= 256`, jadi isi box `uuid` bisa menimpa saved `rbp` dan saved `rip`.

## Recon

`checksec` memberi hasil penting berikut:

- PIE enabled
- No canary
- GNU_STACK RWE, jadi stack executable
- IBT dan SHSTK terpasang di note ELF

Offset hasil cyclic:

- saved `rbp`: 272 byte
- saved `rip`: 280 byte

## Analisis exploit

Setelah `fread()` overflow selesai, jalur sukses fungsi masih melakukan:

```asm
1474: lea -0x110(%rbp), %rax
...
151e: leave
151f: ret
```

Artinya sebelum `ret`, register `rax` masih menunjuk ke `uuid_buffer`, yaitu buffer kita di stack. Karena stack executable, cara paling murah adalah mengarahkan return ke gadget `call rax` di binary. Dengan begitu shellcode di `uuid_buffer` langsung dijalankan.

Masalahnya ada dua:

1. Binary pakai PIE, jadi alamat absolut gadget berubah.
2. Kita hanya menimpa 2 byte terendah dari saved `rip`, sehingga kita bergantung pada 4 bit acak dari base PIE.

Offset gadget yang dipakai adalah:

- `call rax` di `0x1014`

Karena page alignment PIE berbentuk `...000`, 2 byte terendah gadget yang mungkin hanyalah:

- `0x1014`
- `0x2014`
- `0x3014`
- ...
- `0xf014`
- `0x0014`

Total cuma 16 kemungkinan. Satu request remote bisa gagal kalau nibble PIE tidak cocok, jadi solver cukup brute-force 16 nilai ini berulang sampai satu request kena kombinasi yang benar.

## Kenapa shellcode perlu `endbr64`

Binary dibangun dengan IBT. Target indirect branch yang valid perlu diawali instruksi `endbr64`, jadi shellcode dimulai dengan opcode itu supaya `call rax` tidak langsung ditolak.

## Shellcode

Payload memakai `pwntools.shellcraft.cat('/flag.txt')` lalu `exit(0)`. Jadi kalau eksekusi berhasil, isi flag dikirim ke stdout proses, dan aplikasi web menampilkan stdout itu di tag `<pre>`.

## Alur solver

1. Siapkan MP4 valid berdurasi 6 detik.
2. Tempel box `uuid` dengan UUID target.
3. Isi data box dengan:
   - shellcode
   - padding sampai offset 272
   - dummy saved `rbp`
   - 2 byte partial overwrite saved `rip`
4. Upload berulang ke `/upload`.
5. Parse HTML response dan ambil string berbentuk `xxx{...}`.

## Menjalankan solver

Aktifkan environment lalu jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Kalau request pertama belum kena nibble PIE yang pas, script akan lanjut brute-force sampai flag muncul.

## Flag

```text
dalctf{s0rry_f0r_th3_d3c3pt10n}
```
