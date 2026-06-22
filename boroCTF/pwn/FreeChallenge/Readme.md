# Free Challenge

Binary ini punya bug use-after-free yang bersih banget.

`close_report()` cuma `free(report)` lalu pointer global `report` tetap dipakai. Setelah itu `edit_report()` masih jalan, jadi kita bisa baca dan nulis isi chunk yang sudah di-free.

## Recon

`checksec`:

```text
Arch: amd64
RELRO: Partial RELRO
Canary: found
NX: enabled
PIE: No PIE
```

Source yang penting:

```c
void close_report() {
  if (report == NULL) return;
  free(report);
  puts("Closed report!");
}
```

`report` dangling. Itu primitive utamanya.

## Bug

Struct:

```c
typedef struct report {
  char title[8];
  char* file_data;
  uint32_t size;
} report_t;
```

Alur eksploitasi:

1. Buat report dengan `size = 0x280`.
2. `close_report()` untuk free chunk `report`.
3. Panggil `edit_report()` lagi ke chunk yang sudah free.
4. Karena chunk itu sekarang dipakai `tcache_perthread_struct`, input kita masuk ke metadata tcache.

Di glibc challenge ini, entry tcache untuk size class `0x30` ada di offset `0x80`. Kita overwrite `entries[0x30]` ke alamat yang kita mau.

## Kenapa leak flag bisa langsung

Global `target` ada di `.data`:

- `target` di `0x404090`
- `target.file_data` di `0x404098`

Binary tidak PIE, jadi alamat global tetap. Langkah pertama adalah leak isi `target.file_data`, karena field itu sendiri menyimpan pointer ke buffer yang berisi flag.

Kalau `entries[0x30]` kita poison ke `target.file_data`, lalu pilih menu `make_report()`, `malloc(sizeof(report_t))` akan return alamat field pointer tersebut. `edit_report()` bakal nge-print isi pointer itu sebagai title, jadi kita dapat alamat buffer flag dulu.

Setelah pointer buffer ketemu, poison lagi ke `flag_buf + n`. Dari sana `edit_report()` langsung nge-print 8 byte pertama chunk hasil alokasi sebagai title:

```c
printf("'%s' currently has: '", report->title);
```

Karena alokasi dimulai tepat di buffer flag, title berisi potongan flag 8 byte per koneksi.

Dump per 8 byte:

```text
0x00 -> b'boroCTF{'
0x08 -> b'free_you'
0x10 -> b'rself_in'
0x18 -> b'to_tcach'
0x20 -> b'e}\n'
```

Gabungin hasilnya:

```text
boroCTF{free_yourself_into_tcache}
```

## Exploit

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE=1
```

Output:

```text
boroCTF{free_yourself_into_tcache}
```
