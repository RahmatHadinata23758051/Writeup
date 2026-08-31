# Arena Snapshots

## Ringkasan

Bug ada di mekanisme `ROLLBACK`. Saat `SNAP`, program menyimpan metadata slot dan data payload. Saat `ROLLBACK`, program hanya mengembalikan metadata slot, free list, generation, dan epoch. Payload slot tidak dikembalikan. Akibatnya, payload baru dapat tetap tinggal di slot lama, tetapi metadata slot kembali ke tipe lama.

Primitive yang dipakai:

- metadata confusion setelah rollback;
- handle forging karena format handle hanya XOR dengan konstanta tetap `0xf4a77a8e77fb3a2c`;
- leak payload job valid dengan membuat payload job berada di bawah metadata buffer;
- recover secret integrity job dari signature job valid;
- forge payload job bertipe shell dengan path `/bin/sh`;
- jalankan forged job untuk mendapatkan shell;
- baca flag dari memfd `as-flag` yang diwariskan ke shell.

## Proteksi Binary

Binary adalah ELF 64-bit PIE, dynamically linked, stripped. Stack NX aktif karena `GNU_STACK` hanya RW. Program memakai stack canary. RELRO tersedia melalui segmen `GNU_RELRO`.

## Analisis Program

Service memakai protokol teks:

```
BUF <hex>
VIEW <handle> <offset> <size>
PATCH <handle> <offset> <hex>
DROP <handle>
JOB <path>
SNAP
ROLLBACK
RUN <handle>
QUIT
```

Handle disusun dari field berikut lalu di-XOR dengan konstanta tetap:

```
(type << 56) | (epoch << 40) | (generation << 24) | index
```

Konstanta XOR:

```
0xf4a77a8e77fb3a2c
```

Tipe handle:

```
0x42 = buffer
0x4a = job
```

Karena handle tidak memakai MAC, handle baru bisa dibuat jika `epoch`, `generation`, dan `index` diketahui.

## Vulnerability

`SNAP` menyimpan status slot. Namun `ROLLBACK` tidak mengembalikan payload slot secara penuh. Efeknya:

1. Buat slot sebagai buffer.
2. Ambil snapshot.
3. Drop buffer.
4. Reuse slot yang sama sebagai job.
5. Rollback.
6. Slot kembali dianggap buffer, tetapi payload masih berisi job.

Kondisi sebaliknya juga bisa dibuat:

1. Buat slot sebagai job.
2. Ambil snapshot.
3. Drop job.
4. Reuse slot yang sama sebagai buffer berisi payload job palsu.
5. Rollback.
6. Slot kembali dianggap job, tetapi payload berasal dari buffer yang kita kontrol.

## Menentukan Primitive

Program memakai free list LIFO. Slot yang baru di-drop akan dipakai ulang oleh alokasi berikutnya. Ini membuat type confusion stabil.

Untuk leak secret, exploit membuat buffer, snapshot, drop, lalu membuat job di slot yang sama. Setelah rollback, metadata slot kembali menjadi buffer. Dengan forged buffer handle untuk epoch baru, `VIEW` dapat membaca payload job valid.

Payload job valid berisi:

```
+0x00 magic      = 0x415379b7
+0x04 kind       = 0x415347dc untuk job normal
+0x08 selector   = 0x1357
+0x0c path_len
+0x10 nonce
+0x18 sig64
+0x20 checksum32
+0x24 path
```

`sig64` memakai secret 64-bit dari context. Karena field job valid diketahui dan signature tersimpan dalam payload, secret dapat dipulihkan dengan membalik fungsi mix berbasis konstanta SplitMix64.

## Strategi Exploit

Setelah secret didapat, exploit membuat payload job palsu:

```
magic    = 0x415379b7
kind     = 0x4153b0d8
selector = 0x1357
path     = /bin/sh
```

`kind = 0x4153b0d8` mengaktifkan jalur shell di `RUN`. Payload dihitung ulang dengan `sig64` dan `checksum32` yang valid.

Payload ini dimasukkan sebagai buffer. Setelah rollback, metadata slot kembali menjadi job. Exploit lalu membuat handle job baru untuk epoch setelah rollback dan menjalankan `RUN`.

Shell yang muncul mewarisi memfd flag bernama `as-flag`. Program menduplikasi fd flag ke rentang 64 sampai 512 sebelum `execl`. Exploit membaca `/proc/self/fd/*` pada rentang tersebut dan mengambil fd yang nama link-nya mengandung `as-flag`.

## Cara Menjalankan

Lokal:

```bash
python3 solve.py LOCAL
```

Remote:

```bash
python3 solve.py REMOTE --host 91.107.187.160 --port 18123
```

Atau:

```bash
HOST=91.107.187.160 PORT=18123 python3 solve.py REMOTE
```

## Hasil

Lokal:

```
ASIS{local_fake_flag_for_testing}
```

Remote:

```
ASIS{SN4PSH07_SL33P_R0LB4CK_R3P347_b027d27dc0834f9f}
```

## Flag

```
ASIS{SN4PSH07_SL33P_R0LB4CK_R3P347_b027d27dc0834f9f}
```
