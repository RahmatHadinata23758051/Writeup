# Chronicle

## Ringkasan

Redis module menerima archive `CHRONICLE.IMPORT`. Validasi ukuran annotation memakai cast ke `uint8_t`, sehingga `body_length = 0x100` lolos pemeriksaan `<= 80`. `memcpy` kemudian menyalin 256 byte ke `note[80]` dan menimpa function pointer `completion`.

## Proteksi Binary

`chronicle.so` adalah ELF x86-64 shared object, dynamic, PIE, NX, Full RELRO, stack canary, IBT, dan SHSTK. Binary tidak stripped. Build remote Docker menghasilkan offset fungsi:

```text
commit_annotation  = 0x11b0
materialize_anchor = 0x1280
```

## Analisis Program

`ChronicleTask` menempatkan `note` pada offset `0x48` dan `completion` pada offset `0x98`, jadi function pointer berjarak 80 byte dari awal `note`. `CHRONICLE.NEW` membuat task NOTE dengan completion `commit_annotation` lalu mengembalikan `ticket`:

```c
ticket = (uintptr_t)task->completion ^ rotate_left(task->id * CONST, 17);
```

Ticket pada `CHRONICLE.SHOW` menjadi leak pointer setelah salt dibalik.

## Vulnerability

Pada import:

```c
if ((uint8_t)body_length > NOTE_CAPACITY) reject;
...
memcpy(task->note, cursor, (size_t)body_length);
```

Nilai `body_length=256` berubah menjadi nol saat cast untuk pengecekan, tetapi tetap bernilai 256 saat `memcpy`. Payload menulis 80 byte padding lalu alamat `materialize_anchor` ke `completion`.

## Strategi Exploit

1. Buat task NOTE dengan delay normal.
2. Baca ticket dan pulihkan alamat `commit_annotation`.
3. Hitung alamat `materialize_anchor` dengan delta `0x1280 - 0x11b0 = 0xd0`.
4. Buat archive valid dengan body 256 byte dan checksum FNV-1a yang benar.
5. Import archive. Timer memanggil `materialize_anchor`, yang menyalin isi `/tmp/.chronicle-anchor` ke `result`.
6. Tampilkan task hasil import.

## Exploit Final

Payload penting:

```python
body = b"A" * 80 + p64(materialize_anchor) + b"B" * (256 - 88)
```

`solve.py` menggunakan RESP binary-safe untuk `CHRONICLE.IMPORT`, sehingga byte nol dan byte non-printable pada alamat tetap dikirim utuh.

## Cara Menjalankan

Remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE HOST=chal.thjcc.org PORT=6379
```

Lokal, setelah Redis challenge berjalan di port 6379:

```bash
python3 solve.py
```

## Hasil

Exploit berhasil secara konsisten pada service remote. Flag muncul dari response `CHRONICLE.SHOW`:

```text
<FLAG>THJCC{D0_y0u_KN0W_7h15_15_@_PWN_ch@ll3nge_WH17CH_m4d3_BY_@1???}</FLAG>
```

## Catatan Stabilitas

Offset harus diambil dari build remote yang sama. `chronicle.so` yang tersedia di luar Docker dibangun dengan compiler berbeda dan memiliki offset fungsi berbeda; memakai `0x1300` untuk `materialize_anchor` membuat Redis crash setelah timer berjalan.
