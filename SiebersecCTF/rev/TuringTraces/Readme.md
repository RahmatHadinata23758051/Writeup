# Turing Traces

Binary ini punya tiga stage terenkripsi di `.text`. `main()` nge-`fork()`, child jalan sampai `int3`, lalu parent pakai `ptrace(PTRACE_PEEKDATA/POKEDATA)` buat decrypt blob stage di memori child sebelum dieksekusi.

Stage pertama buka `license.key`, baca string hex, lalu parse dengan `strtoull(..., 16)` ke global `0x405100`.

Stage kedua bikin nilai turunan:

```c
v = license ^ 0xbdd640fb06671ad1;
v *= 0x1c80317fa3b1799d;
v = rol(v, 17);
v ^= 0x3eb13b9046685257;
```

Hasilnya disimpan ke `0x405108` dan dibandingkan di stage ketiga dengan konstanta `0xcc4a46bf3e0e326c`.

Karena perkalian dilakukan modulo `2^64` dengan konstanta ganjil, operasi itu invertible. Balik persamaannya:

```text
license = ror((target ^ 0x3eb13b9046685257), 17) * inv(0x1c80317fa3b1799d) ^ 0xbdd640fb06671ad1
license = 0x23b8c1e9392456de
```

Kalau license benar, stage ketiga generate output 64 byte pakai PRNG model `splitmix64`, lalu XOR dengan data di `.rodata`. Hasil stringnya:

```text
sctf{funding_for_this_program_was_made_possible_by_by_by_by_by}
```

## Langkah singkat

1. Decrypt stage offline dengan ngereplikasi AES-CTR yang dipakai `decrypt_stage`.
2. Disassemble plaintext stage dan baca logic validasi.
3. Invers operasi 64-bit di stage dua buat dapat license valid.
4. Jalankan binary pakai `license.key` itu untuk keluarin flag.

## Run

```bash
python3 solve.py
```

Output:

```text
=== Turing Traces Product Activation Tool ===
Activation complete: sctf{funding_for_this_program_was_made_possible_by_by_by_by_by}

[+] license.key = 23b8c1e9392456de
[+] flag = sctf{funding_for_this_program_was_made_possible_by_by_by_by_by}
```
