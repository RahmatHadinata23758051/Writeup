# try

Binary `chall.exe` itu PE64 Windows dengan checker custom. Jalur cepatnya bukan brute force, tapi bongkar verifier lalu balikkan transformasinya.

## Ringkas

- `main` baca input, strip newline, lalu panggil `0x4024d9` buat ambil seed anti-debug.
- Kalau program jalan normal, seed yang dipakai verifier adalah `0xa7`.
- Verifier utama ada di `0x402618`. Syarat lolosnya:
  - panjang input harus 22 byte
  - checker bytecode di `0x401fb8` harus return true
  - hash input dari `0x401c53` harus sama dengan target yang dibentuk `0x401d6f`

## Enumerasi

`strings` langsung nunjukin beberapa petunjuk:

- `sealed input verifier`
- `WhatSoundDoesACowMake`
- `abcdefghijklmnopqrstuvwxyzSLAIDPUH`

Yang penting justru bukan string itu, tapi alur fungsi:

- `0x402962` = `main`
- `0x4024d9` = seed anti-debug
- `0x402618` = wrapper verifikasi
- `0x401fb8` = checker utama
- `0x401c53` = hash input

## Seed

`0x4024d9` ngecek debugger dan timing. Return value normalnya `0xa7`. Value lain cuma dipakai kalau ketahuan debug atau timing-nya janggal.

Jadi solver cukup pakai seed `0xa7`.

## Bytecode verifier

Checker di `0x401fb8` baca stream byte dari tabel `.data` mulai `0x4043a8`. Byte mentahnya tidak dipakai langsung. Tiap byte didecode dulu:

```text
decoded = ror8(table[i] ^ mix32(i, seed), (i ^ seed) & 7)
```

Setelah didecode, stream itu ternyata bukan random. Polanya rapi:

- 22 blok awal selalu panjangnya 14 byte
- blok-blok ini mengisi satu karakter flag per indeks
- setelah itu ada beberapa blok pasangan sebagai consistency check
- bagian akhir cuma menghitung jumlah operasi dan membandingkan dengan `0x21`

22 blok awal punya pola tetap:

```text
5d xx 4b ii 71 xx 32 xx 18 rr 71 xx d4 yy
```

Arti praktisnya:

1. Ambil karakter pada indeks `ii`
2. XOR, tambah, rotate, XOR lagi
3. Hasil akhirnya dibandingkan dengan `yy`

Karena semua transformasinya reversible, tiap blok bisa langsung dibalik:

```text
ch = yy ^ xor2
ch = ror8(ch, rot)
ch = (ch - add2) & 0xff
ch ^= xor1
```

Jalankan ke 22 blok pertama, lalu taruh hasilnya ke indeks masing-masing.

## Hasil

Urutan indeks yang keluar dari verifier membentuk:

```text
v1t{n0_dump_just_pain}
```

Hash dari string itu juga cocok dengan target dari `0x401d6f`, dan binary nerima inputnya:

```text
[+] accepted
```

## Solver

Solver final ada di `solve.py`. Script itu:

- decode tabel verifier
- balikkan 22 blok constraint
- validasi hash akhir
- print flag

Jalankan:

```bash
python3 solve.py
```

Kalau mau sekalian ngetes ke binary:

```bash
python3 solve.py --check-binary
```

## Flag

```text
v1t{n0_dump_just_pain}
```
