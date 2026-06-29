# Finger Arithmetic — Reverse Engineering

## Ringkasan

Binary meminta key sepanjang 32 karakter. Pemeriksaan tidak membandingkan angka secara langsung, tetapi merender setiap nilai integer menjadi PNG berisi empat bentuk tangan lalu membandingkannya dengan PNG target yang ditanam di `.rodata`.

Flag:

```text
TBCTF{ju75u5_n_d34d_3nd5_4w417!}
```

## Triage

```bash
file 'chall(2)'
checksec --file='chall(2)'
nm -C 'chall(2)' | grep -E 'main|validate|compare_hand'
```

Binary berupa ELF 64-bit PIE, tidak stripped. Simbol yang paling relevan:

```text
main
validate_checksum_v2
compare_hand_png_i32
```

String prompt dan pesan hasil disimpan dalam bentuk XOR sederhana. Setelah didekode, alur `main` menjadi:

1. Baca input.
2. Pastikan panjangnya 32 byte.
3. Periksa empat byte pertama.
4. Pastikan karakter indeks ke-5 adalah `{`.
5. Jalankan `validate_checksum_v2`.
6. Cetak pesan sukses bila seluruh pemeriksaan lolos.

## Mekanisme gambar tangan

`compare_hand_png_i32()` menerima integer 32-bit, merender empat tangan ke kanvas 256×256, mengubahnya menjadi PNG, lalu membandingkannya dengan PNG referensi.

Setiap tangan merepresentasikan satu byte:

- tujuh posisi jari menyimpan bit 0–6;
- arah tangan menyimpan bit 7;
- warna, rotasi, dan pose tambahan diturunkan dari keseluruhan integer agar template sederhana sulit dipakai.

PNG target diekstrak dari `.rodata`. Nilainya dibaca dengan membuat dataset lokal dari renderer binary, mengklasifikasikan bentuk jari, lalu menguji kandidat teratas dengan render pixel-perfect. Kandidat benar menghasilkan PNG yang identik byte-per-byte dengan target tertanam.

Delapan integer target yang berhasil dipulihkan:

```text
t0 = 0x65657598
t1 = 0x100f0ede
t2 = 0x25662659
t3 = 0x41394806
t4 = 0xa09d7c39
t5 = 0x95f9120a
t6 = 0x9e7e2255
t7 = 0xe35f1564
```

## Membalik validasi

Input dibagi menjadi delapan word little-endian `u0` sampai `u7`. Fungsi validasi membentuk target berikut:

```text
t0 = u0 + 0x11223344
t1 = u1 ^ t0
t2 = u2 - t1
t3 = u3 ^ t2
t4 = u4 + t3
t5 = u5 ^ t4
t6 = u6 - t5
t7 = u7 ^ t6
```

Semua operasi memakai aritmetika 32-bit. Persamaan dibalik menjadi:

```text
u0 = t0 - 0x11223344
u1 = t1 ^ t0
u2 = t2 + t1
u3 = t3 ^ t2
u4 = t4 - t3
u5 = t5 ^ t4
u6 = t6 + t5
u7 = t7 ^ t6
```

Hasil per chunk:

```text
u0 = TBCT
u1 = F{ju
u2 = 75u5
u3 = _n_d
u4 = 34d_
u5 = 3nd5
u6 = _4w4
u7 = 17!}
```

Gabung seluruh chunk:

```text
TBCTF{ju75u5_n_d34d_3nd5_4w417!}
```

## Solver

```bash
python3 solve.py
```

Output:

```text
TBCTF{ju75u5_n_d34d_3nd5_4w417!}
[+] Local validation passed
```

Validasi manual:

```bash
printf '%s\n' 'TBCTF{ju75u5_n_d34d_3nd5_4w417!}' | './chall(2)'
```

```text
Enter the flag: Correct! The flag is the input you entered.
```
