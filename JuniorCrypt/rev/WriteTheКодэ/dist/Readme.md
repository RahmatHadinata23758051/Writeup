# Write The "Кодэ"

Kategori: Reverse  
Flag: `grodno{Fabrice_Bellard_is_a_really_cool_programmer}`

Source `checker.c` kelihatan polos: baca input, lalu panggil fungsi eksternal `audit(answer)`. Fungsi `audit` tidak ada di source maupun `runtime/libtcc1.a`, jadi bagian pentingnya ada di compiler `tcc` yang sudah dimodifikasi.

Compile sesuai instruksi:

```bash
./tcc -B./runtime checker.c -o checker
```

Binary hasil compile punya kode tambahan setelah `main`. Call ke `audit` diarahkan ke fungsi internal di sekitar `0x402296`. Fungsi ini:

- menghitung seed dari `/proc/self/exe`, tepatnya section ELF bertipe `SHT_RELA`;
- decrypt blob 0x200 byte di `.data + 4`;
- menjalankan VM kecil hasil decrypt;
- VM mengecek input byte-per-byte dengan checksum 32-bit.

Seed dihitung dari relocation entries:

```c
state = 0x6a09e667f3bcc909;
state ^= r_info + 0x9e3779b97f4a7c15 + (section_index << 32) + entry_index;
state = rol64(state, 17) * 0xbf58476d1ce4e5b9;
state ^= r_addend;
```

Blob `.data` didecrypt memakai xorshift64* dan byte paling atas dari output RNG:

```c
state ^= state >> 12;
state ^= state << 25;
state ^= state >> 27;
keystream = (state * 0x2545f4914f6cdd1d) >> 56;
plain[i] = encrypted[i] ^ keystream;
```

Bytecode VM dimulai dengan:

- 2 byte panjang flag;
- magic `0x51`;
- lalu record 7 byte per karakter: opcode `0xa7`, konstanta add, rotasi, expected checksum.

Update checksum per karakter:

```c
checksum ^= input[i] + add_key;
checksum = rol32(checksum, rotate);
checksum += (i * 0x45d9f3b) ^ 0x9e3779b9;
checksum == expected;
```

Karena setiap step hanya bergantung pada checksum sebelumnya dan satu byte input, cukup brute force 1..255 untuk tiap posisi. Solver final ada di `solve.py`.

```bash
$ python3 solve.py
grodno{Fabrice_Bellard_is_a_really_cool_programmer}
```
