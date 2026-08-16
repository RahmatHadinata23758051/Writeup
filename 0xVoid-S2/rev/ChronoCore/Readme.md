# ChronoCore

## Ringkasan

Binary `chronocore` menerima input flag dengan format:

```
0xV01D{...}
```

Validasi utamanya ada di fungsi sekitar `0x1390`. Program tidak menyimpan flag sebagai string utuh. Byte input diproses memakai state rolling, rotasi bit, konstanta hardcoded, dan urutan indeks yang dipermutasi. Dengan meniru state machine itu, flag bisa direcover dari belakang/constraint per byte.

Flag:

```
0xV01D{vm_tr4c3s_l13_but_st4t3_t3lls}
```

## File Challenge

Isi archive:

```
README.md
chronocore
```

Hasil identifikasi:

```bash
file chronocore
```

Output penting:

```
chronocore: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Binary stripped, jadi nama fungsi asli tidak tersedia.

## Analisis Awal

`strings` menunjukkan beberapa string yang berguna:

```
chronocore>
0xV01D{
rejected
accepted
```

Dari sini kelihatan program punya prompt, prefix flag, dan output sukses/gagal. Flag lengkap tidak muncul di `strings`, jadi perlu reverse fungsi validasinya.

Program bisa menerima input dari argv atau stdin:

```bash
./chronocore '0xV01D{test}'
```

Outputnya:

```
rejected
```

## Analisis Static

Bagian awal `main` melakukan validasi format dasar:

```asm
call strlen
cmp  rax, 0x25
jne  rejected

memcmp(input, "0xV01D{", 7)
cmp byte [rsp+0x24], 0x7d
```

Artinya panjang input harus `0x25` atau 37 byte.

Struktur format:

```
0xV01D{ + isi 29 byte + }
```

Setelah format cocok, program memanggil fungsi validasi di sekitar alamat `0x1390`.

## Analisis Fungsi Validasi

Di `.rodata` ada beberapa array hardcoded:

```
0x2040 -> TARGET
0x2080 -> ROT
0x20c0 -> MASK
0x2100 -> ADD
0x2140 -> PERM
```

Array `PERM` berisi urutan posisi input yang dicek:

```
02 1a 14 1d 23 05 01 1c 04 0b 0f 0d 19 0c 21 18
08 1b 16 24 11 03 1e 20 15 12 13 0e 00 07 0a 09
10 1f 06 22 17
```

Jadi byte input tidak dicek dari kiri ke kanan. Program mengambil byte dari posisi `PERM[i]`, lalu mengolahnya dengan state sebelumnya.

Operasi penting per byte:

```c
c = input[PERM[i]];
edi = ADD[i] + c + 17*i;
edi ^= eax;
eax = rol32(edi, ROT[i]);
eax = eax * 0x45d9f3b;
eax = eax + i + 0x27100001;

shift = (i & 3) * 8;
ecx = (eax >> shift) + c;
cl ^= MASK[i];
ecx ^= r10;

if ((ecx & 0xff) != TARGET[i]) reject;
r10 = c + i + ecx;
```

State awal:

```
eax = 0x9e3779b9
r10 = 0x42
```

Karena setiap step hanya butuh satu byte baru sesuai `PERM[i]`, kita bisa brute force byte printable pada posisi tersebut, update state, lalu lanjut ke step berikutnya.

## Penyusunan Solve Script

`solve.py` menyalin konstanta dari `.rodata`, lalu mengemulasi state machine. Prefix `0xV01D{` dan suffix `}` dipasang sebagai byte yang sudah diketahui.

Search dilakukan sesuai urutan `PERM`, bukan urutan normal string. Untuk setiap posisi, solver mencoba karakter printable sampai state menghasilkan byte `TARGET[i]`.

Ada collision printable kecil karena validasi hanya membandingkan low byte (`cl`). Binary lokal menerima lebih dari satu kandidat. Kandidat yang readable dan sesuai pesan challenge adalah:

```
0xV01D{vm_tr4c3s_l13_but_st4t3_t3lls}
```

## Cara Menjalankan

```bash
chmod +x solve.py
python3 solve.py
```

Output:

```
0xV01D{vm_tr4c3s_l13_but_st4t3_t3lls}
accepted
```

Validasi manual:

```bash
./chronocore '0xV01D{vm_tr4c3s_l13_but_st4t3_t3lls}'
```

Output:

```
accepted
```

## Flag

```
0xV01D{vm_tr4c3s_l13_but_st4t3_t3lls}
```

