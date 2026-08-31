# LeakMeAk Writeup

## Ringkasan

Binary menerima flag dengan format `ASIS{...}`. Bagian dalam flag panjangnya 28 byte dan diproses per 4 byte. Setiap 4 byte menghasilkan satu nilai `uint32`, lalu 7 nilai itu dicek memakai relasi berantai, hash kecil, dan beberapa validasi state.

Flag valid yang didapat:

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```

## File Challenge

File yang dianalisis:

```
leakmeak.elf
```

Hasil identifikasi:

```
ELF 64-bit LSB PIE executable, x86-64, dynamically linked, stripped
```

Binary stripped, jadi tidak ada simbol fungsi seperti `main` atau `check`.

## Analisis Awal

`strings` memperlihatkan string penting:

```
Enter Flag:
%127s
Access Denied!
ASIS{
Access Granted! Correct Flag.
```

Dari disassembly terlihat alur awal:

```
strlen(input) == 0x22
strncmp(input, "ASIS{", 5) == 0
input[33] == '}'
```

Jadi panjang flag total 34 byte:

```
ASIS{ + 28 byte payload + }
```

## Analisis Static

Payload 28 byte disalin ke stack lalu diproses sebagai 7 chunk, masing-masing 4 byte.

State awal yang dipakai program:

```
S = [5, 21, 10, 14, 0, 0, 0, 0]
C = [0, 0, 0, 0, 0, 0, 0, 0]
```

Untuk setiap chunk `a,b,c,d`, program:

1. Mengambil beberapa index dari low 3 bit `b`, `c`, dan `d`.
2. Mengambil nilai dari array state `S`.
3. Melakukan beberapa conflict check. Kalau gagal, bit pada `ecx` diset dan flag ditolak.
4. Mengupdate salah satu entry `S`.
5. Membuat nilai `D[i]`:

```
packed = (a << 24) | (b << 16) | (c << 8) | d
meta = (new << 24) ^ (val_c << 16) ^ (val_d << 8) ^ (b & 7)
D[i] = (packed * 0x9e3779b9) ^ meta
```

## Analisis Dynamic

Binary diuji lokal setelah payload kandidat ditemukan:

```
printf 'ASIS{haaducrcplmekhylrozcxyxzuizs}\n' | ./leakmeak.elf
```

Output:

```
Enter Flag: Access Granted! Correct Flag.
```

Ini membuktikan flag valid terhadap binary lokal.

## Algoritma Validasi atau Encoding

Setelah 7 nilai `D` dibuat, program mengecek relasi berantai memakai konstanta `.rodata`.

Konstanta target:

```
T = [
    0x449f4ab5, 0xbb5e7ac4, 0x91141f33, 0x9caafb86,
    0xd99258f7, 0x2abb0f38, 0x3ff226d0,
]
```

Konstanta XOR:

```
K = [
    0xa5a5a5a5, 0x5a5a5a5a, 0x3c3c3c3c, 0xc3c3c3c3,
    0x96969696, 0x69696969, 0x1f1f1f1f,
]
```

Relasi yang dicek:

```
T[i-1] == ((ror32(D[i % 7], 13) + D[i-1]) & 0xffffffff) ^ K[i-1]
```

Relasi ini bikin setiap `D` berikutnya bisa dihitung dari `D` sebelumnya. Solver cukup brute force chunk pertama dari charset flag, turunkan semua `D`, lalu cari chunk berikutnya yang menghasilkan target `D` tersebut.

Final hash:

```
edx = 0
for v in D:
    edx = (edx * 0x21) ^ v

# edx harus 0xddaacf25
# transform 64 ronde dari edx harus 0x376a3d36
```

## Penyusunan Solve Script

`solve.py` mengemulasikan satu iterasi validasi dari binary. Strateginya:

1. Brute force chunk pertama dari charset `a-z0-9_`.
2. Dari `D[0]`, turunkan kandidat `D[1]..D[6]` memakai relasi berantai.
3. Filter kandidat dengan wraparound check dan final hash.
4. Untuk tiap target `D` berikutnya, cari chunk 4 byte yang menghasilkan nilai itu dan tidak mengaktifkan bit gagal `ecx`.
5. Cek final state `S[0] & 3 == 1` dan `S[1] & 3 == 2`.
6. Cetak flag.

## Cara Menjalankan

```
cd /mnt/data/leakmeak_chal
python3 solve.py
```

Output:

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```

Untuk submit ke remote, jalankan sendiri:

```
printf 'ASIS{haaducrcplmekhylrozcxyxzuizs}\n' | nc 65.109.208.91 3117
```

## Flag

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```
