# MINIGAME2

## Ringkasan

Binary adalah game terminal ELF 64-bit, statically linked, stripped. Flag tidak tersimpan sebagai string plaintext. Setelah syarat game terpenuhi, program menyalin key panel ke buffer global lalu menjalankan fungsi decode di `0x11f0d30`. Versi kedua menambah gate ore ledger sebelum flag dibuka, dan encoding flag dibuat lebih ribet: ciphertext dipecah ke empat tabel kecil, urutan bacanya diacak dengan modulo, lalu tiap byte diputar dan di-XOR dengan byte dari PRNG/mixer custom.

Flag bisa diambil tanpa memainkan game penuh dengan mereplikasi fungsi decode tersebut.

## File Challenge

- `minigame2`
  - ELF 64-bit LSB executable
  - x86-64
  - statically linked
  - stripped

File bantu:

- `solve.py` — script ekstraksi flag dari binary
- `Readme.md` — writeup teknis

## Analisis Awal

Pemeriksaan awal:

```bash
cd /mnt/data
file *
strings -a ./minigame2 | head -n 100
readelf -h ./minigame2
readelf -S ./minigame2
objdump -d -M intel ./minigame2 > objdump_minigame2.txt
```

Hasil penting:

```
minigame2: ELF 64-bit LSB executable, x86-64, statically linked, stripped
Entry point address: 0x11bea70
```

Section penting:

```
.rodata  vaddr 0x1000240  offset 0x240
.text    vaddr 0x11bea70  offset 0x1bda70
.data    vaddr 0x11f9e30  offset 0x1f6e30
.bss     vaddr 0x11ff000
```

Mapping `.rodata` punya delta tetap:

```
vaddr - file_offset = 0x1000000
```

Jadi alamat virtual `.rodata` bisa dikonversi langsung ke offset file dengan `offset = vaddr - 0x1000000`.

String game yang relevan:

```
fbgchadebhcfaged
MINE EVERY ORE QUOTA  THEN DEFEAT THE FINAL BOSS TO OPEN THE FLAG VAULT
CIPHER PANELS  TOP 4  MID 2  BOT 1  READ L TO R
CIPHER ACCEPTED  VAULT OPEN
VAULT SEALED  MINE EVERY ORE QUOTA
MINE COAL 2  IRON 4  HELLSTONE 4  CRYSTAL 5  SOUL 5
```

Dibanding MINIGAME pertama, versi ini menambah syarat mined quota sebelum vault benar-benar terbuka.

## Analisis Static

Referensi ke key panel muncul di disassembly:

```
11c4a82: vmovupd xmm0, XMMWORD PTR [rip+...]  # 0x10008b0
11c4a8a: vmovupd XMMWORD PTR [rip+...]        # 0x1405228
11c4aa6: call   0x11f0d30
```

Key 16 byte berada di `.rodata` offset file `0x8b0`:

```
05 01 06 02 07 00 03 04 01 07 02 05 00 06 04 03
```

Byte ini cocok dengan clue `fbgchadebhcfaged` jika huruf `a` sampai `h` dipetakan ke angka `0` sampai `7`:

```
f b g c h a d e b h c f a g e d
5 1 6 2 7 0 3 4 1 7 2 5 0 6 4 3
```

Fungsi decode utama ada di `0x11f0d30`. Awal fungsi mengecek beberapa gate:

```
cmp BYTE PTR [0x140763a], 0x1       ; vault/key state
cmp BYTE PTR [0x1405239], 0x1       ; cipher accepted
vpmaxuw ... [0x1402dfa] vs [0x1000840]
cmp WORD PTR [0x1402e02], 0x4       ; progress/kill/ledger gate
```

Gate ore ledger membandingkan mined count global dengan target di `.rodata` offset `0x840`:

```
02 00 04 00 04 00 05 00
```

Itu sesuai string quota:

```
COAL 2, IRON 4, HELLSTONE 4, CRYSTAL 5
```

SOUL dicek lewat progress berikutnya (`cmp WORD PTR [0x1402e02], 0x5` di helper sekitar `0x11f107f`) sebelum status sukses ditulis.

## Analisis Dynamic

Binary adalah game terminal dan butuh TTY. Jalur dynamic tidak diperlukan untuk brute force. Static analysis sudah cukup karena fungsi `0x11f0d30` langsung memperlihatkan:

1. key 16 byte yang dipakai,
2. seed mixer,
3. pointer ke tabel ciphertext,
4. panjang output,
5. transform byte per byte.

Output flag tidak divalidasi dengan `strcmp`; flag ditulis ke buffer global mulai `0x140763b`. Loop decode berhenti setelah 54 byte, lalu program menulis `0x36` ke `0x1407671`, cocok dengan panjang flag `54`.

## Algoritma Validasi atau Encoding

Decode flag memakai dua tahap.

Tahap pertama, derive seed dari key 16 byte:

```
key offset file: 0x8b0 .. 0x8bf
initial state : 0x07defd73b4593394
xor final     : 0xc3a5c85c97cb3127
```

Loop seed memproses dua byte key per iterasi. Tiap byte dikalikan konstanta turunan `0x6d2b79f5`, ditambah state, di-rotate 64-bit, lalu di-XOR dengan hasil shift kanan `0x17`.

Tahap kedua, decode 54 byte ciphertext. Ciphertext tidak linear di satu array. Ada pointer table di `.rodata` alamat virtual `0x11b87a8`, offset file `0x1b87a8`:

```
0x100f80a
0x100f818
0x100f826
0x100f833
```

Empat pointer ini menunjuk empat chunk encoded byte:

```
0x100f80a: f8 45 a9 23 35 ba 11 c5 80 75 2e e1 b6 75
0x100f818: 47 ee 00 de 27 d4 ea bc 76 c6 09 e2 dd 9e
0x100f826: 1b 75 73 ce 17 4b 3f 34 68 95 1c 44 a4
0x100f833: d0 19 8b 40 6f 70 1b 86 4a f4 d3 10 5a
```

Urutan baca byte dihitung dari `pos_seed % 54`, dengan `pos_seed` mulai dari `7` dan bertambah `0x13`. Binary menghitung modulo ini memakai magic multiply `0x97b425ed097b425f`, tapi hasilnya sama dengan modulo 54 untuk range loop ini.

Setiap byte encoded diproses seperti ini:

```
pos = pos_seed % 54
enc = table[pos & 3][pos >> 2]
state = PRNG/mixer custom 64-bit
val = enc - ((state >> 27) & 0xff) + delta
plain = ror8(val, (top_byte % 7) + 1) ^ mask
```

`delta` mulai `0`, lalu berkurang `0x1d` setiap byte. `mask` diambil dari kombinasi `state`, `state >> 19`, dan `state >> 43`.

## Penyusunan Solve Script

`solve.py` membaca binary lokal `./minigame2`, lalu mengambil:

```
key           = binary[0x8b0:0x8c0]
pointer table = binary[0x1b87a8:0x1b87c8]
flag length   = 54
```

Script mengimplementasikan ulang:

- rotate 64-bit (`rol64`),
- rotate kanan 8-bit (`ror8`),
- seed mixer dari fungsi `0x11f0d30`,
- pembacaan empat tabel ciphertext,
- loop decode 54 byte.

Tidak ada brute force dan tidak ada tebakan flag.

## Cara Menjalankan

```bash
cd /mnt/data
chmod +x solve.py
./solve.py
```

Output:

```
TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying}
```

## Flag

```
TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying}
```
