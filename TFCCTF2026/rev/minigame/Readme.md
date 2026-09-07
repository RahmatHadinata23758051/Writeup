# MINIGAME

## Ringkasan

Binary adalah game terminal statically linked dan stripped. Flag tidak muncul sebagai string biasa. Saat event akhir/vault terbuka, program menyalin 16 byte kunci dari `.rodata`, menjalankan rutinitas PRNG/custom mixer di alamat `0x11ef760`, lalu mendekripsi 39 byte ciphertext ke area global tepat sebelum map.

Flag bisa diambil tanpa memainkan game penuh dengan mereplikasi rutinitas decode tersebut.

## File Challenge

- `mini_game(2)`
  - ELF 64-bit LSB executable
  - x86-64
  - statically linked
  - stripped

File bantu yang dibuat:

- `solve.py` — script ekstraksi flag dari binary
- `Readme.md` — writeup teknis

## Analisis Awal

Pemeriksaan awal:

```bash
file *
strings -a './mini_game(2)' | head -n 100
readelf -h './mini_game(2)'
readelf -S './mini_game(2)'
objdump -d -M intel './mini_game(2)' > objdump_minigame.txt
```

Hasil penting dari `file`:

```
mini_game(2): ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

Section penting dari `readelf -S`:

```
.rodata vaddr 0x1000240 offset 0x240
.text   vaddr 0x11be7d0 offset 0x1bd7d0
.data   vaddr 0x11f88a0 offset 0x1f58a0
.bss    vaddr 0x11fe000 offset 0x1fa310
```

Karena `.rodata` punya selisih tetap `vaddr - file_offset = 0x1000000`, alamat virtual `.rodata` bisa langsung dikonversi ke offset file. Contoh:

```
vaddr 0x1000880 -> file offset 0x880
vaddr 0x100f7d5 -> file offset 0xf7d5
```

String game yang relevan:

```
fbgchadebhcfaged
CIPHER PANELS  TOP 4  MID 2  BOT 1  READ L TO R
CIPHER ACCEPTED  VAULT OPEN
WRONG LEVER  SEQUENCE RESET
DEFEAT CLOCKWORK MOON AND THE FLAG VAULT AUTO OPENS
```

String `fbgchadebhcfaged` cocok dengan 16 byte kunci jika huruf `a` sampai `h` dipetakan ke nilai `0` sampai `7`:

```
f b g c h a d e b h c f a g e d
5 1 6 2 7 0 3 4 1 7 2 5 0 6 4 3
```

Byte yang sama juga ada di `.rodata` pada offset `0x880`.

## Analisis Static

Entry binary masuk ke loop game. Program memakai banyak global address tetap karena binary non-PIE.

Map game berada di global buffer:

```
0x140665c  world grid, ukuran 96 x 96
```

Di map hasil dump runtime ada clue:

```
S.fbgchadebhcfaged......S
```

Status message memakai enum global di sekitar:

```
0x1404218  status/message enum
```

Nilai `9` mengarah ke string:

```
CIPHER ACCEPTED  VAULT OPEN
```

Block akhir game ada di sekitar `0x11c3e75`. Bagian pentingnya:

```
11c3e90: vmovupd xmm0, XMMWORD PTR [rip+...]  # 0x1000880
11c3e98: vmovupd XMMWORD PTR [rip+...]        # 0x140661e
11c3eb4: call 0x11ef760
11c3ec0: call 0x11ef0b0
11c3ecc: mov BYTE PTR [0x140665a], 0x1
11c3ed3: mov BYTE PTR [0x1404218], 0x9
```

Jadi saat vault dibuka, program:

1. Menyalin 16 byte dari `0x1000880` ke `0x140661e`.
2. Memanggil fungsi `0x11ef760`.
3. Mengubah status game menjadi vault terbuka.

Fungsi `0x11ef760` membaca 16 byte kunci dari `0x140661e` sampai `0x140662d`, menghitung seed 64-bit dengan beberapa konstanta mixer, lalu mendekripsi ciphertext dari `.rodata`.

Ciphertext yang dipakai ada di alamat virtual:

```
0x100f7d5 .. 0x100f7fb
```

Karena mapping `.rodata`, offset file-nya:

```
0xf7d5 .. 0xf7fb
```

Panjang ciphertext adalah 39 byte.

## Analisis Dynamic

Binary butuh TTY. Jika dijalankan tanpa terminal interaktif, program gagal dengan:

```
error: NotATerminal
```

Saat dijalankan lewat PTY lokal, game menampilkan HUD:

```
HP 120  PICK 4  BLADE 4  KILLS 0  POWER OFF  ITEM STONE 0
FOLLOW THE COMPASS  DEFEAT THE FINAL BOSS TO OPEN THE FLAG VAULT
AWAKENING  KILL 4 THEN FIND GREEN ALTAR
```

Dump memori proses lokal memperlihatkan map 96x96 dan clue `fbgchadebhcfaged`. Dynamic analysis dipakai untuk mengonfirmasi bahwa clue tersebut memang bagian dari dunia game, bukan string acak biasa.

## Algoritma Validasi atau Encoding

Tidak ada `strcmp` langsung terhadap flag. Flag didekripsi saat vault terbuka.

Alurnya:

1. Ambil 16 byte key dari offset file `0x880`:

```
05 01 06 02 07 00 03 04 01 07 02 05 00 06 04 03
```

2. Key ini sama dengan hasil mapping clue:

```
fbgchadebhcfaged -> [5,1,6,2,7,0,3,4,1,7,2,5,0,6,4,3]
```

3. Key diproses oleh mixer 64-bit di fungsi `0x11ef760`. Instruksi utamanya memakai:

```
ror64(state, 0x33)
multiply 0xbf58476d1ce4e5b9
xor dan shift kanan 0x1d
```

4. Setelah seed jadi, program menjalankan xorshift:

```
seed ^= seed >> 12
seed ^= seed << 25
seed ^= seed >> 27
keystream = (seed * 0x2545f4914f6cdd1d) >> 56
```

5. Setiap byte ciphertext di-XOR dengan byte keystream.

Hasil plaintext adalah flag.

## Penyusunan Solve Script

`solve.py` membaca binary lokal, mengambil:

```
key        = binary[0x880:0x890]
ciphertext = binary[0xf7d5:0xf7fc]
```

Lalu script mereplikasi fungsi decode `0x11ef760`:

- operasi 64-bit dibatasi dengan mask `0xffffffffffffffff`
- implementasi `ror64`
- implementasi mixer key
- implementasi xorshift keystream
- XOR ciphertext dengan keystream

Script tidak brute force dan tidak bergantung ke tebakan flag.

## Cara Menjalankan

```bash
cd /mnt/data
chmod +x solve.py
./solve.py
```

Output:

```
TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d}
```

## Flag

```
TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d}
```
