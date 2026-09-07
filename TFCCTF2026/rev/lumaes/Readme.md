# lumaes

## Ringkasan

Binary AArch64 ini ngecek flag dengan white-box AES yang dibikin sengaja ribet. Fungsi `check()` dan `lumaes_encrypt_block()` cuma wrapper; body pentingnya dienkripsi dan baru dibuka lewat `__enc_enter()`.

Flag didapat dengan cara tidak menjalankan binary ARM-nya langsung. Tabel white-box di `.data` diekstrak, lalu transformasinya dibalik per blok 16 byte sampai plaintext keluar.

## File Challenge

```
chall: ELF 64-bit LSB executable, ARM aarch64, dynamically linked, not stripped
```

Symbol penting dari `readelf -s`:

```
0x8ef970   check
0xb52970   lumaes_encrypt_block
0x8efa40   xor32
0x917900   xor128
0xb701a0   sr
0xb70204   wb_tii
0xb94204   wb_tiii
0xbb8204   wb_xor
0xc24204   wb_tv
0xc25204   flag_blocks
0xc25208   flag_ct
```

## Analisis Awal

`strings` nunjukin beberapa string normal:

```
flag?
Correct.
flag_blocks
flag_ct
lumaes_encrypt_block
```

Ada juga string bait/prompt-injection di binary. Itu cuma noise dari challenge dan tidak dipakai buat analisis.

`main()` alurnya simpel:

```
print "flag? "
read input
check(input)
kalau check != 0 -> Correct.
```

`check()` sendiri bukan body asli. Wrapper-nya manggil:

```
__enc_enter(desc)
enc.body.1(input)
__enc_leave(desc)
```

## Analisis Static

Dari descriptor runtime encryption:

```
check body:
addr   = 0x400670
length = 0x4ef2f8
key    = "ong-hiumee-is-kinda-skibidi"

lumaes body:
addr   = 0x917a30
length = 0x23af3c
key    = "no-key-in-here"
```

Routine decrypt body:

```python
w4 = (31 * len(key) + 7) & 0xff
for i in range(length):
    w4 = (w4 + key[i % len(key)] + i) & 0xff
    buf[i] ^= w4
```

Setelah body dibuka, bagian pentingnya tetap sangat obfuscated, tapi call ke `xor128()` masih bisa dilacak. Dari ukuran tabel:

```
wb_tii  = 0x24000 = 9 * 16 * 256 * 4
wb_tiii = 0x24000 = 9 * 16 * 256 * 4
wb_xor  = 0x6c000 = 216 * 0x800
wb_tv   = 0x1000  = 16 * 256
```

Ini cocok dengan 9 round white-box AES:

```
9 round * 4 kolom * 2 xor128 per kolom = 72 xor128
72 xor128 * 3 xor32 = 216 xor32 table
```

## Analisis Dynamic

Binary target AArch64, jadi tidak langsung dieksekusi native di environment x86_64. Untuk trace lokal, body decrypt diemulasi ringan dan `xor128()` di-hook.

Trace dengan input `ABCDEFGHIJKLMNOP` membuktikan urutan round pertama:

```
call 1: wb_tii  round 0 pos 0..3   input A F K P
call 2: wb_tiii round 0 pos 0..3   input hasil call 1 secara big-endian
call 3: wb_tii  round 0 pos 4..7   input E J O D
call 4: wb_tiii round 0 pos 4..7
call 5: wb_tii  round 0 pos 8..11  input I N C H
call 6: wb_tiii round 0 pos 8..11
call 7: wb_tii  round 0 pos 12..15 input M B G L
call 8: wb_tiii round 0 pos 12..15
```

Permutation `sr`:

```
[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
```

Jadi setiap round diawali ShiftRows:

```
shifted[i] = state[sr[i]]
```

## Algoritma Validasi atau Encoding

Satu blok 16 byte diproses begini:

```
state = plaintext_block

for r in range(9):
    shifted[i] = state[sr[i]]

    untuk tiap kolom c:
        w1 = xor128(wb_tii[r][4c+0..4c+3][shifted[4c..4c+3]])
        mid = bytes(w1, big-endian)
        w2 = xor128(wb_tiii[r][4c+0..4c+3][mid])
        state[4c..4c+3] = bytes(w2, big-endian)

cipher[i] = wb_tv[i][state[sr[i]]]
```

`xor128()` berisi 3 kali `xor32()`. `xor32()` bekerja per nibble lewat lookup table 0x800 byte:

```python
def xor32(table, a, b):
    r = 0
    for k in range(8):
        shift = 4 * (7 - k)
        idx = (((a >> shift) & 0xf) << 4) | ((b >> shift) & 0xf)
        r |= table[k * 0x100 + idx] << shift
    return r
```

Ciphertext hardcoded terdiri dari 4 blok:

```
71 51 ed 9c 0f 52 e1 b6 0f 0c 18 e2 ee ce ba 97
08 f9 15 b5 0d 66 0b 0b 7e 10 fc 04 6e b2 43 3e
73 1c 55 b3 46 f5 c2 4a 7f 05 92 bd 58 0f ae 8c
e4 48 1d d8 14 06 78 07 23 17 4e 96 52 6d a3 e4
```

## Penyusunan Solve Script

`solve.py` mengekstrak tabel langsung dari `chall`, lalu membalik transformasinya.

Pembalikan `xor128()` dilakukan pakai meet-in-the-middle:

```
L = xor32(word0, word1)
R = xor32(word2, word3)
out = xor32(L, R)
```

Untuk target 32-bit, solver bikin map semua kemungkinan `L` dari pasangan byte pertama dan kedua. Lalu pasangan byte ketiga dan keempat dicoba untuk mencari `R` yang cocok.

Model yang valid dari trace:

```
endian result = big-endian
round pre-permutation = sr
final TV permutation = sr
```

Hasil plaintext terakhir punya padding PKCS#7 `0x0b`, lalu padding dibuang.

## Cara Menjalankan

```bash
cd /mnt/data/lumaes
python3 solve.py
```

Output:

```
<FLAG>TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9}</FLAG>
```

## Flag

```
TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9}
```

