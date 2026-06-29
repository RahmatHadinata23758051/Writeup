# Something (Reverse)

## Info
- **Binary**: `chall` — ELF 64-bit, statically linked Go binary, not stripped
- **Flag**: `TBCTF{r3v_x0r_m3mfr0b!}`

## Recon

Binary statik Go, debug info masih ada jadi semua nama simbol package `main` kebawa:
nm chall | grep ' main.'

Ketemu beberapa global menarik: `encPrompt`, `encCorrect`, `encIncorrect`, `encExpected`, sama empat `encFakeN`. Semua isinya bukan plaintext — di-encode sama satu byte XOR key. Dump byte mentahnya pakai radare2 (`pxq 16 @ alamat`), terus brute key 1 byte sampe `encPrompt` jadi `"Enter flag: "`. Key-nya `0x16`.

Decode semua string pakai key itu, hasilnya:
PROMPT    : Enter flag:

CORRECT   : Correct! Flag is your input.

INCORRECT : Incorrect flag.

FAKE1     : TBCTF{sh4_h4sh_br0k3n}

FAKE3     : TBCTF{rs4_pr1v4t3_k3y}

FAKE4     : TBCTF{hm4c_s1gn3d}

FAKE5     : TBCTF{bl0wf1sh_c1ph3r}

`encExpected` tetap non-printable walau di-XOR `0x16` — berarti bukan plaintext langsung, ada layer encoding lain. Empat `FAKE*` itu decoy: nama-nama algoritma crypto (SHA, RSA, HMAC, Blowfish) sengaja dipasang biar reverser kebuang waktu nyari implementasi crypto yang sebenernya gak dipakai.

## Analisis main.main

Disasm `main.main` nunjukin flow:

1. Input dibaca, di-trim.
2. Validasi panjang ≥ 6, 6 byte pertama harus `"TBCTF{"` (dicek pakai satu `movabs` constant), byte terakhir harus `'}'`.
3. Sebelum sampai ke pengecekan asli, ada serangkaian percabangan yang ngecek angka-angka random kayak `0xdeadbeef`, `0xcafebabe`, `0x12345678`, `1337`, `42` — semua jalur ini ujungnya manggil salah satu `encFakeN`. Decoy, gak ada pengaruh ke validasi sebenarnya.
4. Jalur asli: bagian tengah input (antara `TBCTF{` dan `}`, harus pas 16 byte) dilempar ke `main.reallocate_memory_region`. Hasil boolean-nya (lewat flag ZF setelah `call`) nentuin print `encCorrect` atau `encIncorrect`.

## Analisis main.reallocate_memory_region

Ini fungsi validasi sebenarnya:

1. Cek panjang input tengah harus 16 byte persis.
2. **Reverse** 16 byte itu (swap index `i` dengan `15-i`).
3. Tiap byte di-**XOR `0xd7`**, lalu di-**XOR `0x2a`** lagi — net-nya sama aja kayak XOR `0xfd`.
4. Bangun buffer pembanding dari `encExpected`: tiap byte `encExpected[i]` di-XOR sama 6 byte key gabungan (XOR dari konstanta `"TBCTF{"` di rodata) terus di-XOR `0x2a` lagi.
5. Compare byte-per-byte. Kalau cocok semua → return true → `encCorrect`.

Disederhanain: kombinasi reverse + dua XOR berturut sama aja kayak **input_middle[k] = encExpected[15-k] XOR 0xEB** (gabungan net XOR dari kedua sisi).

## Exploit

```python
enc_expected = bytes([
    0xca, 0x89, 0xdb, 0x99, 0x8d, 0x86, 0xd8, 0x86,
    0xb4, 0x99, 0xdb, 0x93, 0xb4, 0x9d, 0xd8, 0x99,
])
middle = bytes(enc_expected[15 - k] ^ 0xEB for k in range(16))
flag = "TBCTF{" + middle.decode() + "}"
print(flag)
```

Output: `TBCTF{r3v_x0r_m3mfr0b!}`

Validasi langsung ke binary:

$ echo "TBCTF{r3v_x0r_m3mfr0b!}" | ./chall

Enter flag: Correct! Flag is your input.

## Flag

TBCTF{r3v_x0r_m3mfr0b!}


