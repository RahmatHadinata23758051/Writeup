# Jack Black Writeup

## Ringkasan

Challenge ini keliatan seperti game blackjack biasa, tapi ada dua bug di jalur kemenangan:

1. `fgets(name, 256, stdin)` membaca sampai 256 byte ke buffer `name[64]`  
   Ini memberi stack overflow.
2. `printf(name)` dipanggil langsung tanpa format string tetap  
   Ini memberi format string vulnerability.

Proteksi binary:

- `NX` aktif
- `Canary` aktif
- `No PIE`
- `Partial RELRO`

Karena ada canary, overflow mentah tidak cukup. Solusi paling enak adalah pakai format string dulu untuk leak canary dan libc, lalu pada win berikutnya kirim payload overflow + ret2libc.

## Recon

Binary yang dipakai adalah `blackjack`.

Source yang disediakan langsung memperlihatkan bagian rentan:

```c
char name[NAME_BUF];
...
fgets(name, 256, stdin);
name[strcspn(name, "\n")] = '\0';
printf("Processing transaction for: ");
printf(name);
```

Layout stack dari `game_loop` di assembly:

- `name` ada di `rbp-0x50`
- canary ada di `rbp-0x8`

Jadi offset dari awal buffer ke canary adalah:

```text
0x50 - 0x8 = 0x48 = 72 byte
```

## Leak

Jalur bug hanya bisa diakses kalau menang satu hand. Jadi exploit harus:

1. main sampai menang
2. kirim format string pendek untuk leak
3. pilih main lagi
4. menang lagi
5. kirim payload overflow

Saya pakai strategi sederhana:

- `hit` kalau total hand `< 17`
- `stand` kalau total hand `>= 17`

Itu sudah cukup untuk menang secara konsisten.

Dari brute force index format string, didapat:

- `%17$p` -> stack canary
- `%43$p` -> pointer ke libc

Untuk libc remote yang dibundel, leak `%43$p` selalu punya offset:

```text
libc_base = leak - 0x2a28b
```

## ROP

Setelah base libc diketahui, chain yang dipakai sederhana:

```text
ret
pop rdi ; ret
"/bin/sh"
system
```

Offset payload:

```text
"A" * 72
canary
"B" * 8        # saved rbp
ret
pop rdi ; ret
/bin/sh
system
```

Sesudah name diproses, program masih menanyakan:

```text
Play another hand? [y/n]:
```

Supaya fungsi `game_loop()` benar-benar `return` dan ROP jalan, jawaban harus `n`.

## Kendala Praktis

Ada satu detail yang penting:

`fgets` berhenti saat bertemu newline (`0x0a`). Kalau byte `0x0a` muncul di canary atau alamat ROP, payload bisa kepotong di tengah.

Solusi saya:

- cek apakah payload mengandung `\n`
- kalau iya, tutup koneksi dan coba lagi

Karena ASLR berubah tiap koneksi, retry penuh lebih simpel dan tetap cepat.

## Hasil

Exploit final ada di `exploit.py`.

Alurnya:

1. konek ke remote
2. menang sekali
3. leak canary dan libc
4. menang lagi
5. kirim ret2libc
6. jawab `n`
7. dapat shell
8. baca `flag.txt`

Flag yang didapat:

```text
dalctf{w3r3_y0u_c0unt1ng_c4rd5?}
```
