# LayerCake (Reverse)

## Info
- **Binary**: `challenge` — ELF 64-bit, dynamically linked, x86-64, not stripped (simbol fungsi kebawa)
- **Flag**: `TBCTF{mult1_lay3r_r3v3rs3}`

## Recon

`afl` di r2 cuma nemu lima fungsi anonim (`fcn.1303`, `fcn.12ad`, `fcn.11f2`, `fcn.11a9`) plus `entry0` — `main` gak ke-detect otomatis. Cek `entry0`:
lea rdi, [0x134c]

call __libc_start_main
Address `0x134c` itu argumen ketiga (`main`) buat `__libc_start_main`. r2 gagal define function di situ karena nyambung langsung sama akhir `fcn.1303` (di alamat 0x134b: `pop rbp; ret`) tanpa padding. Define manual:

af @ 0x134c

pdf @ 0x134c

## Analisis main

Flow program:

1. Validasi argc == 2, kalau gak ada argumen → print usage.
2. `atoi(argv[1])` → key, harus 0-255.
3. `memcpy` 26 byte ciphertext dari `.data @ 0x4050` ke stack buffer.
4. `srand(time(NULL))` lalu `rand() % 100` → nilai random `R` (0-99), berubah tiap kali binary dijalankan — ini sumber output yang "berbeda setiap run" kayak yang disebut di deskripsi challenge.
5. Buffer di-transform lewat 4 fungsi berurutan:
   - `fcn.1303(buf, len, R)` → tiap byte di-XOR sama `R`
   - `fcn.12ad(buf, len)` → tiap byte di-XOR sama tabel `T[i] = (i*7 + 11) & 0xFF` (dihasilkan dari kombinasi shift+sub di fungsi itu, bukan tabel statis di memori — tapi behaviour-nya identik formula linear ini)
   - `fcn.11f2(buf, len, 1)` → rotate-left 3 bit tiap byte (arg ke-3 nentuin arah/jumlah rotasi)
   - `fcn.11a9(buf, len, K)` → tiap byte di-XOR sama key user `K`
6. `puts(buf)` — print hasil akhir.

Jadi output yang keliatan di README ("garbage" pas dijalanin dengan key 0/128/255) itu karena kombinasi `R` (random) dan `K` (key) yang gak pas. Cuma kombinasi tertentu dari `R` dan `K` yang bikin `R XOR K` ketemu nilai yang pas buat decode jadi plaintext — itu makna dari "every now and then, one of those is right."

## Insight exploit

`R` cuma punya 100 kemungkinan (`rand() % 100`), `K` cuma punya 256 kemungkinan (constraint `atoi` 0-255). Total search space cuma 25.600 — kecil banget buat brute force offline, gak perlu interaksi sama binary atau prediksi seed RNG sama sekali.

Formula forward:

O[i] = ROL3( D[i] ^ R ^ T[i] ) ^ K,   T[i] = (i*7+11) & 0xFF

Brute semua `(R, K)`, filter output yang printable ASCII dan match pattern `TBCTF{...}` — langsung ketemu satu kandidat valid (`R` dan `K` saling kompensasi linear, makanya muncul di banyak pasangan berbeda, tapi hasil decode-nya selalu sama).

## Exploit

```python
D = bytes.fromhex("08d3f82366c8111b474dfe3a5bc3cb9bbce04e7fd071624b5c9c")

def rol3(b):
    return ((b << 3) | (b >> 5)) & 0xFF

def transform(R, K):
    out = bytearray(len(D))
    for i in range(len(D)):
        t = (i * 7 + 11) & 0xFF
        v = D[i] ^ R ^ t
        v = rol3(v)
        v ^= K
        out[i] = v
    return bytes(out)

for R in range(100):
    for K in range(256):
        out = transform(R, K)
        if out.startswith(b"TBCTF{") and out.endswith(b"}"):
            print(R, K, out.decode())
```

Output: `TBCTF{mult1_lay3r_r3v3rs3}`

## Flag
TBCTF{mult1_lay3r_r3v3rs3}

