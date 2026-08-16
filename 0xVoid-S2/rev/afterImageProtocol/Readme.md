# Afterimage Protocol

## Ringkasan

Binary `afterimage` tidak menyimpan flag sebagai string. Program hanya mengecek format `0xV01D{...}`, mengambil 16 karakter body, menjalankannya melalui 320 operasi byte/word yang dibentuk dari section `.mist`, lalu membandingkan state akhir dengan target 16 byte yang juga berada di `.mist`.

Karena setiap operasi transformasi bersifat invertible, flag dapat diperoleh tanpa brute force. Caranya adalah menghitung state akhir yang diharapkan, kemudian menjalankan seluruh operasi secara terbalik hingga kembali ke 16 byte input asli.

**Flag:**

```text
0xV01D{N3bula7R4v3n9X2Q}
```

## File Challenge

Isi arsip:

```text
afterimage       ELF 64-bit LSB executable, x86-64, statically linked, stripped
README.md        deskripsi challenge
SHA256SUMS.txt   hash file challenge
```

Hash dari `SHA256SUMS.txt` valid:

```text
afterimage: OK
```

## Analisis Awal

`file` menunjukkan binary berupa ELF x86-64 static dan stripped.

Section penting dari `readelf -S`:

```text
.text    VA 0x401000, file offset 0x1000, size 0x4d8
.rodata  VA 0x402000, file offset 0x2000, size 0x84
.mist    VA 0x402090, file offset 0x2090, size 0xa20
```

`strings` memperlihatkan output program:

```text
no matching reflection
reflection accepted
Afterimage Protocol v2
identifier>
```

Saat dijalankan, program membaca input dari stdin dan mencetak `reflection accepted` hanya untuk identifier yang valid.

## Analisis Static

Entry point langsung berisi logic program karena binary static kecil dan stripped.

Validasi format terdapat di awal `.text`:

* panjang input sebelum newline harus `0x18` atau 24 byte;
* byte awal harus `0xV01D{`;
* byte terakhir harus `}`;
* 16 byte di dalam braces harus alfanumerik.

Potongan disassembly penting:

```asm
401070: cmp eax,0x18
401075: cmp BYTE PTR [rsp-0x38],0x30 ; '0'
40107c: cmp BYTE PTR [rsp-0x37],0x78 ; 'x'
401083: cmp BYTE PTR [rsp-0x36],0x56 ; 'V'
40108a: cmp BYTE PTR [rsp-0x35],0x30 ; '0'
401091: cmp BYTE PTR [rsp-0x34],0x31 ; '1'
401098: cmp BYTE PTR [rsp-0x33],0x44 ; 'D'
40109f: cmp BYTE PTR [rsp-0x32],0x7b ; '{'
4010a6: cmp BYTE PTR [rsp-0x21],0x7d ; '}'
```

Body flag kemudian disalin ke buffer 16 byte. Setelah itu program membaca data dari section `.mist`.

## Layout `.mist`

Layout section `.mist` adalah:

```text
offset 0x00: magic/header      MRR2...
offset 0x08: seed qword        0xd1ceb00c7a11f00d
offset 0x10: 320 qword tape
offset akhir: target 16 byte   15e0df1367f542d563d4eaccdcb1dd8b
```

Loop utama dimulai dari `ebx = 0x29`, lalu setiap iterasi `ebx += 0x49` hingga `0x5b69`.

Index tape dihitung dengan:

```text
idx = ebx % 0x140
```

Jumlah iterasi:

```text
(0x5b69 - 0x29) / 0x49 = 320
```

Karena:

```text
gcd(0x49, 0x140) = 1
```

loop mengunjungi seluruh 320 slot tape dalam urutan terlipat.

## Analisis Dynamic

Tes dengan input salah:

```bash
printf '0xV01D{AAAAAAAAAAAAAAAA}\n' | ./afterimage
```

Output:

```text
Afterimage Protocol v2
identifier> no matching reflection
```

Tes dengan flag hasil solve:

```bash
printf '0xV01D{N3bula7R4v3n9X2Q}\n' | ./afterimage
```

Output:

```text
Afterimage Protocol v2
identifier> reflection accepted
```

## Algoritma Validasi / Encoding

Program membentuk 320 instruksi dari section `.mist`.

Setiap slot tape di-XOR dengan mask SplitMix64-like yang berbasis seed dan `idx`.

Pseudocode pembentukan instruksi:

```text
idx = ebx % 0x140

tape_qword = mist[0x10 + idx * 8 : 0x10 + idx * 8 + 8]

mask = splitmix64_finalizer(
    (0xd6e8feb86659fd93 * idx) ^
    seed ^
    0xa17e5eedc0dec0de +
    GOLDEN
)

key = tape_qword ^ mask

selector = (
    ((0x1d * idx - 0x59) ^ key_low_dword) & 0xff
) % 7
```

`key` juga masuk ke FNV-1a 64-bit accumulator. Accumulator ini dipakai pada tahap compare akhir dan tidak berasal dari input user.

Terdapat tujuh operasi terhadap state 16 byte:

| Selector | Operasi                                         |
| -------: | ----------------------------------------------- |
|        0 | XOR 1 byte                                      |
|        1 | ADD 1 byte modulo 256                           |
|        2 | ROL 1 byte                                      |
|        3 | SWAP 2 byte                                     |
|        4 | Multiply byte dengan odd multiplier + konstanta |
|        5 | Feistel-like transform pada 2 × 64-bit half     |
|        6 | Rotate seluruh state 16 byte                    |

### Sifat Invertible

Semua operasi dapat dibalik:

* **XOR** dibalik dengan XOR yang sama.
* **ADD** dibalik dengan SUB.
* **ROL** dibalik dengan ROR.
* **SWAP** dibalik dengan SWAP kembali.
* **Multiply byte** menggunakan multiplier ganjil, sehingga memiliki inverse modulo `256`.
* **Feistel-like transform** dibalik dengan `R = newL`, kemudian fungsi `F(R)` dihitung ulang untuk memperoleh `L`.
* **Rotate 16 byte** dibalik dengan rotasi ke arah sebaliknya.

Dengan demikian, tidak diperlukan brute force terhadap 16 karakter flag.

## Tahap Compare Akhir

Program membandingkan state akhir dengan 16 byte target di akhir `.mist`.

Target tidak dibandingkan secara langsung, tetapi terlebih dahulu di-XOR dengan mask SplitMix64-like berbasis FNV accumulator:

```text
final_key = fnv ^ seed

expected_state[i] =
    target[i] ^
    (
        splitmix64_finalizer(
            (i * GOLDEN) ^ final_key + GOLDEN
        ) & 0xff
    )
```

State akhir yang diharapkan adalah:

```text
4ea0ddff1529f760f4e773f9d7f8c390
```

Kemudian seluruh 320 operasi dijalankan secara terbalik. Hasil akhirnya adalah:

```text
N3bula7R4v3n9X2Q
```

## Penyusunan Solve Script

`solve.py` melakukan langkah berikut:

1. Membaca binary `afterimage`.
2. Mengambil section `.mist` dari offset `0x2090` dengan ukuran `0xa20`.
3. Membentuk ulang 320 instruksi dari tape.
4. Menghitung FNV accumulator dan expected final state.
5. Menjalankan inverse operation dari instruksi ke-320 sampai instruksi pertama.
6. Mengecek ulang hasilnya dengan forward emulator.
7. Mencetak body dan flag.

Output script:

```text
seed       : 0xd1ceb00c7a11f00d
ops        : 320 {0: 44, 1: 48, 2: 50, 3: 52, 4: 38, 5: 40, 6: 48}
fnv        : 0xe0b595643124827b
final state: 4ea0ddff1529f760f4e773f9d7f8c390
body       : N3bula7R4v3n9X2Q
flag       : 0xV01D{N3bula7R4v3n9X2Q}
```

## Cara Menjalankan

Jalankan:

```bash
cd /mnt/data/afterimage_protocol
python3 solve.py
```

Untuk memvalidasi hasil secara langsung terhadap binary:

```bash
printf '0xV01D{N3bula7R4v3n9X2Q}\n' | ./afterimage
```

Expected output:

```text
Afterimage Protocol v2
identifier> reflection accepted
```

## Flag

```text
0xV01D{N3bula7R4v3n9X2Q}
```
