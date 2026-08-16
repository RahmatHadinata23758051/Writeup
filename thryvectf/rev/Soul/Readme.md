# Soul

## Ringkasan

File utama adalah ELF 64-bit stripped yang berisi VM dispatcher kecil. Program tidak membaca `stdin`, melainkan menerima **satu argumen sepanjang 32 karakter hexadecimal**.

Argumen tersebut diparse menjadi 16 byte key. Key kemudian digunakan untuk validasi VM dan, apabila valid, untuk melakukan XOR-decrypt terhadap buffer flag.

Key yang valid:

```text id="w2x6mz"
4ba317f09c2e886135d47a0fc1563be9
```

Dengan key tersebut, binary mengeluarkan:

```text id="j8p3e1"
Thryve{0n3_7h1n9_4b0u7_m3_15_1_h47e_vm_d15p47ch3r5}
```

## File Challenge

Arsip asli bernama:

```text id="e9m6y4"
soul.7z
```

Tool `7z` tidak tersedia pada environment, sehingga arsip dianalisis secara manual.

Temuan penting:

* Signature 7z valid: `37 7a bc af 27 1c`
* `NextHeader` berada pada offset `0x17b5`
* Header terkompresi menggunakan LZMA raw dengan properti `5d 00 00 80 00`
* Payload utama berhasil didekompresi menjadi ELF `soul_dispatch`

Hasil `file`:

```text id="g6v1kx"
soul_dispatch: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

## Analisis Awal

`strings` hanya memberikan beberapa petunjuk:

```text id="5s4f9q"
nope :3
%02x
ACCESS GRANTED
```

Import penting yang ditemukan:

```text id="c2v7mp"
__isoc23_sscanf
strlen
puts
```

Dari `main`, program memeriksa panjang argumen:

```asm id="x6q9r0"
cmp rax, 0x20
jne nope
```

Artinya input harus memiliki panjang tepat **32 karakter**.

Setelah itu, setiap dua karakter diparse menggunakan format `%02x`, sehingga 32 karakter hexadecimal berubah menjadi:

```text id="d3q1pz"
32 / 2 = 16 byte
```

Byte tersebut kemudian menjadi key yang digunakan oleh VM.

## Analisis Static

Program terlebih dahulu mengisi tabel dispatcher sebanyak 256 entry. Sebagian besar opcode diarahkan ke handler default yang menghentikan VM, sedangkan opcode tertentu diarahkan ke handler asli.

Opcode penting yang digunakan VM:

```text id="k5w8x2"
0x42 = movi reg, imm8
0xd8 = xor  reg, imm8
0x17 = mov  dst, src
0x93 = add  dst, src
0xa5 = sub  dst, src
0x2c = xor  dst, src
0x0a = cmpeq dst, src
0x7e = jmp  imm16
0x8c = jz   reg, imm16
0x55 = jnz  reg, imm16
0x3e = load reg, [addr]
0x6b = store reg, [addr]
0xf1 = loadidx  dst, index_reg, [base]
0xe5 = storeidx src, index_reg, [base]
0xff = halt
```

### Dekode Bytecode

Bytecode VM tidak disimpan secara plaintext.

Setiap byte program pada `.rodata` didekode berdasarkan posisi `PC` menggunakan keystream berikut:

```text id="p1z5f8"
x = pc * 0x9e3779b97f4a7c15
x ^= 0xdeadbeef13371337
x ^= x >> 16
x *= 0x45d9f3b37d3aff67
x ^= x >> 16
x *= 0x45d9f3b37d3aff67
x ^= x >> 16

plain_byte = encrypted_byte ^ (x & 0xff)
```

Dengan membalik proses tersebut, instruksi VM dapat direkonstruksi dan dianalisis secara statis.

### Layout State VM

State VM memiliki beberapa bagian penting:

```text id="c8h4s6"
state[0x00..0x0f]   = 16 register byte
state[0x10..0x1f]   = input key
state[0x30..0x12f]  = S-box 256 byte dari .rodata:0x3880
state[0x130..]      = encrypted flag dari .rodata:0x3020
state[0x210]        = PC
state[0x214]        = halt flag
state[0x20f]        = success flag / memory[0x1ff]
```

Struktur tersebut menunjukkan bahwa key tidak hanya digunakan sebagai password sederhana, tetapi benar-benar menjadi input dari transformasi VM.

## Analisis Dynamic

Key kosong atau key sembarang akan gagal.

Contoh:

```bash id="n8w3f5"
./soul_dispatch 00000000000000000000000000000000
```

Output:

```text id="p6x2w1"
nope :3
```

Setelah key yang benar ditemukan, binary dapat memvalidasi dirinya sendiri:

```bash id="m9q4c7"
./soul_dispatch 4ba317f09c2e886135d47a0fc1563be9
```

Output:

```text id="r3v7k2"
ACCESS GRANTED
Thryve{0n3_7h1n9_4b0u7_m3_15_1_h47e_vm_d15p47ch3r5}
```

Hal ini mengonfirmasi bahwa key hasil reversing valid.

## Algoritma Validasi

VM melakukan transformasi terhadap 16 byte key selama **8 ronde**.

Setiap ronde terdiri dari beberapa operasi utama:

1. XOR register dengan konstanta ronde.
2. Substitusi setiap byte menggunakan S-box 256 byte.
3. Melakukan permutasi register dengan pola tetap.
4. Melakukan ADD berantai dari `r1` hingga `r15`.

Setelah delapan ronde selesai, program menghitung accumulator akhir menggunakan konstanta:

```text id="e2c6k8"
2a9f025450edb9268f30a14f1cbd29df
```

Jika accumulator menghasilkan `0`, VM mengambil jalur sukses.

### Dekripsi Flag

Blok sukses melakukan XOR terhadap buffer flag sepanjang `0x33` byte menggunakan key 16 byte secara berulang.

Encrypted flag berada di `.rodata:0x3020`:

```text id="f5m2n8"
1fcb6589ea4bf3515be72538a96755d0149775c0e919d70c068b4b3a9e6764817f9472afea43d70504e10a3bf63553da39966a
```

Proses dekripsinya sederhana:

```text id="j1q9v3"
plaintext[i] = cipher[i] ^ key[i % 16]
```

Setelah dekripsi berhasil, VM menyimpan nilai `1` ke `memory[0x1ff]`.

`main` kemudian mengecek byte tersebut. Jika nilainya `1`, program mencetak buffer flag melalui `puts`.

## Penyusunan Solve Script

`solve.py` melakukan proses berikut:

1. Membaca binary `soul_dispatch`.
2. Mengambil S-box dari `.rodata`.
3. Mengambil encrypted flag dari `.rodata`.
4. Mereplikasi validasi VM dalam Python.
5. Menemukan key yang memenuhi kondisi accumulator.
6. Melakukan XOR-decrypt terhadap encrypted flag menggunakan key tersebut.
7. Mencetak flag hasil dekripsi.

Solver tidak membutuhkan library eksternal.

## Cara Menjalankan

Dari folder challenge:

```bash id="q7x3m1"
cd /mnt/data/soul_challenge
python3 solve.py
```

Output:

```text id="h4k8v2"
key: 4ba317f09c2e886135d47a0fc1563be9
Thryve{0n3_7h1n9_4b0u7_m3_15_1_h47e_vm_d15p47ch3r5}
```

Hasil tersebut kemudian dapat diverifikasi langsung menggunakan binary:

```bash id="s3n6w9"
./soul_dispatch 4ba317f09c2e886135d47a0fc1563be9
```

Binary memberikan:

```text id="a5r2c7"
ACCESS GRANTED
Thryve{0n3_7h1n9_4b0u7_m3_15_1_h47e_vm_d15p47ch3r5}
```

## Flag

```text id="v8m4q1"
Thryve{0n3_7h1n9_4b0u7_m3_15_1_h47e_vm_d15p47ch3r5}
```
