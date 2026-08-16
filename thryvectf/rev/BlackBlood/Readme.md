# Black Blood

## Ringkasan

File challenge diberikan sebagai `pekaboo.7z`. Isi arsipnya adalah ELF 64-bit PIE yang section header-nya telah dihapus.

Program meminta **13 jawaban**, dengan setiap jawaban harus memiliki panjang tepat **13 byte**. Prompt yang ditampilkan terlihat acak, tetapi validasinya bersifat invariant: jawaban yang benar untuk seluruh ronde ternyata sama.

Jawaban 13 byte yang valid adalah:

```text id="q8z6a2"
give me blood
```

Setelah jawaban tersebut dikirim sebanyak 13 kali, binary mendekripsi pesan akhir dan mencetak:

```text id="5t0p5u"
Thryve{Th3_Bl00d_1s_bl2ck}
```

Karena format flag challenge menggunakan `ThryveCTF{}`, maka flag final adalah:

```text id="m6cv4h"
ThryveCTF{Th3_Bl00d_1s_bl2ck}
```

## File Challenge

File awal:

```text id="h6ubv4"
pekaboo.7z
```

Arsip tidak diekstrak menggunakan executable `7z` eksternal. Format 7z yang digunakan menyimpan payload sebagai raw LZMA1 stream mulai dari offset `0x20`.

Script solver menggunakan modul bawaan Python `lzma` untuk mendekompresi payload.

Hasil ekstraksi:

```text id="2z4t5v"
payload.bin: ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, no section header
```

Informasi ELF penting:

```text id="x22zpk"
Type: DYN (PIE)
Entry point: 0x3290
Program headers: 13
Section headers: 0
```

## Analisis Awal

Walaupun section header ELF telah dihapus, `strings` masih menemukan beberapa string menarik:

```text id="z0x2m7"
license.manifest.result=Thryve{V4nt4C0re_Bl4ckBl00d_L1c3ns3_OK}
license.source=/opt/vantacore/blackblood/enterprise/license_gate.c
[ pekaboo ]
LD_PRELOAD
TracerPid:
~b the-blood-is-bla
```

String:

```text id="g3rj3f"
Thryve{V4nt4C0re_Bl4ckBl00d_L1c3ns3_OK}
```

bukan flag final. String tersebut dikeluarkan melalui mode audit/license dan berfungsi sebagai **decoy**.

Ketika binary dijalankan secara normal, program menampilkan:

```text id="1zq4x4"
[ pekaboo ]
Every answer is wrong. The ritual is invariant.
```

Program kemudian meminta 13 input. Input akan langsung ditolak apabila panjang sebelum newline bukan tepat 13 byte.

## Analisis Static

Karena section header tidak tersedia, proses disassembly dilakukan berdasarkan executable `LOAD` segment, bukan section `.text`.

Entry point mengarah ke startup ELF, sementara fungsi `main` berada di sekitar `0x2310`.

Beberapa fungsi penting yang ditemukan:

```text id="5y6g9m"
0x3380  decode prompt/string terenkripsi
0x3430  compression function mirip BLAKE3/BLAKE2s
0x3bf0  validator/VM per ronde
0x4510  RNG untuk memilih prompt acak
0x45a0  final decrypt dan print pesan akhir
```

Prompt yang ditampilkan kepada user ternyata **tidak menentukan jawaban**. Program memang memilih prompt menggunakan RNG lokal, tetapi validasi setiap ronde menggunakan circuit/VM yang invariant.

### Validator

Validasi input berada di fungsi `0x3bf0`.

Fungsi tersebut menerima beberapa state, antara lain:

```text id="7v1h1f"
round index
input 13 byte
previous state
nilai global hasil constructor
anti-tamper value
```

Dalam kondisi normal, nilai anti-tamper adalah `0`.

Binary juga memiliki sejumlah pengecekan anti-debug ringan, termasuk:

* `/proc/self/status`
* `TracerPid`
* nama parent process
* `LD_PRELOAD`
* `LD_AUDIT`
* `QEMU_LD_PREFIX`
* `VALGRIND_OPTS`

Pengecekan tersebut tidak menjadi inti penyelesaian karena constraint VM dapat direkonstruksi secara statis.

## Analisis Dynamic

Input sembarang menghasilkan status `reject`.

Mode audit/license dapat menghasilkan decoy:

```bash id="ytj4ul"
./payload.bin --license-audit
```

Output dari mode tersebut bukan flag yang digunakan dalam flow utama.

Untuk membuktikan jalur validasi hingga akhir, VM per ronde direkonstruksi dalam Python. Solver kemudian menghasilkan 13 jawaban dan binary dijalankan kembali dengan file input:

```bash id="d3l8w7"
./payload.bin < answer.txt
```

Binary akhirnya mencetak:

```text id="5c9jgj"
Thryve{Th3_Bl00d_1s_bl2ck}
```

Ini merupakan output flag dengan prefix legacy. Setelah disesuaikan dengan format challenge, hasil akhirnya adalah:

```text id="u6k5e9"
ThryveCTF{Th3_Bl00d_1s_bl2ck}
```

## Algoritma Validasi

Setiap ronde menjalankan sebuah VM dengan instruksi yang tersimpan sebagai qword table terenkripsi di sekitar offset `0x6810`.

Dekode instruksi menggunakan seed ronde:

```text id="i9d2qy"
seed = splitmix64(global_14018 ^ prev_state ^ Q[round] ^ ((round + 1) * C_A))
```

Instruksi kemudian didekode menggunakan mask SplitMix64 dan diperiksa melalui checksum 16-bit.

Beberapa opcode yang ditemukan:

```text id="oy6d0a"
0x07  buat mask parity
0x19  hitung parity dari bit input
0x6e  XOR bit constraint dengan tabel byte ronde
0x33  commit constraint ke flags
0x01  update slot VM
0x29  update slot VM dengan splitmix
0x40  rotate/xor slot VM
0xdf  jump relatif
0x55  halt
```

Bagian terpenting adalah interaksi opcode `0x19`, `0x6e`, dan `0x33`.

Ketiganya membentuk persamaan linear **GF(2)** terhadap 104 bit input:

```text id="f4p5az"
13 byte × 8 bit = 104 bit
```

Setiap ronde menghasilkan 104 constraint dengan rank 104, sehingga solusi untuk input bersifat unik.

Solver kemudian menyelesaikan sistem persamaan tersebut menggunakan Gaussian elimination/propagation pada GF(2).

Hasilnya sama pada seluruh ronde:

```text id="t7f5y8"
give me blood
```

### Update State Antar-Ronde

Setelah sebuah ronde berhasil, program memperbarui `prev_state` menggunakan output VM:

```text id="b5t7p9"
prev_state = splitmix64(prev_state ^ out8 ^ Q[round] ^ k)
```

Nilai `k` dimulai dari konstanta golden ratio:

```text id="d2f4cs"
0x9e3779b97f4a7c15
```

dan bertambah dengan konstanta yang sama pada setiap ronde.

Setelah 13 ronde berhasil, fungsi `0x45a0` menggunakan seluruh **169 byte** jawaban beserta state akhir untuk mendekripsi ciphertext final.

Plaintext kemudian diperiksa menggunakan hash internal. Jika hash cocok, pesan akhir dicetak ke stdout.

## Penyusunan Solve Script

`solve.py` melakukan proses berikut:

1. Mengekstrak ELF dari `pekaboo.7z` menggunakan raw LZMA1.
2. Menghitung nilai global yang dihasilkan constructor.
3. Mendekode bytecode VM untuk setiap ronde.
4. Mengubah constraint VM menjadi persamaan linear GF(2).
5. Menyelesaikan 104 bit input pada setiap ronde.
6. Menulis hasil ke `answer.txt`.
7. Menjalankan `payload.bin < answer.txt` untuk memverifikasi flag dari binary.

## Cara Menjalankan

Dari folder challenge:

```bash id="l8l6t0"
python3 solve.py
```

Output penting solver:

```text id="d5l9oj"
Recovered 13 answers:
01: give me blood
02: give me blood
03: give me blood
04: give me blood
05: give me blood
06: give me blood
07: give me blood
08: give me blood
09: give me blood
10: give me blood
11: give me blood
12: give me blood
13: give me blood

Binary output flag: Thryve{Th3_Bl00d_1s_bl2ck}
Challenge-format flag: ThryveCTF{Th3_Bl00d_1s_bl2ck}
```

## Flag

```text id="m9y6h1"
ThryveCTF{Th3_Bl00d_1s_bl2ck}
```
