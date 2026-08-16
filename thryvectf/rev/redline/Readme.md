# RedLine

## Ringkasan

`redline` adalah ELF 64-bit yang **statically linked** dan **stripped**. Program menerima input berupa `credential`, mengubah 36 karakter input menjadi bit, kemudian memproses bit tersebut melalui circuit boolean internal.

Hasil circuit terdiri dari 320 bit yang dibandingkan dengan tabel target di `.rodata`.

String flag yang terlihat melalui `strings` hanyalah **decoy**. Flag valid diperoleh dengan melakukan reversing terhadap circuit, bukan dengan mengambil string secara langsung.

**Flag yang benar:**

```text
ThryveCTF{red_black_relays_dont_lie}
```

## File Challenge

```text
redline: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

## Analisis Awal

Ketika dijalankan, program menampilkan:

```text
THRYVE ACCESS RELAY
credential:
relay trace: ...
consensus: REJECTED / ACCEPTED
```

Input kosong atau input dengan panjang yang salah langsung masuk ke jalur `REJECTED` dan menghasilkan trace default berisi `B`.

Untuk input dengan panjang 36 karakter printable, program mengubah setiap karakter menjadi bit dan menghitung trace `R/B` dari sinyal internal.

### String yang Ditemukan

Hasil `strings` memperlihatkan beberapa string penting:

```text
THRYVE ACCESS RELAY
credential:
relay trace:
consensus: REJECTED
ThryveCTF{local_colors_are_not_enough}
ThryveCTF{red_black_decoy_trace}
```

Dua string `ThryveCTF{...}` tersebut merupakan decoy. Ketika dicoba sebagai input ke program, keduanya menghasilkan:

```text
consensus: REJECTED
```

Dengan demikian, string flag yang ada di binary tidak dapat dipercaya sebagai flag valid.

## Analisis Static

Fungsi utama berada di sekitar alamat `0x401780`.

Alur program secara umum adalah:

1. Mencetak banner `THRYVE ACCESS RELAY`.
2. Membaca input ke buffer stack.
3. Menghapus newline.
4. Memastikan panjang input tepat `0x24` atau **36 byte**.
5. Memastikan setiap byte merupakan karakter printable/graphic.
6. Memecah setiap byte menjadi 8 bit dengan urutan **LSB-first**.
7. Menyimpan setiap bit beserta komplemennya ke buffer global `0x4b2b00`.
8. Menjalankan daftar gate dari `.data.rel.ro`, mulai dari `0x4a14a0` dengan panjang `0xb9c0` byte.
9. Membandingkan 320 sinyal hasil circuit dengan target bit yang berada di `0x47ef20`.

Fungsi gate yang digunakan antara lain:

```text
0x401bb0 : NOT
0x401bd0 : XOR
0x401c00 : NAND
0x401c30 : COPY
0x401c60 : runtime noise / random toggle
```

Trace `R/B` yang dicetak program berasal dari indeks di sekitar `0x47ee80`. Namun, trace tersebut hanya merupakan sebagian dari state internal.

Validasi sebenarnya dilakukan terhadap **320 sinyal** yang dimulai dari `0x47ec00`.

## Analisis Dynamic

Beberapa flag decoy dicoba langsung terhadap binary.

### Decoy Pertama

```bash
printf 'ThryveCTF{local_colors_are_not_enough}\n' | ./redline
```

Hasil:

```text
consensus: REJECTED
```

### Decoy Kedua

```bash
printf 'ThryveCTF{red_black_decoy_trace}\n' | ./redline
```

Hasil:

```text
consensus: REJECTED
```

Setelah flag hasil reversing digunakan:

```bash
printf 'ThryveCTF{red_black_relays_dont_lie}\n' | ./redline
```

Program menghasilkan:

```text
consensus: ACCEPTED
```

Hal ini mengonfirmasi bahwa flag tersebut valid.

## Algoritma Validasi

Validasi dilakukan menggunakan sebuah **boolean circuit**.

Input 36 byte menghasilkan:

```text
36 × 8 = 288 bit
```

Circuit kemudian memproses bit tersebut menggunakan sejumlah gate.

Setiap entry gate berukuran 16 byte dan secara konseptual dapat direpresentasikan sebagai:

```c
struct gate {
    uint64_t fn;
    uint16_t a;
    uint16_t b;
    uint16_t c;
};
```

Setiap entry memanggil function pointer gate dengan argumen berupa indeks sinyal.

Gate yang ditemukan mencakup:

* `NOT`
* `XOR`
* `NAND`
* `COPY`
* runtime noise/random toggle

Setelah seluruh circuit dievaluasi, program mengambil 320 output dan membandingkannya dengan target bit yang tersimpan di binary.

Karena output yang divalidasi memiliki scope yang cukup kecil, solver dapat membangun representasi ekspresi/truth table untuk sinyal-sinyal tersebut. Constraint kemudian diselesaikan menggunakan propagation sederhana.

Solver juga memanfaatkan format flag yang diketahui:

```text
ThryveCTF{...}
```

Isi flag dibatasi menggunakan alphabet yang umum digunakan pada CTF, seperti lowercase, digit, dan underscore.

## Penyusunan Solve Script

`solve.py` melakukan beberapa tahap:

1. Membaca binary `redline`.
2. Mengambil daftar gate dari `.data.rel.ro`.
3. Mengambil indeks output validasi dari `0x47ec00`.
4. Mengambil target bit dari `0x47ef20`.
5. Membangun ekspresi boolean dari gate `NOT`, `XOR`, `NAND`, `COPY`, dan noise gate.
6. Membuat constraint agar seluruh 320 output sama dengan target.
7. Menambahkan constraint berdasarkan format flag.
8. Menyelesaikan constraint dan mencetak flag.

## Cara Menjalankan

Dari direktori challenge:

```bash
cd /mnt/data/redline_challenge
chmod +x redline solve.py
./solve.py
```

Output solver:

```text
ThryveCTF{red_black_relays_dont_lie}
```

Kemudian hasil tersebut dapat divalidasi terhadap binary:

```bash
printf '%s\n' "$(./solve.py)" | ./redline
```

Output validasi:

```text
consensus: ACCEPTED
```

## Flag

```text
ThryveCTF{red_black_relays_dont_lie}
```
