# Circuit Challenge — Writeup

## Ringkasan

Gambar awal menyimpan URL pada **bit paling signifikan channel merah**, bukan pada metadata atau LSB biasa. URL tersebut membuka folder Drive berisi hint dan `inputsequence.b`.

Circuit transistor pada gambar bisa disederhanakan menjadi dua operasi Boolean:

```text
nx_j  = neg_i XOR x_j
PP_ij = ot_i ? nx_j : nx_{j-1}
```

Karena hint menetapkan `zero_i = 0`, transistor clamp pada output tidak aktif. Setiap delapan vektor menghasilkan satu byte ASCII. Hasil akhirnya:

```text
bronco{ov2hhU6mBY}
```

## 1. Ekstraksi link dari gambar

`Challenge.png` terlihat seperti potongan tabel perbandingan rangkaian Radix-4 Booth. Tidak ada chunk teks PNG atau data append yang berguna. Payload justru ditanam pada red-channel bit plane.

Untuk setiap pixel secara row-major, ambil bit ke-7 dari nilai merah:

```python
bit = (red >> 7) & 1
```

Setiap delapan bit kemudian dipaketkan dengan urutan MSB-first. Byte printable pada awal stream membentuk:

```text
https://tinyurl.com/hnexnehb
```

Link tersebut mengarah ke folder Drive yang memuat:

- `hintstable.txt`
- `inputsequence.b`

Hint memberi urutan satu vektor 4-bit:

```text
MSB                                      LSB
neg_i | x_j | nx_{j-1} | ot_i
```

Hint juga menyebutkan bahwa `zero_i` selalu bernilai nol.

## 2. Menyederhanakan circuit

### Jaringan CMOS kiri

Dua cabang pull-up aktif ketika input berbeda:

```text
neg_i = 0, x_j = 1
neg_i = 1, x_j = 0
```

Dua cabang pull-down aktif ketika input sama:

```text
neg_i = 0, x_j = 0
neg_i = 1, x_j = 1
```

Node `nx_j` berarti:

```text
nx_j = neg_i XOR x_j
```

### Transmission-gate multiplexer

Dua transmission gate di sisi kanan memilih sumber output berdasarkan `ot_i`:

```text
ot_i = 0  -> pilih nx_{j-1}
ot_i = 1  -> pilih nx_j
```

Maka:

```text
PP_ij = ot_i ? (neg_i XOR x_j) : nx_{j-1}
```

Secara ekuivalen dalam SystemVerilog:

```systemverilog
module partial_product (
    input  logic zero_i,
    input  logic neg_i,
    input  logic x_j,
    input  logic nx_j_minus_1,
    input  logic ot_i,
    output logic pp_ij
);
    logic nx_j;

    assign nx_j  = neg_i ^ x_j;
    assign pp_ij = zero_i ? 1'b0
                          : (ot_i ? nx_j : nx_j_minus_1);
endmodule
```

## 3. Decode `inputsequence.b`

File memiliki 18 baris. Tiap baris berisi delapan vektor 4-bit, sehingga setiap baris menghasilkan delapan output circuit atau satu byte.

Contoh baris pertama:

```text
0000 1110 1110 0000 0000 0000 1110 0000
```

Evaluasi circuit:

```text
0000 -> 0
1110 -> 1
1110 -> 1
0000 -> 0
0000 -> 0
0000 -> 0
1110 -> 1
0000 -> 0
```

Gabungan output:

```text
01100010 = 0x62 = 'b'
```

Proses yang sama diterapkan ke seluruh baris:

```text
01100010 -> b
01110010 -> r
01101111 -> o
01101110 -> n
01100011 -> c
01101111 -> o
01111011 -> {
01101111 -> o
01110110 -> v
00110010 -> 2
01101000 -> h
01101000 -> h
01010101 -> U
00110110 -> 6
01101101 -> m
01000010 -> B
01011001 -> Y
01111101 -> }
```

## 4. Solver otomatis

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py --image Challenge.png --input inputsequence.b
```

Output:

```text
[+] Embedded URL : https://tinyurl.com/hnexnehb
[+] Decoded bytes: 18
<FLAG>bronco{ov2hhU6mBY}</FLAG>
```

Solver juga dapat dijalankan tanpa gambar setelah `inputsequence.b` diperoleh:

```bash
python3 solve.py --skip-image --input inputsequence.b
```

## Flag

```text
bronco{ov2hhU6mBY}
```
