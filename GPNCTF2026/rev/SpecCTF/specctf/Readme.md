# SpecCTF Writeup

Flag:

```text
GPNCTF{thIs_MEal_IS_5p3cUlATiv31Y_DeLic1ous!!!!}
```

## Ringkasan

Binary `specCTF` adalah ELF 64-bit PIE C++ yang tidak stripped. Program menerima argumen command line, panjangnya harus kelipatan 8, lalu memeriksa input per blok `uint64_t`.

Output yang terlihat hanya `NOPE` atau `CORRECT`, tetapi pembandingnya sengaja dibuat aneh memakai pola Spectre/cache-timing. Setelah disassembly, bagian side-channel itu tidak perlu dijalankan sebagai oracle karena logika sebenarnya tetap terlihat jelas.

## Analisis

Di `main`, setiap 8 byte input dimuat ke register `r14`, lalu nilai target dari global `ENC` dimuat ke `r15`.

Potongan pentingnya:

- `ENC[i]` dimuat sebagai qword ke `r15`
- `input[i:i+8]` dimuat sebagai qword little-endian ke `r14`
- fungsi `specte_byte(0x1337, 0x1337)` dipakai untuk menentukan apakah blok benar

Fungsi `specte_byte` melakukan klasifikasi timing berdasarkan fungsi `specEnvTime`. Di fungsi itu ada kondisi inti:

```c
if (hashy(r14) == r15) {
    touch arr2[0x2800];
} else {
    touch arr2[0xa200];
}
```

Jadi validasi sebenarnya adalah:

```text
hashy(input_qword) == ENC[i]
```

Fungsi `hashy`:

```c
x ^= x >> 33;
x *= 0xf451af975d152cad;
x ^= x >> 33;
x ^= 0xc2ceaade1a351c23;
x ^= x >> 33;
```

Semua operasi di atas reversible modulo 2^64:

- `x ^= x >> 33` bisa dibalik karena shift lebih dari setengah ukuran word
- perkalian bisa dibalik karena konstanta ganjil punya modular inverse modulo 2^64
- xor konstanta tinggal di-xor ulang

`ENC` berukuran 56 byte, tetapi qword terakhir bernilai nol. Program hanya memeriksa sebanyak `strlen(input) / 8` blok dan tidak memaksa semua elemen `ENC` dipakai. Enam qword non-zero pertama sudah menghasilkan flag lengkap sepanjang 48 byte.

## Eksploitasi

Solver membalik `hashy` untuk setiap qword `ENC`, lalu menyusun kembali hasilnya sebagai little-endian bytes.

Validasi lokal:

```text
$ python3 solve.py
GPNCTF{thIs_MEal_IS_5p3cUlATiv31Y_DeLic1ous!!!!}
CORRECT
```
