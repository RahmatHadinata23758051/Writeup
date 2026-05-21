# rev/polaroid

Challenge ini kasih binary `Mach-O 64-bit arm64`, jadi di Linux paling cepat dianalisis secara statis tanpa repot nyari runtime macOS.

## Ringkasan solusi

1. Enumerasi awal pakai `file`, `strings`, dan `rabin2`.
2. Dari `strings` langsung kelihatan ada output `flag.png` dan teks `developed flag.png`.
3. Disassembly `main` menunjukkan password dicek byte per byte dan ternyata hardcoded sebagai:

```text
exposeTheNegative
```

4. Setelah password cocok, binary membuka `flag.png`, lalu melakukan loop XOR:

```c
output[i] = encrypted[i] ^ password[i % 17];
```

5. Blob `encrypted` ada di section `__TEXT.__const`, mulai offset `0x720` dengan ukuran `0x18b4`.
6. Setelah blob didekripsi, hasilnya valid PNG.
7. Gambar hasil dekripsi posisinya terbalik. Setelah diputar 180 derajat, flag terbaca jelas:

```text
tjctf{develop_the_picture}
```

## Detail reversing

Potongan penting dari `main`:

- `strlen(argv[1]) == 0x11`
- karakter password dicek satu-satu menjadi `exposeTheNegative`
- loop dekripsi:

```text
ldrb  w8, [x24, x21]        ; encrypted[i]
...
sub   w9, w21, w9           ; i % 17
ldrsb w9, [x19, x9]         ; password[i % 17]
eor   w0, w9, w8            ; decrypted byte
bl    sym.imp.fputc
```

Trik pembagian di assembly cuma cara compiler menghitung modulo 17 tanpa instruksi division yang mahal.

## Solve script

`solve.py` membaca binary langsung, mengambil blob terenkripsi dari offset yang benar, XOR dengan key `exposeTheNegative`, lalu menulis `flag.png`.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output akhirnya:

```text
tjctf{develop_the_picture}
```
