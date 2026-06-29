# Atari 2600

File yang dikasih adalah ROM Atari 2600 ukuran 4 KiB. Reset vector di akhir ROM mengarah ke `$F000`, jadi offset file `0x0000` dipetakan ke alamat CPU `$F000`.

Bagian game logic utamanya ada setelah inisialisasi. Saat status `D6` aktif, kode memanggil routine `$F562` satu kali. Routine ini bukan enkripsi berat, tapi rangkaian instruksi hasil compile batari Basic untuk menggambar pixel playfield.

Pola instruksinya berulang seperti ini:

```asm
LDX #$00      ; mode set pixel
LDY #row
LDA #col
JSR $F278     ; plot(col, row)
```

Target `$F278` masuk ke helper plot playfield. Nilai `A` dipakai sebagai koordinat X, `Y` sebagai koordinat Y, dan `X = 0` berarti set pixel. Jadi semua koordinat flag bisa diekstrak otomatis dari ROM tanpa main manual di emulator.

Script mencari pola byte berikut:

```text
A2 00 A0 <row> A9 <col> 20 78 F2
```

Dari pola itu didapat bitmap playfield:

```text
█ █  █  ███  ██ ███     ███ ██
█ █ ██   █  ██  █ █     █ █  ██
 █   █   █   ██ ███ ███ ███ ██

███ █   ███ ███  ██ ███ ███ ███
███ █   ███ ███ ███ ███ ██  ███
███ █   ███ ███ ███ ███ ███ ██
```

Tiga baris atas memakai font 3x3 dengan jarak 1 kolom. Setelah dipecah per glyph, hasilnya:

```text
V 1 T { O _ O }
```

Flag:

```text
V1T{O_O}
```

## Run

```bash
python3 solve.py v1t.bas.bin
```

Output:

```text
[+] Decoded top bitmap text: V1T{O_O}
<FLAG>V1T{O_O}</FLAG>
```
