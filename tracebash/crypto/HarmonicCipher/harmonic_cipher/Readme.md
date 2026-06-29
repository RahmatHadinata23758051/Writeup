# Harmonic Cipher

File yang dikasih cuma dua:

- `melody.wav`
- `ciphertext.bin`

`ciphertext.bin` panjangnya 39 byte, jadi ini kelihatan seperti hasil XOR / stream cipher pendek, bukan blok cipher dengan padding.

`melody.wav` ternyata bukan lagu penuh. Durasi total 8 detik dan tiap 1 detik berisi satu sinus murni. FFT per detik kasih delapan frekuensi ini:

```text
440, 494, 523, 587, 659, 698, 784, 880
```

Itu not `A B C D E F G A`, tapi yang dipakai bukan nama notnya. Clue yang jalan justru angka frekuensinya sendiri.

Kalau setiap frekuensi diambil `mod 256`, key yang keluar:

```text
[184, 238, 11, 75, 147, 186, 16, 112]
```

Dalam hex:

```text
b8ee0b4b93ba1070
```

XOR ciphertext dengan key itu secara repeating menghasilkan plaintext yang langsung valid:

```text
TBCTF{h4rm0n1c_fr3qu3nc13s_4r3_m3l0d1c}
```

Solver final ada di `solve.py`.

Run:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```
