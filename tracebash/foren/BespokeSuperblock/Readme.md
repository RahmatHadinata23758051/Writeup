# Bespoke Superblock

Flag: `TBCTF{spat1al_aware_xor_1337}`

File yang dikasih cuma dua:
- `challenge.img`
- `parser.py`

`file challenge.img` ngasih hasil aneh karena header depan dibikin mirip DOS boot sector. Tapi `strings` langsung bocorin petunjuk:

- `NOTICE: Custom Filesystem starts at offset 0x1000. Use parser.py for recovery.`
- `TBFS`

Dari sini fokus pindah ke offset `0x1000` dan isi `parser.py`.

## Analisis

`parser.py` nunjukin format superblock custom:
- offset filesystem: `0x1000`
- header 16 byte
- format: `Magic (4s), BlockSize (H), TotalBlocks (I), FlagInode (I)`

Saat dibaca, nilainya:
- magic: `TBFS`
- block size: `512`
- total blocks: `8`
- flag inode / start data: `0x1020`

Script recovery di `parser.py` baca 4 byte pertama dari tiap block:
- block 0 -> `tbct`
- block 1 -> `f[SP`
- block 2 -> `AT\x11A`
- block 3 -> `L\x7fAW`
- block 4 -> `ARE\x7f`
- block 5 -> `XOR\x7f`
- block 6 -> `\x11\x13\x13\x17`
- block 7 -> `]   `

Kalau digabung, hasil raw:

`tbctf[SPAT\x11AL\x7fAWARE\x7fXOR\x7f\x11\x13\x13\x17]   `

Bagian ini jelas belum final. Petunjuk di source juga bilang ada entropy tinggi dan kemungkinan ada layer encoding tambahan.

Karena banyak byte kelihatan seperti karakter printable yang digeser, cara paling cepat adalah brute-force XOR 1 byte ke seluruh hasil gabungan.

XOR key `0x20` langsung ngasih string valid:

`TBCTF{spat1al_aware_xor_1337}`

## Langkah solve

1. Identifikasi file dan baca string petunjuk.
2. Buka `parser.py` untuk paham struktur data.
3. Parse superblock di offset `0x1000`.
4. Ambil 4 byte pertama dari masing-masing 8 block mulai `0x1020`, lompat per `512` byte.
5. Gabungkan semua chunk.
6. XOR hasil gabungan dengan `0x20`.
7. Dapat flag.

## Command penting

Cek artefak:

```bash
file challenge.img
strings -a challenge.img | head
xxd -g 1 -s 0x1000 -l 256 challenge.img
python3 parser.py challenge.img
```

Bruteforce XOR:

```bash
python3 - <<'PY'
raw=b'tbctf[SPAT\x11AL\x7fAWARE\x7fXOR\x7f\x11\x13\x13\x17]   '
for k in range(256):
    dec=bytes(b^k for b in raw)
    if b'TBCTF{' in dec:
        print(k, dec)
PY
```

Output:

```text
32 b'TBCTF{spat1al_aware_xor_1337}\x00\x00\x00'
```

## Inti bug / trik challenge

Format file palsu di depan dipakai buat ngecoh tool biasa.
Data flag tidak disimpan kontigu. Tiap chunk disebar ke awal block berbeda.
Hasil gabungan juga masih di-XOR satu byte (`0x20`), jadi parser bawaan cuma recover data setengah jadi.

## Flag

`TBCTF{spat1al_aware_xor_1337}`
