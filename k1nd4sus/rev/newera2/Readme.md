# New Era (Part 2) - Writeup

Challenge ini memberi satu file RF capture `intercepted_signal.iq` dan petunjuk bahwa parameter fisik tetap sama: **8 samples per symbol**.

## 1) Enumerasi awal
Cek isi folder:
- hanya ada `intercepted_signal.iq`

Cek struktur datanya:
- file berisi `float32` IQ interleaved
- channel `Q` semuanya `0`
- channel `I` hanya dua level: `+1` dan `-1`

Artinya modulasi yang dipakai sangat sederhana (2-level), jadi kita bisa langsung threshold per simbol.

## 2) Demodulasi dasar
Langkah demod:
1. Baca `float32`
2. Ambil komponen `I` (`raw[0::2]`)
3. Kelompokkan setiap 8 sample sebagai 1 simbol
4. Rata-rata simbol > 0 => bit `1`, selain itu bit `0`

Hasilnya dapat 392 bit.

## 3) Kenapa tidak langsung jadi ASCII
Di Part 1, bitstream langsung bisa dipack jadi byte ASCII.
Di Part 2, kalau langsung dipack, output acak. Berarti ada layer encoding tambahan dari firmware update.

## 4) Identifikasi skema baru
Karena hint tidak ada dan pola RF bersih, dicoba beberapa kemungkinan transform (invert, differential, dsb) dan tidak valid.

Lalu diuji asumsi **FEC Hamming(7,4)**:
- pecah bitstream menjadi blok 7 bit (codeword)
- hitung syndrome (`s1,s2,s4`) untuk koreksi 1-bit error
- ambil data bit di posisi (3,5,6,7)
- gabungkan 2 nibble jadi 1 byte

Begitu decode Hamming(7,4) diterapkan, plaintext langsung terbaca jelas:

`KSUS{h4mm1ng_c0d3s_4r3_c00l}`

## 5) Solver final
Solver otomatis disimpan di file:
- `solve.py`

Cara pakai:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py -i intercepted_signal.iq
```

Output:

```text
KSUS{h4mm1ng_c0d3s_4r3_c00l}
```

## Flag
`KSUS{h4mm1ng_c0d3s_4r3_c00l}`
