# Faultline - Writeup

## Ringkasan Challenge
Binary `faultline` adalah ELF 64-bit statically linked dan punya beberapa subcommand:

- `score <PROFILE>`
- `trace <PROFILE>`
- `token <PROFILE>`
- `submit <PROFILE> <TOKEN>`
- `nudge <PROFILE> <INDEX> <DELTA>`
- `compare <PROFILE_A> <PROFILE_B>`

Dari usage terlihat:

- Alphabet profile: `BCDFGHJKLMNPQRST` (16 karakter)
- Panjang profile: 12
- Benchmark historis: 2026

Petunjuk di `notes` menjelaskan ada 3 family constraint (`stress`, `shear`, `grain`) + `load` + `seal`.

## Enumerasi Awal
Tes input valid termudah:

- `BBBBBBBBBBBB` valid (karena `B` ada di alphabet)
- `trace BBB...` memberi semua nol
- `score BBB...` memberi `-1038`

Ini ngasih indikasi nilai internal profile adalah indeks karakter (0..15), dengan `B=0`.

## Reverse Engineering
Dari simbol fungsi yang masih ada di binary:

- `parseProfile`
- `stressTrace`
- `shearTrace`
- `grainTrace`
- `loadMetric`
- `sealMetric`
- `computeFaultlineScoreVisible`
- `buildSurveyTokenVisible`

Konversi profile jelas: setiap karakter dicari index-nya di alphabet `BCDFGHJKLMNPQRST`.

### Formula yang didapat
Misal profile diubah jadi array `a[0..11]` (tiap elemen 0..15):

1. Stress (11 nilai)

`stress[i] = (2*a[i] + 3*a[i+1]) & 0xf`

2. Shear (10 nilai)

`shear[i] = a[i] ^ a[i+2]`

3. Grain (9 nilai)

`grain[i] = (a[i] + a[i+3] - a[i+1]) & 0xf`

4. Load

`load = sum(a[i])`

5. Seal

`seal = (sum((i+5)*a[i])) & 0xf`

Array observasi (`OBS_*`) hardcoded di `.rodata`:

- `OBS_STRESS = [2,5,11,10,5,1,13,4,3,3,14]`
- `OBS_SHEAR  = [5,5,15,8,5,6,7,4,5,5]`
- `OBS_GRAIN  = [3,11,3,4,14,4,5,6,1]`
- target `load = 93`
- target `seal = 9`

`computeFaultlineScoreVisible` memberi bonus maksimal saat semua cocok persis; nilai maksimum tepat jadi `2026`.

## Cara Solve
Kunci paling enak dipakai: persamaan shear.

Dari `shear[i] = a[i] ^ a[i+2]` =>

`a[i+2] = a[i] ^ OBS_SHEAR[i]`

Artinya cukup brute-force `a0` dan `a1` (16x16 = 256 kemungkinan), sisanya terbangun deterministik. Setelah itu tinggal filter dengan stress + grain + load + seal.

Hasil unik:

`[14, 2, 11, 7, 4, 15, 1, 9, 6, 13, 3, 8]`

Mapping ke alphabet `BCDFGHJKLMNPQRST` menghasilkan profile:

`SDPKGTCMJRFL`

Validasi:

- `./faultline score SDPKGTCMJRFL` -> `2026 (catastrophic resonance lock)`
- `./faultline token SDPKGTCMJRFL` -> `Z2L-2F5-BUBP`
- `./faultline submit SDPKGTCMJRFL Z2L-2F5-BUBP` -> `CIT{12z4PXVTa3x3}`

## Flag

`CIT{12z4PXVTa3x3}`

## Solver
Script final ada di `solve.py`.
Jalankan:

```bash
python3 solve.py
```

Script akan:

1. Cari profile dari constraint
2. Cek skor
3. Ambil token
4. Submit dan print flag
