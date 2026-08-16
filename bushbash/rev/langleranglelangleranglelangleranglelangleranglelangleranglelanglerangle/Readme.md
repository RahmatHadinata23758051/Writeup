# \\langle\\rangle\\langle\\rangle\\langle\\rangle\\langle\\rangle\\langle\\rangle\\langle\\rangle

## Ringkasan

File C++ tidak membaca input. Ia memakai template metaprogramming sebagai interpreter saat kompilasi untuk mengenkripsi 18 byte yang diletakkan pada alias `KVRP`.

## File Challenge

- `main.cpp`: mencetak hasil kalkulasi compile-time.
- `<><><><><><>.hpp`: interpreter template, key, slot plaintext, dan array `output`.

## Analisis Awal

Kedua artefak adalah source ASCII. `main.cpp` mencetak `output`, sedangkan header memuat key sebagai `GEUE` dan komentar pada `KVRP`: `This is where the flag should go if you were encrypting it.`

## Analisis Static

`IDXV<N>` menyimpan integer sebagai type. `OWRC` adalah linked list dan `TWDL` mengambil elemen list berdasarkan indeks. `CWCE` menjalankan instruksi-instruksi encoded sebagai type:

- `JLLV` menyimpan nilai ke variabel.
- `HPFP<..., 16>` mengulang blok internal sebanyak 16 kali.
- `HPFP<..., 9>` memproses sembilan pasangan byte.
- `QVTC`, `EPMS`, `KZRJ`, dan `RCOB` masing-masing adalah XOR, tambah, kali, dan modulo.

Di blok 16 ronde, `SMSW` dihitung sebagai `key[i] * WVTF + WVTF`, lalu `ZCHU` menghasilkan:

```text
F(R) = ((R + (key[i] * state + state)) * 17) % 135
```

Instruksi berikutnya menulis `RLGL = FNHJ` dan `FNHJ = RLGL_lama XOR F(R)`, sehingga satu ronde adalah Feistel:

```text
(L, R) -> (R, L XOR F(R))
```

Setelah 16 ronde, `state` (`WVTF`) ditambah `L + R`. State awalnya `1`. Ciphertext dikumpulkan pada `AXEK` dan urutan `BCAD<17>` hingga `BCAD<0>` membuatnya kembali ke urutan pasangan asli.

## Analisis Dynamic

Mengompilasi source dengan `g++ -std=c++17 -O2 main.cpp` saat `KVRP` berisi nol menghasilkan awalan output `86,144,...`. Simulasi forward dari ronde di atas untuk pasangan nol dan state `1` menghasilkan pasangan awal yang sama. Semua ciphertext challenge juga direproduksi oleh verifikasi dalam solver.

## Algoritma Validasi atau Encoding

Untuk membalik ronde Feistel, ciphertext `(L', R')` diproses dengan key terbalik:

```text
(L, R) = (R' XOR F(L'), L')
```

State untuk pasangan berikutnya tetap memakai ciphertext yang baru selesai diproses, yaitu `state += L' + R'`.

## Penyusunan Solve Script

`solve.py` membalik setiap pasangan ciphertext, menyusun 18 byte plaintext, lalu mengenkripsi ulang hasilnya. Assertion memastikan ciphertext hasil enkripsi ulang identik dengan array challenge.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

## Flag

```text
ma5B3_sf1NAe_neXt?
```

## Catatan

Tidak ada aktivitas network atau artefak di luar direktori challenge. Flag diperoleh dari inversi algoritma yang sama dan diverifikasi dengan enkripsi ulang.
