# Consistently Static Psuedo Random Number Generator

## Deskripsi

> I made a birthday oracle recently, but I can't get it to work at all. It only gets the day of the week right 14% of the time!
>
> Here are my results from the last testing session... can you take a look at it and see what's wrong?

File yang diberikan berisi source generator dan 101 keluaran oracle. State RNG diisi langsung dengan byte flag, jadi targetnya bukan memprediksi tanggal lahir, tetapi membalik proses update state sampai byte awalnya kembali.

## Analisis oracle

Setiap output `guess` tidak dicetak sebagai angka. Nilainya dipecah menjadi tiga indeks:

```python
month = months[guess % 12]
day   = days[guess % 7]
area  = areas[guess % 5]
```

Artinya satu baris transcript membocorkan:

```text
guess mod 12
guess mod 7
guess mod 5
```

Modulus `12`, `7`, dan `5` saling koprima, dengan hasil kali `420`. Karena `guess` selalu satu byte (`0..255`), setiap kombinasi month/day/area menunjuk ke tepat satu nilai.

Contoh baris pertama:

```text
October, Saturday, the Americas
```

Indeksnya:

```text
October      -> 9 mod 12
Saturday     -> 5 mod 7
the Americas -> 2 mod 5
```

Brute force pada rentang byte menghasilkan:

```text
guess = 117
```

Proses yang sama pada seluruh transcript menghasilkan 101 byte output RNG.

## Membalik update state

Misalkan:

- `a_t` adalah output pada iterasi ke-`t`
- `x_t` adalah byte lama yang ditimpa pada iterasi tersebut

Source melakukan:

```python
a = sum(state) % 256
state[schedule[index]] = a
```

Sesudah `x_t` diganti menjadi `a_t`, jumlah state berikutnya adalah:

```text
a_(t+1) = a_t - x_t + a_t mod 256
          = 2a_t - x_t mod 256
```

Jadi byte lama dapat dihitung langsung:

```text
x_t = 2a_t - a_(t+1) mod 256
```

Selama satu putaran schedule, setiap posisi state ditimpa tepat sekali. Maka `x_0` sampai `x_(n-1)` adalah seluruh byte flag asli, hanya urutannya mengikuti schedule acak.

## Menentukan panjang state

Setelah schedule mengulang, posisi yang ditimpa pada iterasi `t+n` sebelumnya berisi `a_t`. Relasinya menjadi:

```text
a_(t+n+1) = 2a_(t+n) - a_t mod 256
```

Solver mencoba seluruh kandidat `n` dan memvalidasi relasi itu ke semua output yang tersedia. Hanya satu nilai yang cocok:

```text
n = 34
```

## Mengembalikan urutan flag

Schedule dibuat dengan dua operasi:

1. rotasi `range(n)`
2. kemungkinan membalik seluruh schedule

Byte awal yang didapat dalam urutan schedule adalah:

```text
1_0tpyrc{ocnorb\n}ni4tr3c_4_3ruce5n
```

Solver mencoba seluruh rotasi dan dua arah schedule. Kombinasi yang benar:

```text
shift    = 15
reversed = True
```

State awalnya menjadi:

```text
bronco{crypt0_1n5ecur3_4_c3rt4in}\n
```

Newline berasal dari `flag.txt` dan bukan bagian flag.

## Solver

Jalankan:

```bash
python3 solve.py result.txt
```

Output:

```text
[+] outputs parsed : 101
[+] state length   : 34
[+] schedule shift : 15
[+] reversed       : True
<FLAG>bronco{crypt0_1n5ecur3_4_c3rt4in}</FLAG>
```

## Flag

```text
bronco{crypt0_1n5ecur3_4_c3rt4in}
```
