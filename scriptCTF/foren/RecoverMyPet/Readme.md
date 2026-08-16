# RecoverMyPet Writeup

## Flag

```text
scriptCTF{w@t_4_cu71e_p@too1$}
```

## Recon

Artifact yang diberikan hanya `images.zip`.

```bash
file images.zip
unzip -l images.zip
```

Hasilnya adalah ZIP biasa yang berisi **36 file PNG**. Semua tile memiliki ukuran yang sama, yaitu `60x60`, sehingga ukurannya cocok untuk disusun menjadi gambar `6 x 6`.

```python
from PIL import Image
from zipfile import ZipFile
from pathlib import Path

with ZipFile("images.zip") as z:
    z.extractall("tiles")

for p in sorted(Path("tiles").glob("*.png"))[:5]:
    im = Image.open(p)
    print(p.name, im.size, im.mode)
```

Nama file memiliki pola seperti:

```text
43_37.png
17_11.png
1_1.png
19_29.png
```

Angka tersebut bukan posisi tile biasa. Jika semua tile langsung ditempel, gambar yang dihasilkan masih acak atau terdistorsi.

## Inti Masalah

Setiap tile diacak menggunakan varian **generalized Arnold Cat Map**. Parameter transformasinya diambil langsung dari nama file.

Untuk tile dengan nama:

```text
a_b.png
```

digunakan transformasi:

```text
x' = x + a*y
y' = b*x + (a*b + 1)*y   mod 60
```

dengan:

* `x` = posisi kolom
* `y` = posisi baris
* `a` dan `b` = angka dari nama file
* `60` = ukuran tile

Karena Arnold Cat Map bersifat periodik, transformasi dapat dibalik setelah sejumlah ronde tertentu.

Recovery satu ronde dilakukan dengan sampling balik:

```text
decoded[y, x] = encoded[y', x']
```

Jumlah ronde berbeda untuk setiap tile. Karena ukuran tile hanya `60x60`, jumlah ronde dapat dicari dengan brute force ringan pada rentang:

```text
0..59
```

Setelah tile berhasil dikembalikan ke bentuk normal, posisi antar-tile dapat ditentukan berdasarkan kontinuitas gambar, terutama bentuk kucing dan tulisan merah.

## Menentukan Susunan Tile

Grid final yang digunakan solver adalah:

```text
43_37  17_11  1_1    19_29  8_5    3_5
41_31  61_53  41_59  9_13   13_9   2_3
23_31  7_4    5_3    13_19  59_41  23_17
19_13  3_2    53_61  2_1    31_23  29_19
7_11   1_2    5_8    29_37  31_41  37_43
4_7    11_7   37_29  17_23  11_17  73_97
```

Beberapa tile background polos terlihat hampir identik, sehingga posisinya tidak selalu dapat ditentukan hanya dari isi tile. Posisi tersebut divalidasi menggunakan hasil gambar secara keseluruhan.

## Solver

Jalankan:

```bash
python3 solve.py images.zip
```

Solver akan menghasilkan beberapa file:

```text
recovered_pet.png
recovered_pet_4x.png
recovered_pet_flag_area_4x.png
```

`recovered_pet.png` merupakan hasil rekonstruksi utama, sedangkan versi `4x` digunakan untuk mempermudah inspeksi visual, khususnya area flag.

## Hasil

Setelah seluruh tile didekripsi dan disusun kembali, flag yang diperoleh adalah:

```text
scriptCTF{w@t_4_cu71e_p@too1$}
```
