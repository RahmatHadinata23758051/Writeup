# oneline6cry7o

## Challenge

```python
assert __import__('re').match('SEKAI{[67]{67}}$', flag := input()) \
    and not int.from_bytes(flag.encode()) % ~(6 + ~7) ** 67
```

Deskripsi:

```text
how hard can six seven be
```

## Analisis

Regex pertama memaksa format flag menjadi:

```text
SEKAI{<67 karakter yang hanya berisi 6 atau 7>}
```

Bagian penting ada pada modulus berikut:

```python
~(6 + ~7) ** 67
```

Kita sederhanakan operator bitwise complement:

```python
~7 == -8
6 + ~7 == -2
(-2) ** 67 == -(2 ** 67)
~(-(2 ** 67)) == 2 ** 67 - 1
```

Jadi pengecekan kedua sebenarnya setara dengan:

```python
int.from_bytes(flag.encode()) % (2**67 - 1) == 0
```

Artinya seluruh byte flag, jika dianggap sebagai sebuah integer besar, harus habis dibagi:

```text
2^67 - 1
```

## Mengubah Masalah Menjadi Pemilihan Bit

Byte ASCII untuk dua karakter yang diperbolehkan adalah:

```text
'6' = 0x36
'7' = 0x37
```

Perbedaannya hanya satu:

```text
0x37 - 0x36 = 1
```

Karena itu, kita dapat memulai dari template yang seluruh isinya adalah `6`:

```python
base_flag = "SEKAI{" + "6" * 67 + "}"
```

Setiap kali satu karakter diganti dari `6` menjadi `7`, nilai integer flag bertambah sebesar pangkat `256` sesuai posisi byte tersebut.

Untuk body sepanjang 67 karakter, kontribusi karakter pada indeks `i` adalah:

```text
256^(67 - i) mod (2^67 - 1)
```

Karena:

```text
256 = 2^8
```

maka kontribusinya menjadi:

```text
2^(8 * (67 - i)) mod (2^67 - 1)
```

Selain itu:

```text
2^67 == 1 mod (2^67 - 1)
```

sehingga eksponen dapat direduksi modulo 67:

```text
2^((8 * (67 - i)) mod 67)
```

Karena `gcd(8, 67) = 1`, pemetaan indeks tersebut merupakan permutasi dari semua posisi bit:

```text
0, 1, 2, ..., 66
```

Ini berarti masing-masing dari 67 karakter body mengontrol tepat satu bit unik pada bilangan modulo `2^67 - 1`.

Target tambahan yang dibutuhkan adalah:

```python
target = (-int.from_bytes(base_flag.encode(), "big")) % (2**67 - 1)
```

Untuk setiap posisi karakter:

- gunakan `7` jika bit target yang bersesuaian bernilai `1`;
- gunakan `6` jika bit tersebut bernilai `0`.

## Solver

```python
#!/usr/bin/env python3

import re


def main() -> None:
    modulus = 2**67 - 1

    base_flag = "SEKAI{" + "6" * 67 + "}"
    base_value = int.from_bytes(base_flag.encode(), "big")

    target = (-base_value) % modulus

    body = []

    for index in range(67):
        bit_position = (8 * (67 - index)) % 67
        bit = (target >> bit_position) & 1
        body.append("7" if bit else "6")

    flag = "SEKAI{" + "".join(body) + "}"

    assert re.match(r"SEKAI{[67]{67}}$", flag)
    assert not int.from_bytes(flag.encode()) % ~(6 + ~7) ** 67

    print(flag)


if __name__ == "__main__":
    main()
```

Jalankan dengan:

```bash
python3 solve.py
```

Output:

```text
SEKAI{6777676667666666677676776776777766777777777776777767777776677666666}
```

## Flag

```text
SEKAI{6777676667666666677676776776777766777777777776777767777776677666666}
```
