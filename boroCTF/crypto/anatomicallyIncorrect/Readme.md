# Anatomically Incorrect

**CTF:** boroCTF  
**Category:** Misc  
**Author:** Franklin  
**Challenge:** Anatomically Incorrect  
**Flag:** `boroCTF{IFOoNEdHtEFlAgS}`

## Deskripsi

```txt
Hey, I found this random assortment of characters on the ground in class. What does it mean?

1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p4 ...
```

Diberikan deretan konfigurasi elektron dan sebuah tabel periodik palsu berbentuk spiral. Catatan challenge menyebutkan hasil solution tidak mengandung `boroCTF`, jadi hasil decode perlu dibungkus manual ke format flag.

## Ide

String seperti `1s2 2s2 2p6 ...` adalah konfigurasi elektron. Jumlah superscript/angka terakhir pada tiap orbital sama dengan jumlah elektron, alias nomor atom unsur tersebut.

Contoh:

```txt
1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p4
= 2 + 2 + 6 + 2 + 6 + 2 + 10 + 4
= 34
```

Nomor atom 34 adalah Selenium (`Se`) pada tabel periodik normal. Namun gambar challenge bukan tabel periodik normal. Posisi unsur nomor 34 pada gambar berisi simbol palsu `I`.

Jadi alurnya:

```txt
konfigurasi elektron -> nomor atom -> posisi di tabel palsu -> simbol palsu -> pesan
```

## Ekstraksi Nomor Atom

Konfigurasi dipisah setiap kali ketemu `1s2` baru. Setelah itu, semua angka elektron di tiap konfigurasi dijumlahkan.

```python
import re

data = """1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p4 1s2 2s2 2p6 3s2 3p6 1s2 2s2 2p6 3s2 3p6 4s2 3d3 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d2 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f13 1s2 2s2 2p6 3s2 3p4 1s2 2s2 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f14 6d9 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f14 6d10 7p3 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6"""

tokens = data.split()
configs = []
cur = []

for tok in tokens:
    if tok == "1s2" and cur:
        configs.append(cur)
        cur = [tok]
    else:
        cur.append(tok)

configs.append(cur)

atomic_numbers = []
for cfg in configs:
    total = sum(int(re.search(r"\d+$", x).group()) for x in cfg)
    atomic_numbers.append(total)

print(atomic_numbers)
```

Output:

```txt
[34, 18, 23, 40, 101, 16, 4, 111, 115, 54]
```

## Mapping ke Tabel Palsu

Nomor atom tersebut mengarah ke unsur asli berikut:

| Nomor atom | Unsur asli | Simbol palsu di gambar |
|---:|---|---|
| 34 | Se | I |
| 18 | Ar | F |
| 23 | V | Oo |
| 40 | Zr | N |
| 101 | Md | Ed |
| 16 | S | Ht |
| 4 | Be | E |
| 111 | Rg | Fl |
| 115 | Mc | Ag |
| 54 | Xe | S |

Jika simbol palsunya digabung:

```txt
I F Oo N Ed Ht E Fl Ag S
```

Tanpa spasi:

```txt
IFOoNEdHtEFlAgS
```

Kalimatnya memang sengaja terlihat rusak karena simbol palsu pada tabel juga rusak. Bila dibaca sebagai potongan kata, pesannya menjadi:

```txt
I found the flags
```

## Solver

```python
#!/usr/bin/env python3
import re

data = """1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p4 1s2 2s2 2p6 3s2 3p6 1s2 2s2 2p6 3s2 3p6 4s2 3d3 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d2 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f13 1s2 2s2 2p6 3s2 3p4 1s2 2s2 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f14 6d9 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f14 6d10 7p3 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6"""

fake_table = {
    34: "I",
    18: "F",
    23: "Oo",
    40: "N",
    101: "Ed",
    16: "Ht",
    4: "E",
    111: "Fl",
    115: "Ag",
    54: "S",
}

tokens = data.split()
configs = []
cur = []

for tok in tokens:
    if tok == "1s2" and cur:
        configs.append(cur)
        cur = [tok]
    else:
        cur.append(tok)

configs.append(cur)

atomic_numbers = []
for cfg in configs:
    atomic_numbers.append(sum(int(re.search(r"\d+$", x).group()) for x in cfg))

decoded = "".join(fake_table[n] for n in atomic_numbers)

print("[atomic numbers]", atomic_numbers)
print("[decoded]", decoded)
print("[flag]", f"boroCTF{{{decoded}}}")
```

Output:

```txt
[atomic numbers] [34, 18, 23, 40, 101, 16, 4, 111, 115, 54]
[decoded] IFOoNEdHtEFlAgS
[flag] boroCTF{IFOoNEdHtEFlAgS}
```

## Flag

```txt
boroCTF{IFOoNEdHtEFlAgS}
```
