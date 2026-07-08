# Elliptic Curve Cryptography

## Challenge

Diberikan sebuah parameter elliptic curve berukuran sekitar 100-bit:

```json
[
  {
    "field": {
      "p": "0x0fffffffffffffffffffffff67"
    },
    "a": "0x0fffffffffffffffffffffff64",
    "b": "0x00000000000000000000000abb",
    "order": "0x0ffffffffffff918654d8534a1",
    "subgroups": [
      {
        "x": "0x00000000000000000000000001",
        "y": "0x05a0248e58b8beaa670036b766",
        "order": "0xffffffffffff918654d8534a1",
        "cofactor": "0x1"
      }
    ]
  }
]
```

Deskripsinya hanya mengatakan:

> the flag is hidden some where in this curve (100-bit?) look at the p,a and x params

Hint dari panitia:

1. What’s the name of the paper include algorithm that generate that curve?
2. マイクロソフト
3. Parameter sebuah kurva berukuran 512-bit yang berisi `p`, `a`, `d`, `r`, `X(P)`, `Y(P)`, dan `h`.

Flag format:

```text
LYKNCTF{...}
```

---

## Analisis Parameter

Petunjuk utama ada pada nilai `p`, `a`, dan koordinat `x` generator.

Pertama, ubah parameter menjadi integer dan periksa relasinya:

```python
p = int("0fffffffffffffffffffffff67", 16)
a = int("0fffffffffffffffffffffff64", 16)
x = int("00000000000000000000000001", 16)

print("bit length:", p.bit_length())
print("2^100 - p:", (1 << 100) - p)
print("p - a:", p - a)
print("x:", x)
```

Hasilnya:

```text
bit length: 100
2^100 - p: 153
p - a: 3
x: 1
```

Jadi parameternya dapat ditulis sebagai:

[
p = 2^{100} - 153
]

[
a = p - 3 \equiv -3 \pmod p
]

dan generator menggunakan:

[
x = 1
]

Kombinasi ini terlihat terlalu terstruktur untuk menjadi parameter kurva acak.

Nilai prima dibuat dekat dengan pangkat dua, koefisien `a` menggunakan nilai sederhana `-3`, dan pencarian generator dimulai dari nilai `x` yang sangat kecil.

Artinya, parameter tersebut kemungkinan dibuat menggunakan algoritma deterministik.

---

## Mengikuti Hint Microsoft

Hint kedua adalah:

```text
マイクロソフト
```

Teks tersebut berarti **Microsoft**.

Hint ketiga memberikan parameter kurva yang jauh lebih besar. Setelah mencari bagian unik dari parameter tersebut, terutama nilai:

```text
d = 0x9BAA8
X(P) = 0x20
h = 0x04
```

parameter itu mengarah ke keluarga kurva milik Microsoft yang disebut **NUMS curves**.

NUMS merupakan singkatan dari:

```text
Nothing Up My Sleeve
```

Kurva ini dibuat dengan parameter yang dipilih secara transparan dan deterministik, sehingga tidak menimbulkan kecurigaan adanya konstanta rahasia atau backdoor.

Kurva pada hint ketiga dikenali sebagai salah satu parameter NUMS, yaitu `numsp512t1`.

---

## Rabbit Hole Pertama: Menebak Nama Kurva

Karena challenge menggunakan kurva 100-bit dengan bentuk Weierstrass dan `a = -3`, muncul dugaan bahwa namanya mengikuti pola kurva NUMS lain:

```text
numsp256d1
numsp384d1
numsp512d1
```

Dengan pola tersebut, kurva challenge terlihat seperti versi kecil:

```text
numsp100d1
```

Percobaan flag:

```text
LYKNCTF{numsp100d1}
```

Namun hasilnya salah.

Masalahnya, `numsp100d1` bukan nama resmi kurva yang terdapat di spesifikasi. Itu hanya nama hasil ekstrapolasi dari pola penamaan kurva lain.

Challenge juga tidak bertanya “what is the name of the curve”, tetapi secara spesifik bertanya:

> What’s the name of the paper include algorithm that generate that curve?

Jadi target sebenarnya bukan nama kurva.

---

## Rabbit Hole Kedua: Kepanjangan NUMS

Karena kurva tersebut berasal dari keluarga NUMS, percobaan berikutnya adalah menggunakan kepanjangannya:

```text
LYKNCTF{nothing_up_my_sleeve}
```

Hasilnya juga salah.

Walaupun frasa tersebut menjelaskan filosofi pemilihan parameternya, hint pertama tetap meminta nama paper atau dokumen yang berisi algoritma pembentukan kurva.

Berarti kita harus mencari dokumen spesifik yang mendefinisikan NUMS curves.

---

## Menemukan Dokumen yang Tepat

Parameter pada hint ketiga ditemukan di dokumen Internet-Draft berjudul:

```text
Elliptic Curve Cryptography (ECC) Nothing Up My Sleeve (NUMS) Curves and Curve Generation
```

Identifier dokumennya adalah:

```text
draft-black-numscurves-02
```

Dokumen tersebut menjelaskan proses pembentukan parameter NUMS, termasuk pemilihan:

* prime field berbentuk dekat dengan (2^n),
* koefisien kurva sederhana,
* pencarian parameter dan generator secara deterministik,
* titik generator dengan koordinat `x` kecil yang memenuhi syarat.

Ini cocok dengan parameter challenge:

```text
p = 2^100 - 153
a = p - 3
x = 1
```

Jadi flag tidak disembunyikan melalui operasi kriptografi terhadap titik kurva. Parameter tersebut digunakan sebagai fingerprint untuk mengidentifikasi algoritma dan dokumen yang membentuknya.

---

## Flag

```text
LYKNCTF{draft-black-numscurves-02}
```

##
