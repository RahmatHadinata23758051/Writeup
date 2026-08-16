# Between The Lines — CTF Writeup

## Challenge Information

**Category:** MISC
**Challenge Name:** Between The Lines
**Flag Format:** `0xV0ID{...}`

**Flag:**

```
0xV0ID{wh1t3sp4c3_h1d3s_4ll_truth}
```

---

## Challenge Description

Diberikan sebuah file bernama `poem.txt` yang terlihat seperti puisi biasa. Namun deskripsi memberikan petunjuk bahwa informasi tersembunyi bukan berada pada isi teks, melainkan pada **jarak antar karakter (whitespace)**.

Petunjuk utama:

> "not the words, but the gaps between them"

Artinya data tersembunyi berada pada karakter whitespace seperti:

* Space
* Tab

---

## Analisis File

Pertama dilakukan pengecekan karakter tersembunyi menggunakan:

```bash
cat -A poem.txt
```

Hasil menunjukkan adanya karakter:

```
^I
```

yang merupakan representasi dari **tab**.

Contoh:

```
In the silence of the void, a signal waits to speak,  ^I^I     ^I$
```

Terlihat setiap akhir baris memiliki kombinasi:

* Space
* Tab

Kombinasi tersebut kemungkinan merupakan representasi binary.

---

## Ekstraksi Whitespace

Dibuat script Python untuk mengambil whitespace pada akhir setiap baris.

Aturan encoding:

```
Space = 0
Tab   = 1
```

Script:

```python
bits = ""

for line in open("poem.txt", "rb").read().splitlines():
    ws = line[len(line.rstrip(b" \t")):]

    bits += ''.join(
        '1' if c == 9 else '0'
        for c in ws
    )

print(bits)
```

Script tersebut mengambil karakter setelah karakter terakhir yang bukan whitespace.

---

## Konversi Binary ke ASCII

Binary yang berhasil diperoleh kemudian dipisahkan setiap 8 bit:

Contoh:

```
00110000
01111000
01010110
00110000
```

Kemudian dikonversi menggunakan ASCII:

```
00110000 -> 0
01111000 -> x
01010110 -> V
00110000 -> 0
```

Script lengkap:

```python
bits = ""

for line in open("poem.txt", "rb").read().splitlines():
    ws = line[len(line.rstrip(b" \t")):]

    for c in ws:
        bits += '1' if c == 9 else '0'


plaintext = ""

for i in range(0, len(bits), 8):
    byte = bits[i:i+8]

    if len(byte) == 8:
        plaintext += chr(int(byte, 2))


print(plaintext)
```

---

## Hasil Dekripsi

Output:

```
0xV0ID{wh1t3sp4c3_h1d3s_4ll_truth}
```

