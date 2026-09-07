# Writeup CTF: Chiral

- **Kategori:** Misc / Reverse Engineering / Molecular Data
- **Tingkat Kesulitan:** Medium
- **Artefak:** `chiral.mol`
- **Flag:** `NNS{ch1r4l1ty_fl1ps_th3_b1ts}`

---

# 1. Deskripsi Tantangan

Challenge hanya memberikan satu file struktur molekul dalam format:

```
MOL
```

File tersebut tidak berisi teks flag secara langsung.

Informasi flag disimpan pada struktur kimia molekul melalui:

- backbone molekul;
- pusat kiral karbon;
- panjang side-chain.

Setiap carbon chiral center menyimpan:

```
1 nibble
```

Dua nibble kemudian digabung menjadi:

```
1 byte ASCII
```

Tujuan challenge adalah mengekstrak informasi stereokimia dari molekul dan mengubahnya kembali menjadi flag.

---

# 2. File Challenge

Struktur file:

```
misc_chiral.tar.gz

└── misc_chiral/
    └── chiral.mol
```

File:

```
chiral.mol
```

merupakan:

```
MOL V2000
```

yang dibuat menggunakan RDKit.

---

# 3. Analisis Awal

Parsing awal menunjukkan:

```
Atoms : 371
Bonds : 370
```

Jumlah bond:

```
atoms - 1
```

berarti graph molekul merupakan:

```
tree
```

Karena berbentuk tree:

- tidak ada cycle;
- path antar atom bersifat unik.

---

Terminal atom:

```
F
```

dan:

```
Br
```

menjadi titik awal dan akhir backbone.

---

# 4. Ekstraksi Backbone

Karena graph berupa tree, shortest path:

```
F -> Br
```

adalah backbone utama molekul.

Path tersebut memiliki:

```
60 atom
```

dengan struktur:

```
F

+

58 carbon chiral center

+

Br
```

---

Jumlah center:

```
58
```

Setiap center menghasilkan:

```
1 nibble
```

Maka total data:

```
58 nibble

=

29 byte
```

Ukuran tersebut sesuai dengan panjang flag:

```
NNS{ch1r4l1ty_fl1ps_th3_b1ts}
```

---

# 5. Encoding Data

Setiap carbon pada backbone menyimpan:

```
1 nibble
```

Format:

```
bit 3        bit 2 bit 1 bit 0

R/S bit      side-chain length
```

---

## Bit Chirality

Mapping:

```
R = 0

S = 1
```

Nilai berada pada:

```
bit tertinggi nibble
```

---

## Side Chain Length

Panjang side-chain:

```
1 - 8
```

disimpan sebagai:

```
length - 1
```

sehingga:

| Panjang | Nilai |
|-|-|
| 1 | 000 |
| 2 | 001 |
| 3 | 010 |
| 4 | 011 |
| 5 | 100 |
| 6 | 101 |
| 7 | 110 |
| 8 | 111 |

---

# 6. Contoh Dekode

Misalnya dua carbon pertama:

Center pertama:

```
R
length = 5
```

Maka:

```
R = 0

length-1 = 4
```

Nibble:

```
0100
```

atau:

```
0x4
```

---

Center kedua:

```
S
length = 7
```

Maka:

```
S = 1

length-1 = 6
```

Nibble:

```
1110
```

atau:

```
0xe
```

---

Gabungan:

```
0x4e
```

ASCII:

```
N
```

---

# 7. Algoritma Ekstraksi

Langkah lengkap:

## 1. Load Molecule

Menggunakan:

```
RDKit
```

untuk membaca:

```
chiral.mol
```

---

## 2. Cari Atom Terminal

Cari:

```
Fluorine (F)
```

dan:

```
Bromine (Br)
```

---

## 3. Cari Backbone

Ambil shortest path:

```
F -> Br
```

---

## 4. Proses Carbon Tengah

Untuk setiap carbon:

Ambil:

- descriptor chirality;
- jumlah side-chain yang keluar dari backbone.

---

## 5. Bentuk Nibble

Formula:

\[
nibble =
(chirality\_bit << 3)
|
(length-1)
\]

---

## 6. Gabungkan Nibble

Setiap dua nibble:

```
high nibble
+
low nibble
```

menjadi:

```
byte ASCII
```

---

# 8. Solve Script

File:

```
solve.py
```

melakukan seluruh proses:

```python
1. Read MOL file

2. Build molecular graph

3. Find F-Br backbone

4. Extract chiral centers

5. Convert R/S + side-chain

6. Combine nibbles

7. Decode ASCII flag
```

---

# 9. Validasi

Solver melakukan pengecekan:

- backbone harus berakhir pada Br;
- jumlah carbon sesuai;
- hasil decode harus berupa printable ASCII.

Hal ini mencegah decode salah jika struktur molekul berubah.

---

# 10. Cara Menjalankan

Install dependency:

```bash
pip install rdkit
```

Jalankan:

```bash
python3 solve.py
```

Output:

```text
<FLAG>NNS{ch1r4l1ty_fl1ps_th3_b1ts}</FLAG>
```

---

# 11. Kesimpulan

Challenge ini menggunakan struktur kimia sebagai media penyimpanan data.

Flag tidak disimpan sebagai:

- string;
- angka;
- ciphertext.

Melainkan melalui:

```
Stereochemistry
        |
        v
Chiral Center
        |
        v
Nibble Encoding
        |
        v
ASCII Flag
```

Informasi yang digunakan:

```
R/S configuration
```

dan:

```
side-chain length
```

berhasil direkonstruksi menjadi:

```
NNS{ch1r4l1ty_fl1ps_th3_b1ts}
```

---

# Flag

```
NNS{ch1r4l1ty_fl1ps_th3_b1ts}
```
