# Grandma's Secret

## Informasi Challenge

- **Kategori:** Crypto
- **Cipher:** ADFGVX + columnar transposition
- **Keyword:** `SUGAR`
- **Ciphertext:** `GVXX FVXV AFXF XVGA DAFF`

Bagian yang gampang salah dibaca ada di grup kedua. Tulisannya adalah `FVXV`, bukan `FVVV`. Kalau dibaca `FVVV`, hasil dekripsi menjadi `JELLYDPNUT` dan jelas ada satu karakter yang salah.

## Analisis

Surat menyebut dua petunjuk secara langsung:

1. `ADFGVX cipher` menunjukkan penggunaan Polybius square 6×6.
2. `alphabetically sorted SUGAR` menunjukkan keyword transposisi kolom adalah `SUGAR`, lalu kolom dibaca berdasarkan urutan alfabet keyword.

Square dari gambar:

```text
      A D F G V X
    +------------
A   | B 3 M R L I
D   | A 6 F 0 8 2
F   | C 7 S E U H
G   | Z 9 D X K V
V   | 1 Q Y W 5 P
X   | N J T 4 G O
```

Urutan alfabet keyword `SUGAR` adalah:

```text
A G R S U
```

Posisi kolom aslinya:

```text
S U G A R
3 4 2 0 1   # indeks jika dihitung dari nol setelah sorting
```

Ciphertext memiliki 20 karakter dan keyword panjangnya 5, jadi setiap kolom berisi 4 karakter. Ciphertext dipecah sesuai urutan alfabet keyword:

```text
A -> GVXX
G -> FVXV
R -> AFXF
S -> XVGA
U -> DAFF
```

Dikembalikan ke posisi kolom asli `S U G A R`:

```text
S -> XVGA
U -> DAFF
G -> FVXV
A -> GVXX
R -> AFXF
```

Membaca tabel per baris menghasilkan stream koordinat ADFGVX:

```text
XDFGAVAVVFGFXXXAFVXF
```

Stream tersebut dipisahkan menjadi pasangan:

```text
XD FG AV AV VF GF XX XA FV XF
```

Lookup ke square menghasilkan:

```text
J  E  L  L  Y  D  O  N  U  T
```

Password WiFi-nya adalah:

```text
JELLYDONUT
```

## Solver

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
key               : SUGAR
ciphertext        : GVXXFVXVAFXFXVGADAFF
coordinate stream : XDFGAVAVVFGFXXXAFVXF
plaintext         : JELLYDONUT
flag              : bronco{jellydonut}
```

## Flag

```text
bronco{jellydonut}
```
