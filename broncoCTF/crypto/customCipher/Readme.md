# Custom Cipher

- **CTF:** BroncoCTF
- **Category:** Misc
- **Difficulty:** Easy
- **Flag:** `bronco{f4ct0r1ng_i5_fr3e???}`

## Analisis

Skema memakai polinomial dengan akar bilangan bulat.

Public key dibuat seperti ini:

```python
public = Poly([1])
for root in private:
    public = public * Poly([-root, 1])
```

Secara matematis:

```text
P(x) = ∏(x - rᵢ)
```

Saat mengenkripsi empat karakter, program tidak melakukan operasi modular atau transformasi satu arah. Ia hanya menambahkan empat faktor baru ke public key:

```python
for root in message:
    public = public * Poly([-root, 1])
```

Untuk satu blok plaintext `[m₀, m₁, m₂, m₃]`, ciphertext-nya adalah:

```text
C(x) = P(x) · (x - m₀)(x - m₁)(x - m₂)(x - m₃)
```

Karena `P(x)` dikirim sebagai public key, ciphertext dapat dibagi langsung:

```text
M(x) = C(x) / P(x)
     = (x - m₀)(x - m₁)(x - m₂)(x - m₃)
```

Tidak perlu mengetahui private roots. Quotient selalu polinomial monic derajat empat dengan akar berupa nilai ASCII karakter plaintext.

## Format Koefisien

`Poly` menyimpan koefisien secara ascending:

```text
[c₀, c₁, c₂, ..., cₙ]
```

Tetapi `to_distrib_form()` mencetak:

```python
self.coeff[:-1]
```

Koefisien tertinggi tidak disertakan karena selalu `1`. Saat parsing, solver menambahkannya kembali:

```python
coefficients = parsed_values + [1]
```

Public key mempunyai derajat 64, sedangkan setiap ciphertext mempunyai derajat 68. Pembagian exact menghasilkan lima koefisien untuk polinomial derajat empat.

## Mengembalikan Urutan Karakter

Akar polinomial hanya memberi multiset karakter. Program menyimpan urutan aslinya dalam integer tambahan:

```python
order = sorted(message)

for i, e in enumerate(order):
    ind = message.index(e)
    order[i] = ind
    message[ind] = -1

order = sum([x << (2 * i) for i, x in enumerate(order)])
```

Setiap indeks asli menggunakan dua bit karena satu blok berisi empat karakter.

Decode-nya:

```python
original_index = (encoded_order >> (2 * sorted_index)) & 3
```

Nilai akar yang sudah diurutkan ditempatkan kembali ke `original_index`.

## Contoh Blok Pertama

Pembagian ciphertext pertama dengan public key menghasilkan:

```text
136410120 - 5057532x + 70234x² - 433x³ + x⁴
```

Akarnya:

```text
98, 110, 111, 114
```

Dalam ASCII:

```text
b, n, o, r
```

Nilai order blok pertama adalah `108`:

```text
108 = 0b01101100
```

Field dua bitnya menghasilkan indeks:

```text
[0, 3, 2, 1]
```

Setelah karakter dikembalikan ke indeks asli:

```text
bron
```

## Hasil Seluruh Blok

```text
bron
co{f
4ct0
r1ng
_i5_
fr3e
???}
```

Gabungannya:

```text
bronco{f4ct0r1ng_i5_fr3e???}
```

Tiga tanda tanya adalah karakter literal. Akar blok terakhir memang bernilai `63`, yaitu ASCII `?`.

## Menjalankan Solver

```bash
python3 solve.py enc.txt
```

Output:

```text
bronco{f4ct0r1ng_i5_fr3e???}
```

## Flag

```text
bronco{f4ct0r1ng_i5_fr3e???}
```
