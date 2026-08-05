# Writeup CTF - Merkle's Trapdoor

## Informasi Challenge

- **Judul:** Merkle's Trapdoor
- **Kategori:** Crypto
- **Deskripsi:**

> Behind every great knapsack lies a hidden trapdoor. Can you find your way through the super-increasing shadows?

### Diberikan

**Ciphertext**

```text
1b99090e0a6109e30414099a090e0a6f211704f4060a20341b99058c060a1c2809d51cbd0a6104e60a6f1cbd21921c281b9921921cbd090320421cbd203f1b990a72
```

**Public Key**

```text
{14, 5937, 140, 213, 3, 1403, 901, 2009}
```

---

# Analisis

Challenge ini menggunakan skema kriptografi **Merkle-Hellman Knapsack Cryptosystem**. Biasanya, untuk mendekripsi pesan diperlukan *private key* berupa deret **super-increasing**, beserta nilai modulus dan multiplier sebagai trapdoor.

Namun, pada challenge ini hanya diberikan **8 buah public key**:

```text
{14, 5937, 140, 213, 3, 1403, 901, 2009}
```

Jumlah elemen public key yang hanya **8 buah** menunjukkan bahwa setiap karakter plaintext direpresentasikan sebagai **1 byte (8 bit)**.

Pada Merkle-Hellman, setiap blok ciphertext merupakan hasil penjumlahan elemen public key berdasarkan bit plaintext:

```text
c = b0*k0 + b1*k1 + ... + b7*k7
```

dengan:

- `bi ∈ {0,1}`
- `ki` adalah elemen public key.

Karena hanya terdapat **8 bit**, maka seluruh kemungkinan plaintext hanya berjumlah:

```text
2^8 = 256 kemungkinan
```

Jumlah ini sangat kecil sehingga jauh lebih mudah melakukan **brute force seluruh kombinasi bit** dibanding mencoba merekonstruksi trapdoor atau private key.

---

# Ide Penyelesaian

Strateginya adalah:

1. Pisahkan ciphertext menjadi blok 16-bit (4 digit heksadesimal).
2. Bangkitkan seluruh kemungkinan byte (`0-255`).
3. Untuk setiap byte:
   - Ambil representasi bitnya.
   - Hitung jumlah knapsack menggunakan public key.
4. Simpan hasilnya dalam tabel lookup:

```text
knapsack_sum -> karakter
```

5. Untuk setiap blok ciphertext:
   - Cari nilainya pada lookup table.
   - Konversi kembali menjadi karakter ASCII.

Karena hanya terdapat 256 kemungkinan, seluruh proses berlangsung sangat cepat.

---

# Solver

```python
#!/usr/bin/env python3

ct = "1b99090e0a6109e30414099a090e0a6f211704f4060a20341b99058c060a1c2809d51cbd0a6104e60a6f1cbd21921c281b9921921cbd090320421cbd203f1b990a72"

pub = [14, 5937, 140, 213, 3, 1403, 901, 2009]

# Pisahkan ciphertext menjadi blok 16-bit.
blocks = [
    int(ct[i:i+4], 16)
    for i in range(0, len(ct), 4)
]

lookup = {}

# Brute force seluruh kemungkinan byte.
for b in range(256):
    bits = [(b >> i) & 1 for i in range(8)]  # LSB-first
    s = sum(bit * key for bit, key in zip(bits, pub))
    lookup[s] = b

flag = ""

for c in blocks:
    flag += chr(lookup[c])

print(flag)
```

---

# Output

Menjalankan solver menghasilkan:

```text
KaliTeam{M4rK14_h3lLm3n_Kn3ps3cK}
```

---

# Flag

```text
KaliTeam{M4rK14_h3lLm3n_Kn3ps3cK}
```

---

