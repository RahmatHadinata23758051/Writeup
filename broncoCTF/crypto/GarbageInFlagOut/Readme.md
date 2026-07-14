# Garbage In, Flag Out

- **CTF:** BroncoCTF
- **Category:** Crypto
- **Difficulty:** Medium
- **Flag:** `bronco{n0t_r4nd0m_3nough}`

## Titik Lemah

Flag dan random garbage memakai key yang sama dalam dua bentuk:

```python
garb = block_encrypt(key, real_garb)

key = scramble(key)
flag = block_encrypt(key, FLAG)
```

`FLAG` mempunyai panjang `N`, sama dengan panjang key. Karena itu enkripsi flag hanya memakai blok key pertama:

```text
flag_cipher[i] = scramble(key[i]) XOR flag[i]
```

Fungsi `scramble()` cuma membalik urutan bit dalam setiap byte. Operasinya reversibel dan tidak menambah keamanan.

Masalah utamanya ada pada random garbage. Plaintext-nya diketahui berasal dari alfabet kecil:

```python
real_garb = "".join(random.choices(string.ascii_lowercase, k=2 * N))
```

Panjangnya `2N`, sehingga ciphertext garbage terbagi menjadi dua bagian:

```text
G0[i] = key[i] XOR lowercase_1[i]
G1[i] = extended_key[i] XOR lowercase_2[i]
```

## Membentuk Kandidat Key

Karakter pada bagian pertama garbage pasti salah satu dari `a` sampai `z`.

Untuk setiap posisi dan setiap kandidat huruf kecil:

```text
key_candidate = G0[i] XOR candidate_lowercase
```

Satu byte garbage hanya memberi beberapa kemungkinan key. Bagian kedua dipakai untuk menyaringnya.

## Kebocoran dari Key Extension

Key extension dibuat dari setiap byte key:

```python
for i in range(4):
    sub = (element >> (2 * i)) & 3
    sub = (sub & 1) ^ (sub >> 1)
    newkey += sub << (7 - i)

newkey += random.getrandbits(4)
```

Empat bit bawah memang random, tetapi empat bit atas sepenuhnya ditentukan oleh key lama.

Untuk pasangan bit:

```text
(b0, b1), (b2, b3), (b4, b5), (b6, b7)
```

program menyimpan XOR tiap pasangan ke bit 7 sampai bit 4:

```text
high_nibble =
    (b0 XOR b1) << 7 |
    (b2 XOR b3) << 6 |
    (b4 XOR b5) << 5 |
    (b6 XOR b7) << 4
```

Karena plaintext bagian kedua juga huruf kecil, kandidat key hanya dipertahankan jika ada huruf `a-z` yang memenuhi:

```text
high_nibble(G1[i] XOR lowercase) == derived_high_nibble(key_candidate)
```

Random nibble tidak perlu ditebak.

## Mendapatkan Kandidat Flag

Setelah kandidat key lolos constraint kedua:

```text
flag_char = flag_cipher[i] XOR reverse_bits(key_candidate)
```

Karakter dibatasi ke alfabet flag:

```text
a-z, 0-9, _, {, }
```

Hasil per posisi hampir seluruhnya tunggal:

```text
b r o n c [o|_] { n 0 t [ _|o ] r 4 n d 0 m _ 3 n [o|_] u g h }
```

Format `bronco{...}` menentukan karakter keenam sebagai `o`.

Kandidat body yang tersisa:

```text
n0t_r4nd0m_3n_ugh
n0t_r4nd0m_3nough
n0tor4nd0m_3n_ugh
n0tor4nd0m_3nough
```

Deskripsi memastikan plaintext adalah English leetspeak. Setelah substitusi:

```text
0 -> o
4 -> a
3 -> e
```

hanya satu kandidat yang membentuk frasa Inggris utuh:

```text
n0t_r4nd0m_3nough
not random enough
```

## Validasi Key

Dengan flag tersebut, key asli dapat dihitung balik:

```text
key[i] = reverse_bits(flag_cipher[i] XOR flag[i])
```

Key yang didapat membuat plaintext bagian pertama garbage menjadi:

```text
dgpnnyfmhzvzygyvzwuaxgtrd
```

Seluruhnya huruf kecil, sesuai generator challenge. Setiap posisi pada bagian kedua juga mempunyai setidaknya satu plaintext `a-z` yang cocok dengan high nibble key extension.

## Menjalankan Solver

```bash
python3 solve.py output.txt
```

Output:

```text
[+] Kandidat setelah constraint:
    bronco{n0t_r4nd0m_3nough}
    bronco{n0t_r4nd0m_3n_ugh}
    bronco{n0tor4nd0m_3nough}
    bronco{n0tor4nd0m_3n_ugh}
[+] Flag: bronco{n0t_r4nd0m_3nough}
```

## Flag

```text
bronco{n0t_r4nd0m_3nough}
```
