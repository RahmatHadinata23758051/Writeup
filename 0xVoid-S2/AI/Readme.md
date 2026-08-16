# 0xV0ID CTF MISC & AI Challenge Writeup Collection

## 1. Between The Lines

**Category:** MISC - Whitespace Steganography

### Analysis

File `poem.txt` terlihat seperti puisi biasa, tetapi terdapat whitespace tambahan pada akhir setiap baris.

Pengecekan:

```bash
cat -A poem.txt
```

Menunjukkan adanya kombinasi:

- Space
- Tab (`^I`)

Whitespace tersebut digunakan sebagai binary.

### Mapping

```
Space = 0
Tab   = 1
```

### Script Ekstraksi

```python
bits = ""
for line in open("poem.txt", "rb").read().splitlines():
    ws = line[len(line.rstrip(b" \t")):]
    bits += ''.join('1' if c == 9 else '0' for c in ws)
print(bits)
```

Binary kemudian dikonversi ke ASCII.

### Flag

```
0xV0ID{wh1t3sp4c3_h1d3s_4ll_truth}
```

---

## 2. Quiet Note

**Category:** MISC - First Letters / Acrostic

### Analysis

Nama file dan challenge memberikan petunjuk:

```
easy_first_letters
```

Setiap baris dimulai dengan karakter yang membentuk flag.

Command:

```bash
cut -c1 letter.txt
```

Menghasilkan:

```
0xV01D{FIRST_LETTERS_NEVER_LIE}
```

### Flag

```
0xV01D{FIRST_LETTERS_NEVER_LIE}
```

---

## 3. Acrostic

**Category:** MISC - Acrostic

### Analysis

Petunjuk:

```
first letter of each line reveals the secret
```

Mengambil huruf pertama setiap baris:

```
F
I
R
S
T
S
T
E
P
```

Digabung menjadi:

```
FIRSTSTEP
```

### Flag

```
0xV0ID{FIRSTSTEP}
```

---

## 4. Single Byte

**Category:** MISC - Single Byte XOR

### Analysis

File `secret.bin` dienkripsi menggunakan XOR satu byte.

Brute force seluruh 256 kemungkinan key:

```python
for k in range(256):
    out = bytes([b ^ k for b in data])
```

Ditemukan:

```
KEY: 0x42
```

Hasil dekripsi:

```
0xV0ID{x0r_k3y_f0und}
```

### Flag

```
0xV0ID{x0r_k3y_f0und}
```

---

## 5. Time Machine

**Category:** MISC - Docker Forensics

### Analysis

Docker image:

```bash
docker pull jinx69/timemachine:latest
```

Petunjuk:

```
The answers aren't in the present.
```

Artinya flag berada pada layer Docker lama.

Melihat history:

```bash
docker history jinx69/timemachine:latest
```

Ditemukan:

```
COPY ... /opt/flag.sh
```

Export image:

```bash
docker save jinx69/timemachine:latest -o tm.tar
```

Ekstrak seluruh layer dan cari flag:

```bash
find extracted -name "flag.sh"
```

Isi file:

```bash
echo "0xVO1D{h1st0ry_n3v3r_li35}"
```

### Flag

```
0xVO1D{h1st0ry_n3v3r_li35}
```

---

## 6. Safety Bitfield

**Category:** AI - Bitfield Decoding

### Analysis

File berisi keputusan satu bit:

```
token_id
allowed
```

Bit harus disusun sesuai urutan yang benar, lalu dilakukan voting transformasi.

Hasil decoding:

```
0xVoid{bits}
```

### Flag

```
0xV0ID{bits}
```

---

## 7. Refusal With Extra Tokens

**Category:** AI - Zero Width Steganography

### Analysis

Pesan refusal memiliki hidden token setelah teks terakhir.

Karakter tersembunyi:

```
U+200B
U+200C
U+200D
```

Karakter tersebut diekstraksi dan dikonversi menjadi binary.

### Mapping

```
U+200B -> 0
U+200C/U+200D -> 1
```

Hasil:

```
0xVoid{invisible_tokens_visible_win}
```

### Flag

```
0xV0ID{invisible_tokens_visible_win}
```

---

## 8. Temperature Seven

**Category:** AI - XOR Cipher

### Analysis

Challenge menyebut:

```
temperature: 0.7
```

Tetapi temperature bukan cryptographic key.

Petunjuk:

```
I simply believed 0.7 looked like a key.
```

Key yang digunakan:

```
7
```

Dekripsi:

```
plaintext = cipher XOR 7
```

Hasil:

```
0xVoid{temperature_is_not_a_secret}
```

### Flag

```
0xV0ID{temperature_is_not_a_secret}
```

---

## 9. Self Consistency Vote

**Category:** AI - Majority Voting

### Analysis

Terdapat 10 output model yang memiliki error berbeda.

Solusi:

1. Ambil setiap posisi karakter.
2. Pilih karakter yang paling banyak muncul.

Konsep yang digunakan adalah self-consistency decoding.

Hasil:

```
0xVoid{majority_vote_beats_hallucination}
```

### Flag

```
0xV0ID{majority_vote_beats_hallucination}
```

---

## 10. Tokenizer Off By One

**Category:** AI - Tokenizer Reversal

### Analysis

Vocab menggunakan index mulai dari 0:

```
vocab_zero_indexed
```

Tetapi token ID digeser +1.

Solusi:

```
token_id - 1
```

Script:

```python
flag = "".join(vocab[i - 1] for i in ids)
```

Hasil:

```
0xVoid{humans_start_at_one_models_do_not}
```

### Flag

```
0xV0ID{humans_start_at_one_models_do_not}
```

---

## 11. Confidence Cipher

**Category:** AI - XOR Key Stream

### Analysis

Confidence score digunakan sebagai XOR key stream.

Operasi:

```
plaintext = cipher XOR confidence_percent
```

Script:

```python
chr(cipher ^ confidence)
```

Hasil:

```
0xVoid{sampling}
```

### Flag

```
0xV0ID{sampling}
```

---

## 12. Checkpoint Seed

**Category:** AI - PRNG Reproduction

### Analysis

Seed diberikan:

```
8675309
```

Algoritma:

```python
random.Random(seed).randrange(256)
```

Nilai tersebut digunakan sebagai keystream XOR.

Dekripsi dilakukan dengan:

```python
random.Random(seed)
cipher_byte ^ random_byte
```

Flag diperoleh:

```
0xVO1D{...}
```

---

## 13. Embedding Oracle

**Category:** AI - Nearest Neighbor Embedding

### Analysis

Embedding token dan query diberikan.

Setiap query dicari token terdekat menggunakan Euclidean distance.

Rumus:

```
distance = sqrt((x1-x2)^2 + (y1-y2)^2)
```

Query diproses dalam urutan:

```
q00 - q29
```

Hasil:

```
0xVoid{nearest_neighbor_knows}
```

### Flag

```
0xV0ID{nearest_neighbor_knows}
```
