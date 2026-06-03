# Writeup - 🧅🧅🧅

## Ringkasan

File yang diberikan cuma berisi deretan emoji. Dari judul dan deskripsi challenge, arahnya cukup jelas: ini bukan stego gambar atau binary, tetapi encoding berlapis seperti bawang.

File dianalisis sebagai teks Unicode. Emoji `🐗` muncul sangat sering dan posisinya konsisten, jadi saya anggap sebagai pemisah. Setelah dipisah, setiap bagian selalu berisi tepat 2 emoji.

## Langkah Penyelesaian

### 1. Pisahkan berdasarkan emoji separator

Isi file dipisah dengan separator:

```text
🐗
```

Hasilnya ada banyak token, dan semua token panjangnya 2 emoji. Ini kuat mengarah ke representasi 1 byte per token, yaitu 2 nibble.

### 2. Mapping emoji ke nibble

Selain separator, ada 16 emoji unik. Karena jumlahnya tepat 16, saya urutkan emoji berdasarkan Unicode codepoint lalu beri nilai `0x0` sampai `0xf`.

Contohnya konsepnya seperti ini:

```python
alphabet = sorted(set("".join(chunks)), key=ord)
value = {ch: i for i, ch in enumerate(alphabet)}
```

Setiap pasangan emoji kemudian digabung menjadi byte:

```python
byte = (value[pair[0]] << 4) | value[pair[1]]
```

Output dari tahap ini menjadi string alfanumerik panjang.

### 3. Decode layer encoding

String hasil mapping ternyata masih berupa encoding berlapis. Urutannya:

1. Base62 decode
2. Base45 decode
3. Base32 decode
4. Base64 decode

Setelah semua layer itu dibuka, hasilnya menjadi string mirip DNA/RNA:

```text
TGGGAAATAAGGGAC GCTCACCAC OAATATAOAAT OGATTTTUTCCTGTGCGACAATTOAAC
```

### 4. Translate DNA/protein

String terakhir berisi kodon DNA, tetapi ada huruf `O` dan `U` yang tidak normal untuk DNA. Di sini trik challenge-nya: `O` dan `U` tidak dibuang, tetapi diperlakukan sebagai huruf literal yang ikut masuk ke pesan.

Kodon normal diterjemahkan memakai tabel codon standar:

```text
TGG -> W
GAA -> E
ATA -> I
AGG -> R
GAC -> D
```

Dengan cara itu pesan akhirnya menjadi:

```text
WEIRD AHH ONION ODFUSCATION
```

Karena flag biasanya lowercase dengan underscore, pesan tersebut diformat menjadi:

```text
THEM{weird_ahh_onion_odfuscation}
```

## Flag

```text
THEM{weird_ahh_onion_odfuscation}
```

## Solver

Solver final ada di `solve.py`. Jalankan dari folder challenge:

```bash
python3 solve.py
```

Output:

```text
THEM{weird_ahh_onion_odfuscation}
```
