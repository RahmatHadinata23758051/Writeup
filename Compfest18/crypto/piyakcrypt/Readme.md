# Writeup — piyakcrypt

**Kategori:** Crypto
**Challenge:** piyakcrypt
**Flag:** `COMPFEST18{b1as3d_n0nc3_mt_r3c0v3ry_lll_hnp_go_brr_727e3a9724b244c1}`

## Ringkasan

Challenge ini memakai ECDSA di curve secp256k1. Private key tiap unit dibuat dengan pola:

```python
secret = tag_high || random_piece || tag_low
```

Bagian `tag_high` dan `tag_low` bisa dilihat dari menu damaged record, tapi bagian tengah tetap besar, jadi brute force private key tidak masuk akal.

Vulnerability utamanya ada di nonce ECDSA `k`. Nonce dibuat dari dua bagian:

```python
chunk_a = make_piece(random.getrandbits(64), random.getrandbits(64), total_signatures)
chunk_b = os.urandom(16)

k = chunk_a || chunk_b
```

Masalahnya, `chunk_a` berasal dari Python `random`, yaitu Mersenne Twister. State MT bisa direcover dari output `random.getrandbits(32)` yang bocor lewat menu data panel.

Setelah state MT didapat, kita bisa memprediksi 128 bit atas nonce ECDSA. Sisa 128 bit bawah nonce tetap unknown, tapi ini cukup untuk menyerang ECDSA dengan Hidden Number Problem menggunakan LLL.

---

## Analisis Source

Menu penting:

```text
[1] Show public records
[2] Show damaged record
[3] Request a signature
[5] Open data panel
[6] Submit code
```

Program membuat 5 unit. Tiap unit punya private key dan public key:

```python
for _ in range(UNIT_COUNT):
    piece = int.from_bytes(os.urandom(D_BYTES), "big")
    secret = ((tag_high << (D_SIZE + A_LOW_SIZE)) | (piece << A_LOW_SIZE) | tag_low) % N
    pub = ec_mul(secret, (Gx, Gy))
```

ECDSA signature dibuat seperti biasa:

```python
s = (inv_mod(k, N) * (z + r * secret)) % N
```

Kalau kita tahu nonce `k`, private key bisa langsung dihitung:

```python
d = (s*k - z) * inverse(r, N) mod N
```

Tapi di sini kita hanya tahu bagian atas nonce, bukan seluruh nonce.

---

## Leak Mersenne Twister

Menu `Open data panel` mencetak 78 entry setiap kali dibuka:

```python
for i in range(TABLE_SIZE):
    pos = table_reads * TABLE_SIZE + i
    v = random.getrandbits(32)
    print(f"entry_{pos:03d} = 0x{panel_value(v, pos):08x}")
```

Nilai `v` tidak ditampilkan langsung, tetapi diacak dulu oleh fungsi `panel_value`.

```python
def panel_value(x, pos):
    salt = (0xA5A5A5A5 + pos * 0x6D2B79F5) & MASK32
    bump = (0x9E3779B9 ^ (pos * 0x85EBCA6B)) & MASK32
    y = rol32(x ^ salt, pos * 7 + 3)
    return (y + bump) & MASK32
```

Fungsi ini reversible karena hanya memakai XOR, rotate, dan addition modulo 32-bit.

Inverse-nya:

```python
def panel_inv(out, pos):
    salt = (0xA5A5A5A5 + pos * 0x6D2B79F5) & MASK32
    bump = (0x9E3779B9 ^ (pos * 0x85EBCA6B)) & MASK32
    y = (out - bump) & MASK32
    return ror32(y, pos * 7 + 3) ^ salt
```

Untuk recover state Mersenne Twister, kita butuh 624 output 32-bit. Karena satu panel memberi 78 output:

```text
624 / 78 = 8
```

Jadi cukup buka data panel 8 kali.

Setelah mendapatkan 624 output, setiap output perlu di-`untemper` untuk mendapatkan internal state MT.

---

## Predict Nonce High Bits

Sebelum unit dibuat, program melakukan skip:

```python
_ = [random.getrandbits(32) for _ in range(SKIP_COUNT)]
```

Setelah itu, data panel menggunakan `random.getrandbits(32)` juga. Karena kita mendapatkan 624 output berturut-turut dari panel, kita bisa reconstruct state MT pada posisi setelah panel read.

Setelah state MT dikloning, request signature berikutnya akan memakai output MT yang bisa kita prediksi:

```python
chunk_a = make_piece(
    random.getrandbits(64),
    random.getrandbits(64),
    total_signatures,
)
```

Karena `chunk_a` adalah 128 bit atas nonce, nonce bisa ditulis:

```text
k = K_known + e
```

dengan:

```text
K_known = chunk_a << 128
0 <= e < 2^128
```

Sisa `e` berasal dari `os.urandom(16)`, jadi tidak bisa diprediksi, tapi ukurannya hanya 128 bit.

---

## Serangan HNP dengan LLL

ECDSA punya persamaan:

```text
s*k = z + r*d mod n
```

Substitusi:

```text
k = K + e
```

maka:

```text
s*(K + e) = z + r*d mod n
```

Susun ulang:

```text
d = (s*K - z)*r^-1 + s*r^-1*e mod n
```

Misal:

```text
a_i = (s_i*K_i - z_i)*r_i^-1 mod n
b_i = s_i*r_i^-1 mod n
```

Maka:

```text
d = a_i + b_i*e_i mod n
```

Karena `e_i < 2^128`, ini menjadi Hidden Number Problem. Dengan beberapa signature dari unit yang sama, kita bisa membuat lattice dan menjalankan LLL untuk menemukan error kecil `e_i`.

Challenge membatasi 4 signature per unit, tapi 4 signature sudah cukup karena unknown tiap nonce hanya 128 bit.

---

## Eksploitasi

Alur exploit:

1. Ambil public key unit 0 dari menu `Show public records`.
2. Buka menu `Open data panel` sebanyak 8 kali.
3. Reverse `panel_value` untuk mendapatkan 624 output MT.
4. Untemper semua output dan clone state Python `random`.
5. Request 4 signature dari unit 0.
6. Prediksi `chunk_a` untuk masing-masing signature.
7. Jalankan LLL untuk recover private key unit 0.
8. Submit private key ke menu `Submit code`.

---

## Solver

Solver dijalankan dengan:

```bash
sage -python solve.py 34.2.147.230 3002
```

Bagian penting solver:

```python
state = [untemper(x) for x in outs]
rng = random.Random()
rng.setstate((3, tuple(state + [624]), None))
```

Ini digunakan untuk clone MT.

Lalu prediksi nonce high:

```python
a = rng.getrandbits(64)
b = rng.getrandbits(64)
chunk_a = make_piece(a, b, t)
K = (chunk_a << 128) % N
```

Kemudian private key didapat dari hasil LLL dan diverifikasi dengan public key:

```python
if ec_mul(d, (Gx, Gy)) == pub:
    return d
```

Setelah secret valid ditemukan, kirim ke menu 6:

```python
io.sendline("6")
io.sendline(str(d))
```

Server mengembalikan flag:

```text
COMPFEST18{b1as3d_n0nc3_mt_r3c0v3ry_lll_hnp_go_brr_727e3a9724b244c1}
```

---
